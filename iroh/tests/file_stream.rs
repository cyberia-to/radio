use radio::{
    Endpoint, RelayMode, SecretKey,
    endpoint::Connection,
    files::{ALPN, Client, Descriptor, FileId, FileProtocol, MAX_RANGE_BYTES, Sink, Source},
    protocol::{AcceptError, ProtocolHandler, Router},
};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

const DEADLINE: Duration = Duration::from_secs(5);
fn descriptor() -> Descriptor {
    Descriptor {
        file: FileId {
            particle: [1; 32],
            profile: [2; 32],
        },
        length: 4,
    }
}
async fn endpoint(n: u8) -> Endpoint {
    Endpoint::empty_builder(RelayMode::Disabled)
        .secret_key(SecretKey::from_bytes(&[n; 32]))
        .bind()
        .await
        .unwrap()
}
fn request(offset: u64, length: u32) -> Vec<u8> {
    [
        descriptor().file.particle.as_slice(),
        descriptor().file.profile.as_slice(),
        &descriptor().length.to_be_bytes(),
        &offset.to_be_bytes(),
        &length.to_be_bytes(),
    ]
    .concat()
}
struct Memory;
impl Source for Memory {
    fn descriptor(&self) -> Descriptor {
        descriptor()
    }
    async fn read(&self, _offset: u64, length: usize) -> io::Result<Vec<u8>> {
        Ok(vec![7; length])
    }
}
struct CountSink(AtomicUsize);
impl Sink for CountSink {
    fn descriptor(&self) -> Descriptor {
        descriptor()
    }
    async fn write(&self, _offset: u64, bytes: Vec<u8>) -> io::Result<()> {
        self.0.fetch_add(bytes.len(), Ordering::SeqCst);
        Ok(())
    }
}

#[tokio::test]
async fn malformed_requests_are_rejected_before_provider_access() {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let provider = move |_peer, _file| {
        observed.fetch_add(1, Ordering::SeqCst);
        async { Ok(Memory) }
    };
    let router = Router::builder(endpoint(21).await)
        .accept(ALPN, FileProtocol::new(provider, 2, DEADLINE).unwrap())
        .spawn();
    let client = endpoint(22).await;
    let mut trailing = request(0, 4);
    trailing.push(0);
    let truncated = request(0, 4)[..83].to_vec();
    for bytes in [
        request(0, 0),
        request(0, MAX_RANGE_BYTES as u32 + 1),
        request(1, 4),
        request(u64::MAX, 1),
        trailing,
        truncated,
    ] {
        let connection = client
            .connect(router.endpoint().addr(), ALPN)
            .await
            .unwrap();
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        send.write_all(&bytes).await.unwrap();
        send.finish().unwrap();
        assert!(
            tokio::time::timeout(DEADLINE, recv.read_to_end(16))
                .await
                .unwrap()
                .is_err()
        );
        connection.close(0u32.into(), b"done");
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    router.shutdown().await.unwrap();
    client.close().await;
}

#[derive(Debug)]
struct Reply(Vec<u8>);
impl ProtocolHandler for Reply {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let (mut send, mut recv) = connection.accept_bi().await?;
        recv.read_to_end(84).await.map_err(AcceptError::from_err)?;
        send.write_all(&self.0)
            .await
            .map_err(AcceptError::from_err)?;
        send.finish()?;
        connection.closed().await;
        Ok(())
    }
}

#[tokio::test]
async fn truncated_trailing_and_invalid_responses_never_reach_the_sink() {
    let client_endpoint = endpoint(23).await;
    for reply in [vec![0, 7, 7, 7], vec![0, 7, 7, 7, 7, 7], vec![2], vec![1]] {
        let router = Router::builder(endpoint(24).await)
            .accept(ALPN, Reply(reply))
            .spawn();
        let mut client = Client::connect(&client_endpoint, router.endpoint().addr(), DEADLINE)
            .await
            .unwrap();
        let sink = CountSink(AtomicUsize::new(0));
        assert!(client.deliver(&sink, 0, 4).await.is_err());
        assert_eq!(sink.0.load(Ordering::SeqCst), 0);
        drop(client);
        router.shutdown().await.unwrap();
    }
    client_endpoint.close().await;
}

#[derive(Debug)]
struct Partial(Arc<tokio::sync::Notify>);
impl ProtocolHandler for Partial {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let (mut send, mut recv) = connection.accept_bi().await?;
        recv.read_to_end(84).await.map_err(AcceptError::from_err)?;
        send.write_all(&[0, 7, 7])
            .await
            .map_err(AcceptError::from_err)?;
        self.0.notify_one();
        connection.closed().await;
        Ok(())
    }
}

#[tokio::test]
async fn interrupted_frames_and_expired_deadlines_do_not_acknowledge_a_sink_write() {
    let client_endpoint = endpoint(25).await;
    for interrupt in [true, false] {
        let sent = Arc::new(tokio::sync::Notify::new());
        let router = Router::builder(endpoint(26).await)
            .accept(ALPN, Partial(sent.clone()))
            .spawn();
        let mut client = Client::connect(&client_endpoint, router.endpoint().addr(), DEADLINE)
            .await
            .unwrap();
        let sink = Arc::new(CountSink(AtomicUsize::new(0)));
        let copy = sink.clone();
        let task = tokio::spawn(async move { client.deliver(copy.as_ref(), 0, 4).await });
        tokio::time::timeout(DEADLINE, sent.notified())
            .await
            .unwrap();
        if interrupt {
            router.shutdown().await.unwrap();
        }
        let error = tokio::time::timeout(DEADLINE * 2, task)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        if !interrupt {
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            router.shutdown().await.unwrap();
        }
        assert_eq!(sink.0.load(Ordering::SeqCst), 0);
    }
    client_endpoint.close().await;
}

#[tokio::test]
async fn each_range_rechecks_authorization_and_connection_admission_is_bounded() {
    use std::sync::atomic::AtomicBool;
    let allowed = Arc::new(AtomicBool::new(true));
    let decision = allowed.clone();
    let provider = move |_peer, _file| {
        let accepted = decision.load(Ordering::SeqCst);
        async move {
            if !accepted {
                return Err(io::Error::from(io::ErrorKind::PermissionDenied));
            }
            Ok(Memory)
        }
    };
    let router = Router::builder(endpoint(27).await)
        .accept(ALPN, FileProtocol::new(provider, 1, DEADLINE).unwrap())
        .spawn();
    let ep1 = endpoint(28).await;
    let ep2 = endpoint(29).await;
    let mut client = Client::connect(&ep1, router.endpoint().addr(), DEADLINE)
        .await
        .unwrap();
    assert_eq!(
        client.read_range(descriptor(), 0, 4).await.unwrap(),
        vec![7; 4]
    );
    allowed.store(false, Ordering::SeqCst);
    assert_eq!(
        client
            .read_range(descriptor(), 0, 4)
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    allowed.store(true, Ordering::SeqCst);
    assert_eq!(
        client.read_range(descriptor(), 0, 4).await.unwrap(),
        vec![7; 4]
    );
    // The established connection keeps the only permit, even between ranges.
    if let Ok(mut rejected) = Client::connect(&ep2, router.endpoint().addr(), DEADLINE).await {
        assert!(rejected.read_range(descriptor(), 0, 4).await.is_err());
    }
    assert_eq!(
        client.read_range(descriptor(), 0, 4).await.unwrap(),
        vec![7; 4]
    );
    drop(client);
    router.shutdown().await.unwrap();
    ep1.close().await;
    ep2.close().await;
}
