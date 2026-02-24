use futures_lite::StreamExt;
use irpc::WithChannels;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::task::AbortOnDropHandle;

use crate::{
    form::EntryOrForm,
    rpc::{client::MemClient, proto::*},
    Engine,
};

#[derive(derive_more::Debug)]
pub(crate) struct RpcHandler {
    /// Client to hand out
    #[debug("MemClient")]
    pub(crate) client: MemClient,
    /// Handler task
    pub(crate) _handler: AbortOnDropHandle<()>,
}

impl RpcHandler {
    pub(crate) fn new(engine: Engine) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel::<RpcMessage>(32);
        let local = irpc::LocalSender::<Request>::from(tx);
        let client = MemClient::new(local.into());
        let _handler = AbortOnDropHandle::new(tokio::task::spawn(async move {
            let mut rx = rx;
            while let Some(msg) = rx.recv().await {
                let engine = engine.clone();
                tokio::task::spawn(async move {
                    if let Err(err) = handle_rpc_message(engine, msg).await {
                        tracing::error!(?err, "rpc handler error");
                    }
                });
            }
        }));
        Self { client, _handler }
    }
}

async fn handle_rpc_message(engine: Engine, msg: RpcMessage) -> anyhow::Result<()> {
    match msg {
        RpcMessage::IngestEntry(msg) => {
            let WithChannels { tx, inner, .. } = msg;
            let res = engine
                .ingest_entry(inner.authorised_entry)
                .await
                .map(|inserted| {
                    if inserted {
                        IngestEntrySuccess::Inserted
                    } else {
                        IngestEntrySuccess::Obsolete
                    }
                })
                .map_err(map_err);
            tx.send(res).await.ok();
        }
        RpcMessage::InsertEntry(msg) => {
            let WithChannels { tx, inner, .. } = msg;
            let entry = EntryOrForm::Form(inner.entry.into());
            let res = engine
                .insert_entry(entry, inner.auth)
                .await
                .map(|(entry, inserted)| {
                    if inserted {
                        InsertEntrySuccess::Inserted(entry)
                    } else {
                        InsertEntrySuccess::Obsolete
                    }
                })
                .map_err(map_err);
            tx.send(res).await.ok();
        }
        RpcMessage::InsertSecret(msg) => {
            let WithChannels { tx, inner, .. } = msg;
            let res = engine
                .insert_secret(inner.secret)
                .await
                .map(|_| InsertSecretResponse)
                .map_err(map_err);
            tx.send(res).await.ok();
        }
        RpcMessage::GetEntries(msg) => {
            let WithChannels { tx, inner, .. } = msg;
            match engine.get_entries(inner.namespace, inner.range).await {
                Ok(stream) => {
                    let mut stream = stream;
                    while let Some(res) = stream.next().await {
                        let item = res.map(GetEntriesResponse).map_err(map_err);
                        if tx.send(item).await.is_err() {
                            break;
                        }
                    }
                }
                Err(err) => {
                    tx.send(Err(map_err(err))).await.ok();
                }
            }
        }
        RpcMessage::GetEntry(msg) => {
            let WithChannels { tx, inner, .. } = msg;
            let res = engine
                .get_entry(inner.namespace, inner.subspace, inner.path)
                .await
                .map(|entry| GetEntryResponse(entry.map(Into::into)))
                .map_err(map_err);
            tx.send(res).await.ok();
        }
        RpcMessage::CreateNamespace(msg) => {
            let WithChannels { tx, inner, .. } = msg;
            let res = engine
                .create_namespace(inner.kind, inner.owner)
                .await
                .map(CreateNamespaceResponse)
                .map_err(map_err);
            tx.send(res).await.ok();
        }
        RpcMessage::CreateUser(msg) => {
            let WithChannels { tx, .. } = msg;
            let res = engine
                .create_user()
                .await
                .map(CreateUserResponse)
                .map_err(map_err);
            tx.send(res).await.ok();
        }
        RpcMessage::DelegateCaps(msg) => {
            let WithChannels { tx, inner, .. } = msg;
            let res = engine
                .delegate_caps(inner.from, inner.access_mode, inner.to)
                .await
                .map(DelegateCapsResponse)
                .map_err(map_err);
            tx.send(res).await.ok();
        }
        RpcMessage::ImportCaps(msg) => {
            let WithChannels { tx, inner, .. } = msg;
            let res = engine
                .import_caps(inner.caps)
                .await
                .map(|_| ImportCapsResponse)
                .map_err(map_err);
            tx.send(res).await.ok();
        }
        RpcMessage::SyncWithPeer(msg) => {
            let WithChannels { tx, rx, inner, .. } = msg;
            let (events_tx, mut events_rx) = tokio::sync::mpsc::channel(32);
            tokio::task::spawn(async move {
                if let Err(err) =
                    sync_with_peer(&engine, inner, events_tx.clone(), rx).await
                {
                    let _ = events_tx.send(Err(RpcError::new(&*err))).await;
                }
            });
            // Forward events from events_rx to tx
            while let Some(event) = events_rx.recv().await {
                if tx.send(event).await.is_err() {
                    break;
                }
            }
        }
        RpcMessage::Subscribe(msg) => {
            let WithChannels { tx, inner, .. } = msg;
            let (sub_tx, sub_rx) = mpsc::channel(1024);
            let res = if let Some(progress_id) = inner.initial_progress_id {
                engine
                    .resume_subscription(
                        progress_id,
                        inner.namespace,
                        inner.area,
                        inner.params,
                        sub_tx,
                    )
                    .await
            } else {
                engine
                    .subscribe_area(inner.namespace, inner.area, inner.params, sub_tx)
                    .await
            };
            match res {
                Ok(()) => {
                    let mut stream = ReceiverStream::new(sub_rx);
                    while let Some(event) = stream.next().await {
                        if tx.send(Ok(event)).await.is_err() {
                            break;
                        }
                    }
                }
                Err(err) => {
                    tx.send(Err(map_err(err))).await.ok();
                }
            }
        }
        RpcMessage::Addr(msg) => {
            let WithChannels { tx, .. } = msg;
            let res = engine.endpoint.addr();
            tx.send(Ok(res)).await.ok();
        }
        RpcMessage::AddAddr(msg) => {
            let WithChannels { tx, .. } = msg;
            // In iroh 0.96, addresses are resolved via AddressLookup services
            // rather than being explicitly added. This is now a no-op.
            tx.send(Ok(())).await.ok();
        }
    }
    Ok(())
}

async fn sync_with_peer(
    engine: &Engine,
    req: SyncWithPeerRequest,
    events_tx: mpsc::Sender<RpcResult<SyncWithPeerResponse>>,
    mut rx: irpc::channel::mpsc::Receiver<SyncWithPeerUpdate>,
) -> anyhow::Result<()> {
    let handle = engine
        .sync_with_peer(req.peer, req.init)
        .await
        .map_err(map_err)?;
    let (mut update_sink, mut events) = handle.split();
    tokio::task::spawn(async move {
        use futures_util::SinkExt;
        while let Ok(Some(update)) = rx.recv().await {
            if update_sink.send(update.0).await.is_err() {
                break;
            }
        }
    });
    tokio::task::spawn(async move {
        while let Some(event) = events.next().await {
            if events_tx
                .send(Ok(SyncWithPeerResponse::Event(event.into())))
                .await
                .is_err()
            {
                break;
            }
        }
    });
    Ok(())
}

fn map_err(err: anyhow::Error) -> RpcError {
    RpcError::new(&*err)
}
