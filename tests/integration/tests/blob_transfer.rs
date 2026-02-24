use anyhow::Result;
use radio_integration_tests::{init_tracing, spawn_pair, spawn_nodes, test_rng};

#[tokio::test]
async fn blob_add_and_fetch_small() -> Result<()> {
    init_tracing();
    let mut rng = test_rng(b"blob_small");
    let (node_a, node_b) = spawn_pair(&mut rng).await?;

    let data = b"hello world";
    let tt = node_a.store.add_bytes(data.to_vec()).await?;

    let conn = node_b
        .router
        .endpoint()
        .connect(node_a.addr(), iroh_blobs::ALPN)
        .await?;
    node_b.store.remote().fetch(conn, tt.hash).await?;

    let fetched = node_b.store.get_bytes(tt.hash).await?;
    assert_eq!(fetched.as_ref(), data);

    tokio::try_join!(node_a.shutdown(), node_b.shutdown())?;
    Ok(())
}

#[tokio::test]
async fn blob_add_and_fetch_1mb() -> Result<()> {
    init_tracing();
    let mut rng = test_rng(b"blob_1mb");
    let (node_a, node_b) = spawn_pair(&mut rng).await?;

    // 1 MB of deterministic data
    let data: Vec<u8> = (0..1_048_576u32).map(|i| (i % 251) as u8).collect();
    let tt = node_a.store.add_bytes(data.clone()).await?;

    let conn = node_b
        .router
        .endpoint()
        .connect(node_a.addr(), iroh_blobs::ALPN)
        .await?;
    node_b.store.remote().fetch(conn, tt.hash).await?;

    let fetched = node_b.store.get_bytes(tt.hash).await?;
    assert_eq!(fetched.len(), data.len());
    assert_eq!(fetched.as_ref(), data.as_slice());

    tokio::try_join!(node_a.shutdown(), node_b.shutdown())?;
    Ok(())
}

#[tokio::test]
async fn blob_chunk_boundary() -> Result<()> {
    init_tracing();
    let mut rng = test_rng(b"blob_boundary");
    let (node_a, node_b) = spawn_pair(&mut rng).await?;

    // 1024 bytes = exactly 1 BAO chunk
    let data = vec![0xABu8; 1024];
    let tt = node_a.store.add_bytes(data.clone()).await?;

    let conn = node_b
        .router
        .endpoint()
        .connect(node_a.addr(), iroh_blobs::ALPN)
        .await?;
    node_b.store.remote().fetch(conn, tt.hash).await?;

    let fetched = node_b.store.get_bytes(tt.hash).await?;
    assert_eq!(fetched.as_ref(), data.as_slice());

    tokio::try_join!(node_a.shutdown(), node_b.shutdown())?;
    Ok(())
}

#[tokio::test]
async fn blob_empty() -> Result<()> {
    init_tracing();
    let mut rng = test_rng(b"blob_empty");
    let (node_a, node_b) = spawn_pair(&mut rng).await?;

    let data = b"";
    let tt = node_a.store.add_bytes(data.to_vec()).await?;

    let conn = node_b
        .router
        .endpoint()
        .connect(node_a.addr(), iroh_blobs::ALPN)
        .await?;
    node_b.store.remote().fetch(conn, tt.hash).await?;

    let fetched = node_b.store.get_bytes(tt.hash).await?;
    assert_eq!(fetched.as_ref(), data.as_ref());

    tokio::try_join!(node_a.shutdown(), node_b.shutdown())?;
    Ok(())
}

#[tokio::test]
async fn blob_multiple_sequential() -> Result<()> {
    init_tracing();
    let mut rng = test_rng(b"blob_multi");
    let (node_a, node_b) = spawn_pair(&mut rng).await?;

    let payloads: Vec<Vec<u8>> = (0..5)
        .map(|i| format!("payload number {i} with some extra bytes").into_bytes())
        .collect();

    let mut hashes = Vec::new();
    for payload in &payloads {
        let tt = node_a.store.add_bytes(payload.clone()).await?;
        hashes.push(tt.hash);
    }

    let conn = node_b
        .router
        .endpoint()
        .connect(node_a.addr(), iroh_blobs::ALPN)
        .await?;

    for (hash, payload) in hashes.iter().zip(&payloads) {
        node_b.store.remote().fetch(conn.clone(), *hash).await?;
        let fetched = node_b.store.get_bytes(*hash).await?;
        assert_eq!(fetched.as_ref(), payload.as_slice());
    }

    tokio::try_join!(node_a.shutdown(), node_b.shutdown())?;
    Ok(())
}

#[tokio::test]
async fn blob_fetch_via_downloader() -> Result<()> {
    init_tracing();
    let mut rng = test_rng(b"blob_downloader");
    let (node_a, node_b) = spawn_pair(&mut rng).await?;

    let data = b"downloading via the high-level API";
    let tt = node_a.store.add_bytes(data.to_vec()).await?;

    let downloader = node_b.store.downloader(node_b.router.endpoint());
    downloader.download(tt.hash, [node_a.id()]).await?;

    let fetched = node_b.store.get_bytes(tt.hash).await?;
    assert_eq!(fetched.as_ref(), data.as_ref());

    tokio::try_join!(node_a.shutdown(), node_b.shutdown())?;
    Ok(())
}

#[tokio::test]
async fn blob_three_nodes_relay() -> Result<()> {
    init_tracing();
    let mut rng = test_rng(b"blob_3nodes");
    let nodes = spawn_nodes(3, &mut rng).await?;

    let data = b"data pinned on node 0, fetched by nodes 1 and 2";
    let tt = nodes[0].store.add_bytes(data.to_vec()).await?;

    // Node 1 fetches from node 0
    let conn1 = nodes[1]
        .router
        .endpoint()
        .connect(nodes[0].addr(), iroh_blobs::ALPN)
        .await?;
    nodes[1].store.remote().fetch(conn1, tt.hash).await?;
    assert_eq!(nodes[1].store.get_bytes(tt.hash).await?.as_ref(), data.as_ref());

    // Node 2 fetches from node 0
    let conn2 = nodes[2]
        .router
        .endpoint()
        .connect(nodes[0].addr(), iroh_blobs::ALPN)
        .await?;
    nodes[2].store.remote().fetch(conn2, tt.hash).await?;
    assert_eq!(nodes[2].store.get_bytes(tt.hash).await?.as_ref(), data.as_ref());

    for node in nodes {
        node.shutdown().await?;
    }
    Ok(())
}
