use std::time::Duration;

use anyhow::Result;
use futures_util::StreamExt;
use iroh_docs::{
    api::protocol::{AddrInfoOptions, ShareMode},
    engine::LiveEvent,
};
use radio_integration_tests::{init_tracing, spawn_pair, test_rng};

#[tokio::test]
async fn doc_sync_simple() -> Result<()> {
    init_tracing();
    let mut rng = test_rng(b"doc_sync_simple");
    let (node_a, node_b) = spawn_pair(&mut rng).await?;

    // Node A: create doc, write key/value
    let author_a = node_a.docs_api.author_create().await?;
    let doc_a = node_a.docs_api.create().await?;
    let hash_a = doc_a
        .set_bytes(author_a, b"greeting".to_vec(), b"hello world".to_vec())
        .await?;

    // Share with node B
    let ticket = doc_a
        .share(ShareMode::Write, AddrInfoOptions::RelayAndAddresses)
        .await?;
    let doc_b = node_b.docs_api.import(ticket).await?;
    let mut events_b = doc_b.subscribe().await?;

    // Wait for content to arrive
    wait_for_content_ready(&mut events_b, hash_a, Duration::from_secs(30)).await?;

    // Verify the entry on node B
    let entry = doc_b
        .get_exact(author_a, b"greeting".to_vec(), false)
        .await?
        .expect("entry should exist on node B");
    assert_eq!(entry.content_hash(), hash_a);

    // Verify the blob content on node B
    let content = node_b.store.get_bytes(hash_a).await?;
    assert_eq!(content.as_ref(), b"hello world");

    tokio::try_join!(node_a.shutdown(), node_b.shutdown())?;
    Ok(())
}

#[tokio::test]
async fn doc_sync_bidirectional() -> Result<()> {
    init_tracing();
    let mut rng = test_rng(b"doc_sync_bidir");
    let (node_a, node_b) = spawn_pair(&mut rng).await?;

    // Node A: create doc
    let author_a = node_a.docs_api.author_create().await?;
    let doc_a = node_a.docs_api.create().await?;
    let hash_a = doc_a
        .set_bytes(author_a, b"from_a".to_vec(), b"value_a".to_vec())
        .await?;

    // Share with node B
    let ticket = doc_a
        .share(ShareMode::Write, AddrInfoOptions::RelayAndAddresses)
        .await?;
    let doc_b = node_b.docs_api.import(ticket).await?;
    let mut events_b = doc_b.subscribe().await?;

    // Wait for node B to receive node A's entry
    wait_for_content_ready(&mut events_b, hash_a, Duration::from_secs(30)).await?;

    // Node B writes its own entry
    let author_b = node_b.docs_api.author_create().await?;
    let hash_b = doc_b
        .set_bytes(author_b, b"from_b".to_vec(), b"value_b".to_vec())
        .await?;

    // Node A should receive node B's entry via live sync
    let mut events_a = doc_a.subscribe().await?;
    wait_for_content_ready(&mut events_a, hash_b, Duration::from_secs(30)).await?;

    // Verify both entries exist on both nodes
    let entry_a_on_b = doc_b
        .get_exact(author_a, b"from_a".to_vec(), false)
        .await?;
    assert!(entry_a_on_b.is_some());

    let entry_b_on_a = doc_a
        .get_exact(author_b, b"from_b".to_vec(), false)
        .await?;
    assert!(entry_b_on_a.is_some());

    tokio::try_join!(node_a.shutdown(), node_b.shutdown())?;
    Ok(())
}

#[tokio::test]
async fn doc_sync_large_value() -> Result<()> {
    init_tracing();
    let mut rng = test_rng(b"doc_sync_large");
    let (node_a, node_b) = spawn_pair(&mut rng).await?;

    // 1 MB value
    let large_value: Vec<u8> = (0..1_048_576u32).map(|i| (i % 251) as u8).collect();

    let author_a = node_a.docs_api.author_create().await?;
    let doc_a = node_a.docs_api.create().await?;
    let hash_a = doc_a
        .set_bytes(author_a, b"big".to_vec(), large_value.clone())
        .await?;

    let ticket = doc_a
        .share(ShareMode::Write, AddrInfoOptions::RelayAndAddresses)
        .await?;
    let doc_b = node_b.docs_api.import(ticket).await?;
    let mut events_b = doc_b.subscribe().await?;

    wait_for_content_ready(&mut events_b, hash_a, Duration::from_secs(60)).await?;

    let content = node_b.store.get_bytes(hash_a).await?;
    assert_eq!(content.len(), large_value.len());
    assert_eq!(content.as_ref(), large_value.as_slice());

    tokio::try_join!(node_a.shutdown(), node_b.shutdown())?;
    Ok(())
}

// --- Helpers ---

async fn wait_for_content_ready(
    events: &mut (impl futures_util::Stream<Item = Result<LiveEvent, anyhow::Error>> + Unpin),
    expected_hash: iroh_blobs::Hash,
    timeout: Duration,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let event = tokio::time::timeout_at(deadline, events.next())
            .await?
            .ok_or_else(|| anyhow::anyhow!("event stream ended"))??;
        if let LiveEvent::ContentReady { hash } = event {
            if hash == expected_hash {
                return Ok(());
            }
        }
    }
}
