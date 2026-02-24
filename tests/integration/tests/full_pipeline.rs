use std::time::Duration;

use anyhow::Result;
use futures_util::StreamExt;
use iroh_docs::{
    api::protocol::{AddrInfoOptions, ShareMode},
    engine::LiveEvent,
};
use radio_integration_tests::{init_tracing, spawn_pair, test_rng};

/// End-to-end: pin a blob on node A, create a doc entry referencing it,
/// node B syncs the doc and downloads the blob content.
#[tokio::test]
async fn pin_then_doc_sync_then_download() -> Result<()> {
    init_tracing();
    let mut rng = test_rng(b"full_pipeline");
    let (node_a, node_b) = spawn_pair(&mut rng).await?;

    // 1. Pin a blob on node A
    let blob_data = b"important content pinned on node A for distribution";
    let tt = node_a.store.add_bytes(blob_data.to_vec()).await?;
    let blob_hash = tt.hash;

    // 2. Create a doc on node A with an entry that uses the blob hash as its content
    let author_a = node_a.docs_api.author_create().await?;
    let doc_a = node_a.docs_api.create().await?;

    // set_bytes stores the value and creates an entry whose content_hash is the hash of the value
    let entry_hash = doc_a
        .set_bytes(
            author_a,
            b"pinned-file".to_vec(),
            blob_data.to_vec(),
        )
        .await?;
    // The hash from set_bytes is the content hash (BAO root of the value bytes)
    assert_eq!(entry_hash, blob_hash);

    // 3. Share the doc with node B
    let ticket = doc_a
        .share(ShareMode::Write, AddrInfoOptions::RelayAndAddresses)
        .await?;
    let doc_b = node_b.docs_api.import(ticket).await?;
    let mut events_b = doc_b.subscribe().await?;

    // 4. Wait for the content to be synced and downloaded on node B
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let event = tokio::time::timeout_at(deadline, events_b.next())
            .await?
            .ok_or_else(|| anyhow::anyhow!("event stream ended"))??;
        if let LiveEvent::ContentReady { hash } = event {
            if hash == blob_hash {
                break;
            }
        }
    }

    // 5. Verify the full pipeline: entry exists + content matches
    let entry = doc_b
        .get_exact(author_a, b"pinned-file".to_vec(), false)
        .await?
        .expect("entry should exist on node B");
    assert_eq!(entry.content_hash(), blob_hash);

    let downloaded = node_b.store.get_bytes(blob_hash).await?;
    assert_eq!(downloaded.as_ref(), blob_data.as_ref());

    tokio::try_join!(node_a.shutdown(), node_b.shutdown())?;
    Ok(())
}

/// Pin multiple blobs, reference them in doc entries, sync all to node B.
#[tokio::test]
async fn multi_blob_doc_sync() -> Result<()> {
    init_tracing();
    let mut rng = test_rng(b"multi_blob_pipeline");
    let (node_a, node_b) = spawn_pair(&mut rng).await?;

    let author_a = node_a.docs_api.author_create().await?;
    let doc_a = node_a.docs_api.create().await?;

    // Create 3 entries with different content
    let items = vec![
        (b"file1".to_vec(), b"content of file 1".to_vec()),
        (b"file2".to_vec(), b"content of file two".to_vec()),
        (b"file3".to_vec(), b"third file's content".to_vec()),
    ];

    let mut expected_hashes = Vec::new();
    for (key, value) in &items {
        let hash = doc_a
            .set_bytes(author_a, key.clone(), value.clone())
            .await?;
        expected_hashes.push(hash);
    }

    // Share and sync
    let ticket = doc_a
        .share(ShareMode::Write, AddrInfoOptions::RelayAndAddresses)
        .await?;
    let doc_b = node_b.docs_api.import(ticket).await?;
    let mut events_b = doc_b.subscribe().await?;

    // Wait for all 3 contents to be ready
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut ready_hashes = std::collections::HashSet::new();
    while ready_hashes.len() < expected_hashes.len() {
        let event = tokio::time::timeout_at(deadline, events_b.next())
            .await?
            .ok_or_else(|| anyhow::anyhow!("event stream ended"))??;
        if let LiveEvent::ContentReady { hash } = event {
            ready_hashes.insert(hash);
        }
    }

    // Verify all entries and their content
    for (i, (key, value)) in items.iter().enumerate() {
        let entry = doc_b
            .get_exact(author_a, key.clone(), false)
            .await?
            .unwrap_or_else(|| panic!("entry {} should exist on node B", i));
        let content = node_b.store.get_bytes(entry.content_hash()).await?;
        assert_eq!(content.as_ref(), value.as_slice());
    }

    tokio::try_join!(node_a.shutdown(), node_b.shutdown())?;
    Ok(())
}
