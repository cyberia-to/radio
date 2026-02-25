use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use futures_util::StreamExt;
use iroh_gossip::api::{Event, GossipReceiver};
use radio_integration_tests::{init_tracing, spawn_nodes, spawn_pair, test_rng};

#[tokio::test]
async fn gossip_two_nodes() -> Result<()> {
    init_tracing();
    let mut rng = test_rng(b"gossip_two");
    let (node_a, node_b) = spawn_pair(&mut rng).await?;

    let hash_bytes: [u8; 32] = cyber_poseidon2::hash(b"gossip-two-nodes").as_bytes()[..32].try_into().unwrap();
    let topic: iroh_gossip::TopicId = hash_bytes.into();

    // Both nodes subscribe without blocking; node B bootstraps off node A
    let sub_a = node_a.gossip.subscribe(topic, vec![]).await?;
    let sub_b = node_b.gossip.subscribe(topic, vec![node_a.id()]).await?;

    let (sender_a, mut receiver_a) = sub_a.split();
    let (_sender_b, mut receiver_b) = sub_b.split();

    // Wait for mesh to form concurrently (joined() waits for NeighborUp)
    tokio::try_join!(
        async {
            tokio::time::timeout(Duration::from_secs(10), receiver_a.joined())
                .await
                .map_err(|_| anyhow::anyhow!("timeout waiting for receiver_a join"))?
                .map_err(|e| anyhow::anyhow!(e))
        },
        async {
            tokio::time::timeout(Duration::from_secs(10), receiver_b.joined())
                .await
                .map_err(|_| anyhow::anyhow!("timeout waiting for receiver_b join"))?
                .map_err(|e| anyhow::anyhow!(e))
        },
    )?;

    // Node A broadcasts a message
    let msg = Bytes::from("hello from A");
    sender_a.broadcast(msg.clone()).await?;

    // Node B should receive it
    let received = wait_for_received(&mut receiver_b, Duration::from_secs(10)).await?;
    assert_eq!(received, msg);

    tokio::try_join!(node_a.shutdown(), node_b.shutdown())?;
    Ok(())
}

#[tokio::test]
async fn gossip_three_nodes_fan_out() -> Result<()> {
    init_tracing();
    let mut rng = test_rng(b"gossip_fan_out");
    let nodes = spawn_nodes(3, &mut rng).await?;

    let hash_bytes: [u8; 32] = cyber_poseidon2::hash(b"gossip-fan-out").as_bytes()[..32].try_into().unwrap();
    let topic: iroh_gossip::TopicId = hash_bytes.into();

    // All subscribe; nodes 1 and 2 bootstrap off node 0
    let sub0 = nodes[0].gossip.subscribe(topic, vec![]).await?;
    let sub1 = nodes[1]
        .gossip
        .subscribe(topic, vec![nodes[0].id()])
        .await?;
    let sub2 = nodes[2]
        .gossip
        .subscribe(topic, vec![nodes[0].id()])
        .await?;

    let (sender0, _recv0) = sub0.split();
    let (_sender1, mut recv1) = sub1.split();
    let (_sender2, mut recv2) = sub2.split();

    // Wait for mesh to form concurrently
    tokio::try_join!(
        async {
            tokio::time::timeout(Duration::from_secs(10), recv1.joined())
                .await
                .map_err(|_| anyhow::anyhow!("timeout waiting for recv1 join"))?
                .map_err(|e| anyhow::anyhow!(e))
        },
        async {
            tokio::time::timeout(Duration::from_secs(10), recv2.joined())
                .await
                .map_err(|_| anyhow::anyhow!("timeout waiting for recv2 join"))?
                .map_err(|e| anyhow::anyhow!(e))
        },
    )?;

    // Node 0 broadcasts
    let msg = Bytes::from("broadcast to all");
    sender0.broadcast(msg.clone()).await?;

    // Both node 1 and node 2 should receive
    let r1 = wait_for_received(&mut recv1, Duration::from_secs(10)).await?;
    let r2 = wait_for_received(&mut recv2, Duration::from_secs(10)).await?;
    assert_eq!(r1, msg);
    assert_eq!(r2, msg);

    for node in nodes {
        node.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn gossip_bidirectional() -> Result<()> {
    init_tracing();
    let mut rng = test_rng(b"gossip_bidir");
    let (node_a, node_b) = spawn_pair(&mut rng).await?;

    let hash_bytes: [u8; 32] = cyber_poseidon2::hash(b"gossip-bidir").as_bytes()[..32].try_into().unwrap();
    let topic: iroh_gossip::TopicId = hash_bytes.into();

    // Both subscribe; node B bootstraps off node A
    let sub_a = node_a.gossip.subscribe(topic, vec![]).await?;
    let sub_b = node_b.gossip.subscribe(topic, vec![node_a.id()]).await?;

    let (sender_a, mut receiver_a) = sub_a.split();
    let (sender_b, mut receiver_b) = sub_b.split();

    // Wait for mesh to form concurrently
    tokio::try_join!(
        async {
            tokio::time::timeout(Duration::from_secs(10), receiver_a.joined())
                .await
                .map_err(|_| anyhow::anyhow!("timeout waiting for receiver_a join"))?
                .map_err(|e| anyhow::anyhow!(e))
        },
        async {
            tokio::time::timeout(Duration::from_secs(10), receiver_b.joined())
                .await
                .map_err(|_| anyhow::anyhow!("timeout waiting for receiver_b join"))?
                .map_err(|e| anyhow::anyhow!(e))
        },
    )?;

    // A -> B
    let msg_a = Bytes::from("from A");
    sender_a.broadcast(msg_a.clone()).await?;
    let received_b = wait_for_received(&mut receiver_b, Duration::from_secs(10)).await?;
    assert_eq!(received_b, msg_a);

    // B -> A
    let msg_b = Bytes::from("from B");
    sender_b.broadcast(msg_b.clone()).await?;
    let received_a = wait_for_received(&mut receiver_a, Duration::from_secs(10)).await?;
    assert_eq!(received_a, msg_b);

    tokio::try_join!(node_a.shutdown(), node_b.shutdown())?;
    Ok(())
}

// --- Helpers ---

async fn wait_for_received(
    receiver: &mut GossipReceiver,
    timeout: Duration,
) -> Result<Bytes> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let item = tokio::time::timeout_at(deadline, receiver.next())
            .await?
            .ok_or_else(|| anyhow::anyhow!("stream ended"))?;
        let event = item.map_err(|e| anyhow::anyhow!("{e}"))?;
        if let Event::Received(msg) = event {
            return Ok(msg.content);
        }
    }
}
