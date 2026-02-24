use std::future::Future;

use anyhow::Result;
use iroh::{
    address_lookup::MemoryLookup, protocol::Router, Endpoint, EndpointId, RelayMode, SecretKey,
};
use iroh_blobs::{store::mem::MemStore, BlobsProtocol};
use iroh_docs::{api::DocsApi, protocol::Docs};
use iroh_gossip::net::Gossip;
use rand::{CryptoRng, Rng, SeedableRng};

/// A test node wrapping all protocols: blobs, gossip, docs.
pub struct TestNode {
    pub router: Router,
    pub store: MemStore,
    pub gossip: Gossip,
    pub docs_api: DocsApi,
}

impl TestNode {
    /// Endpoint ID of this node.
    pub fn id(&self) -> EndpointId {
        self.router.endpoint().id()
    }

    /// The endpoint address (for connecting / registering with MemoryLookup).
    pub fn addr(&self) -> iroh::EndpointAddr {
        self.router.endpoint().addr()
    }

    /// Graceful shutdown.
    pub async fn shutdown(self) -> Result<()> {
        self.router.shutdown().await?;
        Ok(())
    }
}

/// Spawn a single test node with the given MemoryLookup for address discovery.
fn spawn_one(
    rng: &mut (impl CryptoRng + Rng),
    disco: MemoryLookup,
) -> impl Future<Output = Result<TestNode>> + 'static {
    let secret_key = SecretKey::generate(rng);
    async move {
        let ep = Endpoint::empty_builder(RelayMode::Disabled)
            .secret_key(secret_key)
            .address_lookup(disco)
            .bind()
            .await?;

        let store = MemStore::new();
        let blobs_store = (*store).clone(); // iroh_blobs::api::Store
        let gossip = Gossip::builder().spawn(ep.clone());
        let docs = Docs::memory()
            .spawn(ep.clone(), blobs_store.clone(), gossip.clone())
            .await?;

        let router = Router::builder(ep)
            .accept(iroh_blobs::ALPN, BlobsProtocol::new(&blobs_store, None))
            .accept(iroh_docs::ALPN, docs.clone())
            .accept(iroh_gossip::ALPN, gossip.clone())
            .spawn();

        Ok(TestNode {
            router,
            store,
            gossip,
            docs_api: docs.api().clone(),
        })
    }
}

/// Spawn a pair of test nodes that can discover each other.
pub async fn spawn_pair(rng: &mut (impl CryptoRng + Rng)) -> Result<(TestNode, TestNode)> {
    let disco = MemoryLookup::new();
    let fut_a = spawn_one(rng, disco.clone());
    let fut_b = spawn_one(rng, disco.clone());
    let (a, b) = tokio::try_join!(fut_a, fut_b)?;
    disco.add_endpoint_info(a.addr());
    disco.add_endpoint_info(b.addr());
    Ok((a, b))
}

/// Spawn N test nodes that can all discover each other.
pub async fn spawn_nodes(n: usize, rng: &mut (impl CryptoRng + Rng)) -> Result<Vec<TestNode>> {
    let disco = MemoryLookup::new();
    let mut futs = Vec::with_capacity(n);
    for _ in 0..n {
        futs.push(spawn_one(rng, disco.clone()));
    }
    let nodes: Vec<TestNode> = futures_util::future::try_join_all(futs).await?;
    for node in &nodes {
        disco.add_endpoint_info(node.addr());
    }
    Ok(nodes)
}

/// Create a deterministic RNG from a seed string.
pub fn test_rng(seed: &[u8]) -> rand_chacha::ChaCha12Rng {
    let hash = cyber_poseidon2::hash(seed);
    rand_chacha::ChaCha12Rng::from_seed(*hash.as_bytes())
}

/// Initialize tracing for tests (call once, ignores errors on repeat calls).
pub fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init()
        .ok();
}
