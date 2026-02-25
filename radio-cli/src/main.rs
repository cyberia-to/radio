use std::fs;
use std::io::{self, Read, Write as _};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use clap::{Parser, Subcommand};
use futures_lite::StreamExt;
use iroh::{Endpoint, RelayMode, SecretKey};
use iroh::protocol::Router;
use iroh_blobs::{BlobsProtocol, Hash, store::mem::MemStore};
use iroh_gossip::net::{Gossip, GOSSIP_ALPN};
use iroh_gossip::proto::TopicId;

use cyber_bao::hash::Poseidon2Backend;
use cyber_bao::io::{decode, encode, outboard};
use cyber_bao::tree::BlockSize;

#[derive(Parser)]
#[command(name = "radio", about = "Radio network CLI", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Poseidon2 hashing and BAO verified streaming
    Hash {
        #[command(subcommand)]
        action: HashAction,
    },
    /// Node identity and lifecycle
    Node {
        #[command(subcommand)]
        action: NodeAction,
    },
    /// Content-addressed blob storage and transfer
    Blob {
        #[command(subcommand)]
        action: BlobAction,
    },
    /// Pub/sub messaging over gossip
    Gossip {
        #[command(subcommand)]
        action: GossipAction,
    },
}

// ── Hash ───────────────────────────────────────────────────────────────

#[derive(Subcommand)]
enum HashAction {
    /// Hash files or stdin with Poseidon2
    Sum {
        /// Files to hash (reads stdin if none)
        files: Vec<PathBuf>,
    },
    /// Verify a file against an expected root hash
    Verify {
        /// File to verify
        file: PathBuf,
        /// Expected hash (128 hex chars)
        hash: String,
    },
    /// BAO encode a file (writes to stdout)
    BaoEncode {
        /// File to encode
        file: PathBuf,
    },
    /// BAO decode and verify (writes to stdout)
    BaoDecode {
        /// Encoded file
        file: PathBuf,
        /// Root hash (128 hex chars)
        hash: String,
    },
    /// Print outboard hash tree info
    Outboard {
        /// File to inspect
        file: PathBuf,
    },
}

// ── Node ───────────────────────────────────────────────────────────────

#[derive(Subcommand)]
enum NodeAction {
    /// Generate and print a new endpoint ID
    Id,
    /// Start a node with blobs + gossip (Ctrl-C to stop)
    Start,
}

// ── Blob ───────────────────────────────────────────────────────────────

#[derive(Subcommand)]
enum BlobAction {
    /// Import a file into the blob store and print its hash
    Add {
        /// File to import
        path: PathBuf,
    },
    /// Download a blob from a peer
    Get {
        /// Hash of the blob (hex)
        hash: String,
        /// Endpoint ID of the peer
        peer: iroh::EndpointId,
        /// Output file path
        #[arg(short, long)]
        out: PathBuf,
    },
    /// List stored blobs
    List,
}

// ── Gossip ─────────────────────────────────────────────────────────────

#[derive(Subcommand)]
enum GossipAction {
    /// Open a gossip topic (creates new if none given)
    Open {
        /// Topic ID (64 hex chars). Random if omitted.
        topic: Option<String>,
    },
    /// Join a gossip topic
    Join {
        /// Topic ID (64 hex chars)
        topic: String,
        /// Endpoint IDs of peers to bootstrap from
        peers: Vec<iroh::EndpointId>,
    },
}

// ── Main ───────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Hash { action } => cmd_hash(action),
        Commands::Node { action } => {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(cmd_node(action))
        }
        Commands::Blob { action } => {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(cmd_blob(action))
        }
        Commands::Gossip { action } => {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(cmd_gossip(action))
        }
    }
}

// ── Hash implementation ────────────────────────────────────────────────

fn cmd_hash(action: HashAction) -> Result<()> {
    match action {
        HashAction::Sum { files } => {
            if files.is_empty() {
                let mut data = Vec::new();
                io::stdin().read_to_end(&mut data)?;
                let h = cyber_poseidon2::hash(&data);
                println!("{h}");
            } else {
                for path in &files {
                    let data = fs::read(path)
                        .with_context(|| format!("reading {}", path.display()))?;
                    let h = cyber_poseidon2::hash(&data);
                    if files.len() > 1 {
                        println!("{h}  {}", path.display());
                    } else {
                        println!("{h}");
                    }
                }
            }
        }
        HashAction::Verify { file, hash } => {
            let data = fs::read(&file)
                .with_context(|| format!("reading {}", file.display()))?;
            let expected = parse_poseidon_hash(&hash)?;
            let backend = Poseidon2Backend;
            let ob = outboard::outboard(&backend, &data, BlockSize::ZERO);
            if ob.root == expected {
                println!("OK — root hash matches");
            } else {
                eprintln!("FAILED — hash mismatch");
                eprintln!("  expected: {expected}");
                eprintln!("  actual:   {}", ob.root);
                std::process::exit(1);
            }
        }
        HashAction::BaoEncode { file } => {
            let data = fs::read(&file)
                .with_context(|| format!("reading {}", file.display()))?;
            let backend = Poseidon2Backend;
            let (root, encoded) = encode::encode(&backend, &data, BlockSize::ZERO);
            io::stdout().write_all(&encoded)?;
            eprintln!("root hash: {root}");
            eprintln!("encoded size: {} bytes", encoded.len());
        }
        HashAction::BaoDecode { file, hash } => {
            let encoded = fs::read(&file)
                .with_context(|| format!("reading {}", file.display()))?;
            let root = parse_poseidon_hash(&hash)?;
            let backend = Poseidon2Backend;
            match decode::decode(&backend, &encoded, &root, BlockSize::ZERO) {
                Ok(data) => {
                    io::stdout().write_all(&data)?;
                    eprintln!("verified OK — {} bytes", data.len());
                }
                Err(e) => {
                    eprintln!("verification FAILED: {e}");
                    std::process::exit(1);
                }
            }
        }
        HashAction::Outboard { file } => {
            let data = fs::read(&file)
                .with_context(|| format!("reading {}", file.display()))?;
            let backend = Poseidon2Backend;
            let ob = outboard::outboard(&backend, &data, BlockSize::ZERO);
            println!("root hash:      {}", ob.root);
            println!("data size:      {} bytes", data.len());
            println!("blocks:         {}", ob.tree.blocks());
            println!("outboard size:  {} bytes", ob.data.len());
        }
    }
    Ok(())
}

fn parse_poseidon_hash(hex: &str) -> Result<cyber_poseidon2::Hash> {
    let bytes = hex_to_bytes(hex).context("invalid hex hash")?;
    if bytes.len() != 64 {
        bail!("hash must be 64 bytes (128 hex chars), got {} bytes", bytes.len());
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&bytes);
    Ok(cyber_poseidon2::Hash::from_bytes(arr))
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>> {
    if hex.len() % 2 != 0 {
        bail!("odd-length hex string");
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).context("invalid hex digit"))
        .collect()
}

// ── Node implementation ────────────────────────────────────────────────

async fn cmd_node(action: NodeAction) -> Result<()> {
    tracing_subscriber::fmt::init();

    match action {
        NodeAction::Id => {
            let secret_key = SecretKey::generate(&mut rand::rng());
            println!("secret key:   {}", data_encoding::HEXLOWER.encode(&secret_key.to_bytes()));
            println!("endpoint id:  {}", secret_key.public());
        }
        NodeAction::Start => {
            let secret_key = match std::env::var("RADIO_SECRET") {
                Ok(s) => s.parse().context("invalid RADIO_SECRET")?,
                Err(_) => {
                    let sk = SecretKey::generate(&mut rand::rng());
                    eprintln!("generated new secret key (set RADIO_SECRET to reuse):");
                    eprintln!("  RADIO_SECRET={}", data_encoding::HEXLOWER.encode(&sk.to_bytes()));
                    sk
                }
            };

            let store = MemStore::new();
            let endpoint = Endpoint::builder()
                .secret_key(secret_key)
                .relay_mode(RelayMode::Default)
                .bind()
                .await?;

            let blobs = BlobsProtocol::new(&store, None);
            let gossip = Gossip::builder().spawn(endpoint.clone());

            let router = Router::builder(endpoint.clone())
                .accept(iroh_blobs::ALPN, blobs)
                .accept(GOSSIP_ALPN, gossip)
                .spawn();

            endpoint.online().await;
            let addr = endpoint.addr();
            println!("node started");
            println!("endpoint id:  {}", endpoint.id());
            println!("address:      {addr:?}");

            tokio::signal::ctrl_c().await?;
            eprintln!("\nshutting down...");
            router.shutdown().await?;
        }
    }
    Ok(())
}

// ── Blob implementation ────────────────────────────────────────────────

async fn cmd_blob(action: BlobAction) -> Result<()> {
    tracing_subscriber::fmt::init();

    match action {
        BlobAction::Add { path } => {
            let store = MemStore::new();
            let endpoint = Endpoint::builder()
                .relay_mode(RelayMode::Default)
                .bind()
                .await?;
            let blobs = BlobsProtocol::new(&store, None);
            let _router = Router::builder(endpoint)
                .accept(iroh_blobs::ALPN, blobs)
                .spawn();

            let tag = store.blobs().add_path(&path).await
                .with_context(|| format!("importing {}", path.display()))?;
            println!("{}", tag.hash);
        }
        BlobAction::Get { hash, peer, out } => {
            let hash_bytes = hex_to_bytes(&hash)?;
            if hash_bytes.len() != 64 {
                bail!("blob hash must be 64 bytes (128 hex chars)");
            }
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&hash_bytes);
            let blob_hash = Hash::from_bytes(arr);

            let store = MemStore::new();
            let endpoint = Endpoint::builder()
                .relay_mode(RelayMode::Default)
                .bind()
                .await?;
            let blobs = BlobsProtocol::new(&store, None);
            let _router = Router::builder(endpoint.clone())
                .accept(iroh_blobs::ALPN, blobs)
                .spawn();

            let conn = endpoint.connect(peer, iroh_blobs::ALPN).await?;
            store.remote().fetch(conn, blob_hash).await?;

            let data = store.blobs().get_bytes(blob_hash).await?;
            fs::write(&out, &data)
                .with_context(|| format!("writing {}", out.display()))?;
            println!("downloaded {} bytes to {}", data.len(), out.display());
        }
        BlobAction::List => {
            let store = MemStore::new();
            let mut stream = store.tags().list().await?;
            let mut count = 0u64;
            while let Some(item) = stream.next().await {
                let info = item?;
                println!("{}  {:?}  {}", info.hash, info.format, String::from_utf8_lossy(info.name.as_ref()));
                count += 1;
            }
            if count == 0 {
                println!("(no blobs stored)");
            }
        }
    }
    Ok(())
}

// ── Gossip implementation ──────────────────────────────────────────────

async fn cmd_gossip(action: GossipAction) -> Result<()> {
    tracing_subscriber::fmt::init();

    let secret_key = match std::env::var("RADIO_SECRET") {
        Ok(s) => s.parse().context("invalid RADIO_SECRET")?,
        Err(_) => SecretKey::generate(&mut rand::rng()),
    };

    let endpoint = Endpoint::builder()
        .secret_key(secret_key)
        .relay_mode(RelayMode::Default)
        .bind()
        .await?;

    let gossip = Gossip::builder().spawn(endpoint.clone());
    let _router = Router::builder(endpoint.clone())
        .accept(GOSSIP_ALPN, gossip.clone())
        .spawn();

    endpoint.online().await;
    eprintln!("endpoint id: {}", endpoint.id());

    match action {
        GossipAction::Open { topic } => {
            let topic_id = match topic {
                Some(hex) => {
                    let bytes = hex_to_bytes(&hex)?;
                    if bytes.len() != 32 {
                        bail!("topic must be 32 bytes (64 hex chars)");
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    TopicId::from_bytes(arr)
                }
                None => TopicId::from_bytes(rand::random()),
            };
            eprintln!("topic: {topic_id}");
            eprintln!("waiting for peers...");

            let (sender, mut receiver) = gossip.subscribe_and_join(topic_id, vec![]).await?.split();

            // Read stdin in background, broadcast each line
            let (line_tx, mut line_rx) = tokio::sync::mpsc::channel::<String>(1);
            std::thread::spawn(move || {
                let stdin = io::stdin();
                let mut buf = String::new();
                loop {
                    buf.clear();
                    if stdin.read_line(&mut buf).unwrap_or(0) == 0 {
                        break;
                    }
                    let _ = line_tx.blocking_send(buf.clone());
                }
            });

            loop {
                tokio::select! {
                    Some(line) = line_rx.recv() => {
                        sender.broadcast(Bytes::from(line)).await?;
                    }
                    Some(event) = receiver.next() => {
                        match event? {
                            iroh_gossip::api::Event::Received(msg) => {
                                let text = String::from_utf8_lossy(&msg.content);
                                println!("[{}] {}", msg.delivered_from.fmt_short(), text.trim());
                            }
                            iroh_gossip::api::Event::NeighborUp(id) => {
                                eprintln!("+ peer joined: {}", id.fmt_short());
                            }
                            iroh_gossip::api::Event::NeighborDown(id) => {
                                eprintln!("- peer left: {}", id.fmt_short());
                            }
                            _ => {}
                        }
                    }
                    _ = tokio::signal::ctrl_c() => break,
                }
            }
        }
        GossipAction::Join { topic, peers } => {
            let topic_bytes = hex_to_bytes(&topic)?;
            if topic_bytes.len() != 32 {
                bail!("topic must be 32 bytes (64 hex chars)");
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&topic_bytes);
            let topic_id = TopicId::from_bytes(arr);

            eprintln!("topic: {topic_id}");
            eprintln!("joining with {} peers...", peers.len());

            let (sender, mut receiver) = gossip.subscribe_and_join(topic_id, peers).await?.split();

            let (line_tx, mut line_rx) = tokio::sync::mpsc::channel::<String>(1);
            std::thread::spawn(move || {
                let stdin = io::stdin();
                let mut buf = String::new();
                loop {
                    buf.clear();
                    if stdin.read_line(&mut buf).unwrap_or(0) == 0 {
                        break;
                    }
                    let _ = line_tx.blocking_send(buf.clone());
                }
            });

            loop {
                tokio::select! {
                    Some(line) = line_rx.recv() => {
                        sender.broadcast(Bytes::from(line)).await?;
                    }
                    Some(event) = receiver.next() => {
                        match event? {
                            iroh_gossip::api::Event::Received(msg) => {
                                let text = String::from_utf8_lossy(&msg.content);
                                println!("[{}] {}", msg.delivered_from.fmt_short(), text.trim());
                            }
                            iroh_gossip::api::Event::NeighborUp(id) => {
                                eprintln!("+ peer joined: {}", id.fmt_short());
                            }
                            iroh_gossip::api::Event::NeighborDown(id) => {
                                eprintln!("- peer left: {}", id.fmt_short());
                            }
                            _ => {}
                        }
                    }
                    _ = tokio::signal::ctrl_c() => break,
                }
            }
        }
    }

    Ok(())
}
