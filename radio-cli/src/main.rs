use std::fs;
use std::io::{self, Write as _};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use clap::{Parser, Subcommand};
use futures_lite::StreamExt;
use iroh::protocol::Router;
use iroh::{Endpoint, RelayMode, SecretKey};
mod files;
mod names;
use files::{FileAction, Storage};
use iroh_gossip::net::{GOSSIP_ALPN, Gossip};
use iroh_gossip::proto::TopicId;

use cyber_bao::hash::Poseidon2Backend;
use cyber_bao::io::{decode, encode, outboard};
use cyber_bao::tree::BlockSize;

#[derive(Parser)]
#[command(name = "radio", about = "Radio network CLI", version)]
struct Cli {
    #[command(flatten)]
    storage: Storage,
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
    /// Durable files over the shared Cybergraph/BBG owner
    #[command(name = "file", visible_alias = "blob")]
    File {
        #[command(subcommand)]
        action: FileAction,
    },
    /// Versioned file names in the selected BBG namespace
    Name {
        #[command(subcommand)]
        action: names::NameAction,
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
    /// Verify exact bytes against the same particle as hash sum
    Verify {
        /// File to verify
        file: PathBuf,
        /// Expected hash (64 hex chars)
        hash: String,
    },
    /// Legacy BAO encode a file (writes to stdout)
    BaoEncode {
        /// File to encode
        file: PathBuf,
    },
    /// Legacy BAO decode and verify (writes to stdout)
    BaoDecode {
        /// Encoded file
        file: PathBuf,
        /// Root hash (64 hex chars)
        hash: String,
    },
    /// Print legacy BAO outboard hash tree info
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
    /// Serve authorized BBG files and gossip (Ctrl-C to stop)
    Start {
        /// Explicitly allow public reads in the selected namespace
        #[arg(
            long,
            conflicts_with = "allow_peer",
            required_unless_present = "allow_peer"
        )]
        public: bool,
        /// Transport peers authorized to read the selected namespace
        #[arg(long, num_args = 1.., conflicts_with = "public")]
        allow_peer: Vec<iroh::EndpointId>,
        /// Disable relays and discovery (direct connections only)
        #[arg(long)]
        local: bool,
    },
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
        Commands::Name { action } => names::run(action, cli.storage),
        Commands::Node { action } => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(cmd_node(action, cli.storage)),
        Commands::File { action } => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(files::run(action, cli.storage)),
        Commands::Gossip { action } => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(cmd_gossip(action)),
    }
}

// ── Hash implementation ────────────────────────────────────────────────

fn cmd_hash(action: HashAction) -> Result<()> {
    match action {
        HashAction::Sum { files } => {
            if files.is_empty() {
                let h = files::hash_reader(io::stdin().lock())?.0;
                println!("{h}");
            } else {
                for path in &files {
                    let h = files::hash_reader(
                        fs::File::open(path)
                            .with_context(|| format!("reading {}", path.display()))?,
                    )?
                    .0;
                    if files.len() > 1 {
                        println!("{h}  {}", path.display());
                    } else {
                        println!("{h}");
                    }
                }
            }
        }
        HashAction::Verify { file, hash } => {
            let expected = parse_poseidon_hash(&hash)?;
            let actual = files::hash_reader(
                fs::File::open(&file).with_context(|| format!("reading {}", file.display()))?,
            )?
            .0;
            if actual != expected {
                bail!("particle mismatch: expected {expected}, actual {actual}");
            }
            println!("OK — particle matches");
        }
        HashAction::BaoEncode { file } => {
            let data = fs::read(&file).with_context(|| format!("reading {}", file.display()))?;
            let backend = Poseidon2Backend;
            let (root, encoded) = encode::encode(&backend, &data, BlockSize::ZERO);
            io::stdout().write_all(&encoded)?;
            eprintln!("root hash: {root}");
            eprintln!("encoded size: {} bytes", encoded.len());
        }
        HashAction::BaoDecode { file, hash } => {
            let encoded = fs::read(&file).with_context(|| format!("reading {}", file.display()))?;
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
            let data = fs::read(&file).with_context(|| format!("reading {}", file.display()))?;
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

fn parse_poseidon_hash(hex: &str) -> Result<hemera::Hash> {
    let bytes = hex_to_bytes(hex).context("invalid hex hash")?;
    if bytes.len() != 32 {
        bail!(
            "hash must be 32 bytes (64 hex chars), got {} bytes",
            bytes.len()
        );
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(hemera::Hash::from_bytes(arr))
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>> {
    if !hex.is_ascii() || !hex.len().is_multiple_of(2) {
        bail!("expected an even number of ASCII hex digits");
    }
    data_encoding::HEXLOWER
        .decode(hex.to_ascii_lowercase().as_bytes())
        .context("invalid hex digit")
}

// ── Node implementation ────────────────────────────────────────────────

async fn cmd_node(action: NodeAction, storage: Storage) -> Result<()> {
    tracing_subscriber::fmt::init();

    match action {
        NodeAction::Id => {
            let secret_key = SecretKey::generate(&mut rand::rng());
            println!(
                "secret key:   {}",
                data_encoding::HEXLOWER.encode(&secret_key.to_bytes())
            );
            println!("endpoint id:  {}", secret_key.public());
        }
        NodeAction::Start {
            public,
            allow_peer,
            local,
        } => {
            files::serve(storage, public, allow_peer, local).await?;
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
