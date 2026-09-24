use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand, ValueEnum};
use cybergraph::{
    Particle,
    application::{Backend, Database},
    files::{Files, State, Upload, blob_profile},
};
use cybergraph_radio::{ALPN, Client, FileId, FileProtocol, FileSink, FileSource, receive_page};
use iroh::{Endpoint, EndpointId, RelayMode, SecretKey, protocol::Router};
use iroh_gossip::net::{GOSSIP_ALPN, Gossip};
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    net::SocketAddr,
    path::PathBuf,
    time::Duration,
};

const PART_BYTES: u32 = 64 * 1024;
const PAGE: usize = 256;
const DEADLINE: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, ValueEnum, Default)]
enum Profile {
    #[default]
    Ssd,
    Hdd,
}
#[derive(Args)]
pub struct Storage {
    /// Shared BBG path (Fjall directory or redb file)
    #[arg(long, global = true)]
    database: Option<PathBuf>,
    /// Local authorization namespace (64 hex digits)
    #[arg(long, global = true, value_parser = parse_particle)]
    namespace: Option<Particle>,
    /// Physical backend selected by the database owner
    #[arg(long, global = true, value_enum, default_value = "ssd")]
    backend: Profile,
}
impl Storage {
    pub(crate) fn database(self) -> Result<(Database, Particle)> {
        let path = self
            .database
            .context("file operations require --database")?;
        let namespace = self
            .namespace
            .context("file operations require --namespace")?;
        let backend = match self.backend {
            Profile::Ssd => Backend::Ssd,
            Profile::Hdd => Backend::Hdd,
        };
        Ok((Database::open(path, backend)?, namespace))
    }
    fn open(self) -> Result<(Files, Particle)> {
        let (db, namespace) = self.database()?;
        Ok((Files::from_database(db), namespace))
    }
}
#[derive(Subcommand)]
pub enum FileAction {
    /// Import exact bytes into BBG and print their particle
    Add { path: PathBuf },
    /// Download, resume in BBG, verify, then export a file
    Get {
        #[arg(value_parser = parse_particle)]
        particle: Particle,
        peer: EndpointId,
        #[arg(short, long)]
        out: PathBuf,
        /// Direct peer address (may be repeated)
        #[arg(long)]
        addr: Vec<SocketAddr>,
        /// Disable relays and discovery (direct connections only)
        #[arg(long)]
        local: bool,
    },
    /// Export a sealed local file with Radio offline
    Export {
        #[arg(value_parser = parse_particle)]
        particle: Particle,
        #[arg(short, long)]
        out: PathBuf,
    },
    /// Page through sealed files in the selected BBG namespace
    List,
}
pub(crate) fn parse_particle(text: &str) -> Result<Particle, String> {
    let bytes = crate::hex_to_bytes(text).map_err(|e| e.to_string())?;
    bytes
        .try_into()
        .map_err(|_| "particle must contain 64 hex digits".into())
}

/// Hash a stream with fixed working memory and checked byte count.
pub fn hash_reader(mut input: impl Read) -> Result<(hemera::Hash, u64)> {
    let mut hash = hemera::Hasher::new();
    let mut length = 0u64;
    let mut buffer = [0; PART_BYTES as usize];
    loop {
        let count = match input.read(&mut buffer) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            value => value?,
        };
        if count == 0 {
            break;
        }
        length = length
            .checked_add(count as u64)
            .context("file length overflow")?;
        hash.update(&buffer[..count]);
    }
    Ok((hash.finalize(), length))
}
fn upload(namespace: Particle, particle: Particle, length: u64) -> Upload {
    let mut hash = hemera::Hasher::new();
    hash.update(b"cybergraph/cli-file-import\0");
    hash.update(&namespace);
    hash.update(&particle);
    hash.update(&blob_profile());
    hash.update(&length.to_le_bytes());
    hash.update(&PART_BYTES.to_le_bytes());
    Upload {
        namespace,
        request: *hash.finalize().as_bytes(),
    }
}
async fn blocking<T: Send + 'static>(
    job: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    tokio::task::spawn_blocking(job).await?
}
fn export(files: &Files, namespace: Particle, particle: Particle, path: PathBuf) -> Result<u64> {
    let mut input = files.reader(namespace, particle)?;
    // Avoid data loss on retries and never overwrite the selected database/input.
    let mut output =
        File::create_new(&path).with_context(|| format!("creating {}", path.display()))?;
    let bytes = io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    Ok(bytes)
}
fn endpoint_key() -> Result<SecretKey> {
    match std::env::var("RADIO_SECRET") {
        Ok(value) => value.parse().context("invalid RADIO_SECRET"),
        Err(std::env::VarError::NotPresent) => Ok(SecretKey::generate(&mut rand::rng())),
        Err(error) => Err(error.into()),
    }
}
async fn endpoint(local: bool) -> Result<Endpoint> {
    let builder = if local {
        Endpoint::empty_builder(RelayMode::Disabled)
    } else {
        Endpoint::builder()
    };
    Ok(builder.secret_key(endpoint_key()?).bind().await?)
}

pub async fn run(action: FileAction, storage: Storage) -> Result<()> {
    let (files, namespace) = blocking(move || storage.open()).await?;
    match action {
        FileAction::Add { path } => {
            let particle = blocking(move || {
                let mut input = File::open(&path)?;
                let (particle, length) = hash_reader(&mut input)?;
                input.seek(SeekFrom::Start(0))?;
                let id = *particle.as_bytes();
                // Re-read and verify: a changing input cannot bind wrong bytes.
                files.import(upload(namespace, id, length), id, length, PART_BYTES, input)?;
                Ok(particle)
            })
            .await?;
            println!("{particle}");
        }
        FileAction::List => {
            blocking(move || {
                let mut after = None;
                let mut found = false;
                loop {
                    let rows = files.uploads(namespace, after, PAGE)?;
                    if rows.is_empty() {
                        break;
                    }
                    for (upload, progress) in &rows {
                        if progress.state == State::Sealed
                            && files
                                .info(namespace, progress.spec.particle)?
                                .is_some_and(|info| info.upload == *upload)
                        {
                            println!(
                                "{}  {}",
                                data_encoding::HEXLOWER.encode(&progress.spec.particle),
                                progress.spec.length
                            );
                            found = true;
                        }
                    }
                    after = rows.last().map(|(upload, _)| upload.request);
                }
                if !found {
                    println!("(no files stored)");
                }
                Ok(())
            })
            .await?;
        }
        FileAction::Export { particle, out } => {
            let size = blocking(move || export(&files, namespace, particle, out)).await?;
            println!("exported {size} bytes");
        }
        FileAction::Get {
            particle,
            peer,
            out,
            addr,
            local,
        } => {
            if out.try_exists()? {
                bail!("output already exists: {}", out.display());
            }
            let ep = endpoint(local).await?;
            let result = async {
                let mut address = iroh::EndpointAddr::new(peer);
                for addr in addr {
                    address = address.with_ip_addr(addr);
                }
                let mut client = Client::connect(&ep, address, DEADLINE).await?;
                let descriptor = client
                    .describe(FileId {
                        particle,
                        profile: blob_profile(),
                    })
                    .await?;
                let id = upload(namespace, particle, descriptor.length);
                let stored = files.clone();
                blocking(move || {
                    stored.begin(id, particle, descriptor.length, PART_BYTES)?;
                    Ok(())
                })
                .await?;
                let sink = FileSink::open(files.clone(), id).await?;
                let mut from = 0;
                loop {
                    let page = receive_page(&mut client, &sink, from, PAGE).await?;
                    match page.next {
                        Some(next) => from = next,
                        None => break,
                    }
                }
                sink.seal().await?;
                drop(client);
                blocking(move || export(&files, namespace, particle, out)).await
            }
            .await;
            ep.close().await;
            println!("downloaded {} bytes", result?);
        }
    }
    Ok(())
}

pub async fn serve(
    storage: Storage,
    public: bool,
    peers: Vec<EndpointId>,
    local: bool,
) -> Result<()> {
    if !public && peers.is_empty() {
        bail!("serving requires --public or --allow-peer");
    }
    let (files, namespace) = blocking(move || storage.open()).await?;
    let provider = move |peer: EndpointId, file: FileId| {
        let allowed = (public || peers.contains(&peer)) && file.profile == blob_profile();
        let files = files.clone();
        async move {
            if !allowed {
                return Err(io::Error::from(io::ErrorKind::PermissionDenied));
            }
            FileSource::open(files, namespace, file.particle).await
        }
    };
    let ep = endpoint(local).await?;
    let gossip = Gossip::builder().spawn(ep.clone());
    let router = Router::builder(ep.clone())
        .accept(ALPN, FileProtocol::new(provider, 64, DEADLINE)?)
        .accept(GOSSIP_ALPN, gossip)
        .spawn();
    if !local {
        ep.online().await;
    }
    println!("endpoint id: {}", ep.id());
    for addr in ep.addr().ip_addrs() {
        println!("direct address: {addr}");
    }
    io::stdout().flush()?;
    let stop = tokio::signal::ctrl_c().await;
    let shutdown = router.shutdown().await;
    stop?;
    shutdown?;
    Ok(())
}
