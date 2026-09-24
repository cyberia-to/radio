use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use cybergraph::{
    Particle,
    application::{ApplicationGraph, Head},
    catalog::{Catalog, Change, Entry},
};

use crate::files::{Storage, parse_particle};

#[derive(Args)]
pub struct Mutation {
    /// Exact prior catalog revision; conflicts if another operation advanced it
    #[arg(long)]
    expected: Option<u64>,
    /// Stable request for retries (64 hex digits); generated and printed if omitted
    #[arg(long, value_parser = parse_particle)]
    request: Option<Particle>,
}

#[derive(Subcommand)]
pub enum NameAction {
    /// Create or edit a name to point to an already sealed file
    Set {
        path: String,
        #[arg(value_parser = parse_particle)]
        particle: Particle,
        #[command(flatten)]
        mutation: Mutation,
    },
    /// Print the payload particle, stable binding and content revision
    Resolve {
        path: String,
        /// Read an exact historical revision
        #[arg(long)]
        at: Option<u64>,
    },
    /// Atomically move a name while preserving its payload and revision
    Rename {
        from: String,
        to: String,
        #[command(flatten)]
        mutation: Mutation,
    },
    /// Remove a selected name while retaining earlier states
    Remove {
        path: String,
        #[command(flatten)]
        mutation: Mutation,
    },
    /// List a pinned state in bounded lexicographic pages
    List {
        #[arg(long)]
        at: Option<u64>,
    },
    /// Read one page of retained catalog revisions
    History {
        /// Exclusive previous revision index
        #[arg(long)]
        after: Option<u64>,
        #[arg(long, default_value_t = 256, value_parser = clap::value_parser!(u16).range(1..=4096))]
        limit: u16,
    },
}

pub fn run(action: NameAction, storage: Storage) -> Result<()> {
    let (database, namespace) = storage.database()?;
    let graph = ApplicationGraph::from_database(database);
    let catalog = Catalog::new(&graph, namespace);
    match action {
        NameAction::Set {
            path,
            particle,
            mutation,
        } => {
            let (request, expected) = mutation.prepare(&graph, &catalog, namespace)?;
            let change = match catalog.resolve(expected, &path)? {
                Some(entry) => Change::Edit {
                    path: &path,
                    expected: entry,
                    particle,
                },
                None => Change::Create {
                    path: &path,
                    particle,
                },
            };
            print_head(catalog.apply(request, expected, change)?);
        }
        NameAction::Rename { from, to, mutation } => {
            let (request, expected) = mutation.prepare(&graph, &catalog, namespace)?;
            let entry = catalog
                .resolve(expected, &from)?
                .context("source name is absent in the selected state")?;
            print_head(catalog.apply(
                request,
                expected,
                Change::Rename {
                    from: &from,
                    to: &to,
                    expected: entry,
                },
            )?);
        }
        NameAction::Remove { path, mutation } => {
            let (request, expected) = mutation.prepare(&graph, &catalog, namespace)?;
            let entry = catalog
                .resolve(expected, &path)?
                .context("name is absent in the selected state")?;
            print_head(catalog.apply(
                request,
                expected,
                Change::Remove {
                    path: &path,
                    expected: entry,
                },
            )?);
        }
        NameAction::Resolve { path, at } => {
            let head = select(&catalog, at)?;
            let entry = catalog
                .resolve(head, &path)?
                .context("name is absent in the selected state")?;
            println!("particle {}", hex(entry.particle));
            println!("binding {}", hex(entry.binding));
            println!("revision {}", hex(entry.revision));
        }
        NameAction::List { at } => {
            let head = select(&catalog, at)?;
            let mut after = None;
            loop {
                let page = catalog.list(head, after.as_deref(), 256)?;
                for (path, entry) in page.entries {
                    print_entry(&path, entry);
                }
                after = page.next;
                if after.is_none() {
                    break;
                }
            }
        }
        NameAction::History { after, limit } => {
            let heads = catalog.history(after, usize::from(limit))?;
            for head in &heads {
                print_head(*head);
            }
            if heads.len() == usize::from(limit) {
                if let Some(head) = heads.last() {
                    eprintln!("continue with --after {}", head.index);
                }
            }
        }
    }
    Ok(())
}

impl Mutation {
    fn prepare(
        self,
        graph: &ApplicationGraph,
        catalog: &Catalog<'_>,
        namespace: Particle,
    ) -> Result<(Particle, Option<Head>)> {
        let request = self.request.unwrap_or_else(rand::random);
        eprintln!("request {}", hex(request));
        let expected = match self.expected {
            Some(index) => Some(at(catalog, index)?),
            None => match graph.resolve(&namespace, &request)? {
                Some(receipt) => match receipt.index.checked_sub(1) {
                    Some(index) => Some(at(catalog, index)?),
                    None => None,
                },
                None => catalog.head()?,
            },
        };
        Ok((request, expected))
    }
}
fn select(catalog: &Catalog<'_>, index: Option<u64>) -> Result<Option<Head>> {
    match index {
        Some(index) => Ok(Some(at(catalog, index)?)),
        None => Ok(catalog.head()?),
    }
}
fn at(catalog: &Catalog<'_>, index: u64) -> Result<Head> {
    catalog
        .history(index.checked_sub(1), 1)?
        .into_iter()
        .find(|head| head.index == index)
        .context("catalog revision does not exist")
}
fn print_head(head: Head) {
    println!("{} {}", head.index, hex(head.commit));
}
fn print_entry(path: &str, entry: Entry) {
    println!(
        "{} {} {} {path:?}",
        hex(entry.particle),
        hex(entry.binding),
        hex(entry.revision)
    );
}
fn hex(particle: Particle) -> String {
    data_encoding::HEXLOWER.encode(&particle)
}
