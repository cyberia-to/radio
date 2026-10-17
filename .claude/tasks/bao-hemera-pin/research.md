# Reproducible Hemera source for BAO

Serves: owner's Kadek phase-1 closure · Radio/soft3 · prerequisite for bounded
BAO verification in Kadek foundation row 4. Dependency-only task; bounded root
reduction, no_std API, slice parsing and authenticated particle/root association
remain separate dependent work. No production change has been made.

Owned worktree: `/Users/master/cyber/radio-bao-bounded-root`, branch
`feat/bao-hemera-pin`, parent Radio
`a11d342594949d4ea542b26366f71d56ef21662d`. The worktree was created clean from
that commit; its initial branch was renamed before any edit. Shared Radio and
Hemera working trees are not inputs. Fresh `git ls-remote origin HEAD` returned
that Radio revision and Hemera `d5f0a09539360934fb32db9b2e15a91995607db6`.

## Source and dependency facts

Radio has no committed root/cyber-bao AGENTS.md or CLAUDE.md at this parent.
The supplied parent AGENTS.md and cyberia/dev.md apply; engineering, quality,
projects, documentation, refinement and fathership were read. Repository gates
come from Makefile.toml and .github/workflows/{ci.yml,tests.yaml,docs.yaml}.
No formatter, source, manifest, lock, specification, version or release edit is
included in this research.

Eight root-workspace members use a sibling Hemera path:

| Manifest directory | Current Hemera features |
|---|---|
| cyber-bao | default → std; serde forwarded when selected |
| iroh-blobs | default → std, serde |
| iroh-docs | default → std |
| iroh-gossip | default → std |
| iroh-relay | default → std; additionally declares version 0.3 |
| iroh-willow | default → std |
| particle | default → std |
| radio-cli | default → std |

They all spell `path="../../hemera/rs"`. Root Cargo.lock records the resulting
cyber-hemera 0.3.1 without a source revision. The hosted PR36 receipt
`audit/2026-10-11-empty-status/hosted-checks.md` records missing sibling Hemera;
that receipt is historical evidence, not a newly run gate. Merely publishing a
local source-archive pin does not make the production dependency consumable.

Changing only cyber-bao to another source splits the concrete Hash type shared
with these consumers. Examples: iroh-blobs/src/hash.rs:17–20 returns a Hemera
Hash from PreOrderMemOutboard; particle/src/main.rs parses a Hemera Hash for
cyber-bao decode; radio-cli/src/main.rs does the same. A source-wide Cargo
identity must be consistent. A same-version Git, registry and path package are
different Cargo identities even when their bytes happen to match.

`iroh-ffi/Cargo.toml` is a separate workspace containing iroh-js. Its Hemera path
and registry iroh/iroh-blobs dependencies are outside the root-workspace closure;
it declares no local cyber-bao dependency. It remains unchanged. The root
integration package and excluded iroh-js separately request registry Hemera 0.1;
root Cargo.lock resolves 0.1.2 with checksum
`7b69554ac12fa0b19bb85f1d1965b0682ae4c71fa737d3d66d532ba2c8f35e4d`.
Their manifests and distinct dependency identities remain unchanged.

## Why the existing registry release does not preserve the input

The cached published cyber-hemera-0.3.1.crate has SHA-256
`ebcf7ffcd69170adde7e792826d7cececda962ea220b9834c6535bbc71e5a6df`, matching
Kadek's exact registry lock. A fresh extraction, not the mutable registry source
directory, supplied comparison input. Its .cargo_vcs_info.json names 23f3bbcf.
Current d5f0a095 includes new arithmetic/backend/kernel modules, optimized tree
batching, Hasher::new_secret/hash_secret and constant-time secret/keyed mode state.
These are implementation/API changes, even where published hash vectors remain
equal. Substituting the registry version would roll back those current inputs.

`/tmp/radio-bao-hemera-pin-research/published-comparison.json` compares the current
rs manifest and src tree: 24 paths, 13 byte-identical, 11 different or added.
Every path carries both available SHA-256s. An initial Ruby comparison mixed
UTF-8 and binary strings, yielding false inequality for equal non-ASCII bytes;
its inconclusive JSON is retained, and the final comparison explicitly uses
binary bytes. No Cargo command was rerun for that harness correction.

## Git dependency resolution measured

At 2026-10-11T20:03:19Z–20:03:22Z, actual Rustup1.95 Cargo metadata resolved a
standalone research manifest with
`git="https://github.com/cyberia-to/hemera"`, exact revision d5f0a095,
default-features=false and features=["std"]. Exit 0. The empty research target
contains no implementation; this was dependency metadata, not a build/test.

Exact argv/environment/cwd and untouched streams are
`/tmp/radio-bao-hemera-pin-research/git-metadata.{json,stdout,stderr}`; manifest,
empty target and generated lock are in its `probe/`. Cargo's source ID includes
the exact requested and resolved revision. Its checkout's 30 tracked rs package
files were compared byte-for-byte against Git d5f0a095 in
`git-package-source-verification.json`; all matched. Metadata reports only std
enabled for that standalone probe and no active transitive dependency. This is
not the full Radio feature closure. Hemera's optional production dependency is
serde; dev dependencies must not be inferred as downstream production inputs.

An unchanged Radio Git archive plus the exact Hemera archive then resolved with
`cargo metadata --format-version 1 --offline --locked`, default/none/all feature
variants: each exit 0. Temporarily moving only this isolated sibling away yielded
exit101, ending `failed to read .../baseline/hemera/rs/Cargo.toml` / `No such file
or directory (os error 2)`. All seven metadata invocations/14 raw streams are
retained. These are source-delivery observations, not algorithm tests.

The baseline 0.3.1 package has features default+serde+std in all three workspace
variants. An initially empty-lock Git std+serde probe selected serde1.0.229;
retain that diagnostic without treating it as the intended candidate closure.
A distinct probe seeded with Radio's exact Cargo.lock resolved the Git Hemera
while retaining serde1.0.228 and its locked dependencies. `metadata-summary.json`
records the actual baseline IDs/edges and independent Git probes. Full candidate
workspace graph parity remains a post-approval gate; no production manifest has
been replaced to manufacture that observation.

## Proposed source boundary

Use one root workspace Hemera declaration with the immutable Git revision and
default-features=false. Each of the eight inheritors explicitly enables std;
iroh-blobs also keeps serde, and cyber-bao's serde forwarding remains unchanged.
Hemera's pinned default consists only of std; no source cfg(feature="default")
was found in its rs/src. This removes only the default feature marker while
preserving actual current cfg behavior. The later no_std task can independently
change cyber-bao's feature forwarding without remigrating every manifest.

The extended tracked-package scan also checks CARGO_FEATURE_DEFAULT, the entire
rs tree/root workspace manifest, build declarations and build.rs/.cargo paths;
no default-marker consumer or build script was found. Cargo's exact Git package
metadata has no custom-build target. Full scan argv, exits and empty output will
be frozen with the PLAN, rather than inferring the absence from src alone.

The exact Git source determines version 0.3.1; root inheritance replaces relay's
redundant floating 0.3 selector as well as its path. No component version changes.
Git-only delivery is intentional. This task does not make a crates.io release,
change pins in another repository, publish or tag anything.

Other production sources remain pinned by the committed lock: willow-rs at
`12d29767cf3dedfaba7f03e14eaaf4c4cca5b438` and willow-store at
`b1c1bb90aa6c1b732be10c7071d10f0e3c6a195d`; registry checksums and versions
stay fixed. Quinn/nettools path dependencies resolve inside the exact Radio tree.
Gate preparation must confirm this closure with Cargo metadata, not substitute
similarly named registry packages. The only planned lock change is the new Git
source on the existing 0.3.1 package; any additional resolution change is a stop
for explanation, not permission to update dependencies indiscriminately.

## Blast radius and verification boundary

The first cached registry input was soft3 `18fd6b22`; fresh origin inspection
and an exact-object fetch advance this inventory to
`44824e6cf64f5b0b1d7443eea412001e74c5f32e`. It still declares Radio
part_of=soft3, Hemera part_of=nox and Kadek part_of=cyb. No release pin changes
are included: phase1.toml still pins older Radio db1d62e2 and Hemera 23f3bbcf.
This is ordinary source development, not a release candidate or pin-drift fix.

`reverse-consumers.json` inventories committed Cargo manifests in the 52
registry-listed repositories: 50 have readable cached origin-default inputs;
kern is unavailable and the original Nu Git directory is broken. A separate
exact Nu clone at 1e58416e is then included in `reverse-fresh.json`, without
altering or claiming to repair the original. Unrefreshed refs and missing kern
limit any external-consumer absence claim. The fresh follow-up pins soft3,
cybergraph 42fc2512, foculus 4ae1a79b, tade c7d404aa, cyb 4e4711f1 and evy
a194311a to recorded live origins; its full manifests and selected callers are
retained. These are source inspections, not successful product builds.

Neither current soft3 Cargo manifest directly depends on Radio. Its product
crate uses registry Hemera and path cybergraph/foculus; conformance uses path
Hemera and stack siblings. Current cybergraph and foculus also use path Hemera;
foculus's optional transport is upstream registry iroh 0.96, not cyber-radio.
Tade has no Radio/Hemera dependency. Cyb's separate crates/cyb manifest actually
depends on registry cyber-radio 0.1 and registry Hemera 0.3; wire.rs uses Endpoint
and copies Hemera results to [u8;32], with no concrete Radio Hash exchange found.
Evy's evy_radio is its own channel wrapper, without a Radio crate dependency.
Thus no concrete path-Radio plus path-Hemera exchange was found in these
inspected current consumers. Registry membership still requires ring-1 product
and kelvin checks; source inventory does not discharge them.

Public Hash identity nevertheless changes from path to Git. A downstream
consumer that keeps its independent path Hemera declaration cannot pass that
Hash into the newly pinned Radio APIs. This is an intentional source-identity
compatibility boundary, even with identical Rust bytes or a green rustdoc check.
After approval a legacy-path consumer probe must distinguish parent success
from candidate type mismatch; full current consumers must retain their source
declarations for comparison. Any new dependent failure belongs to this change
unless the exact unchanged parent reproduces it; a broad historical red cannot
hide it. No external manifest or registry/FFI dependency is silently migrated.

Current Radio's prior audited gates include broad format/Clippy/docs/policy and
all-feature compilation/runtime failures. Keep the committed PR36 receipt as
history; rerun the appropriate candidate/current-parent commands on this unit's
own exact inputs before assigning its status. Hosted source-delivery progress
does not certify platforms, fleet, kelvin, full product closure or row 4.

Inspection commands: exact `git show <revision>:<path>`; `git grep -n` for
hemera/cyber-bao/path declarations in tracked Cargo.toml files, excluding
nettools/target, audit and .claude; exact Cargo metadata invocation above; binary
package comparisons and source hashes retained in the research directory. The
earlier BAO boundary handoff is `/tmp/kadek-bao-bounded-research-20261011/`, with
its 38-file input manifest and findings. No algorithm/performance result is new.
