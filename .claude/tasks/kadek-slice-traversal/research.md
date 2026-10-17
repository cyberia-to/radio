# Sync slice traversal research

Status: fresh Opus plan APPROVE received; implementation source frozen for code review.
Serves: owner's phase-1 completion · radio verified streaming · kadek foundation
closure row 4 authenticated slice-proof dependency. Parent/discovered-from:
[kadek closure](https://github.com/cyberia-to/kadek/blob/54cf261913849d023184d19e149afa58350c5f35/.claude/plans/foundation-closure.md),
[durable probe](https://github.com/cyberia-to/kadek/tree/16b53f7b85640be5a68a07787815a44ec6559377/audit/2026-10-09-bao-source-repro).
This task removes one dependency defect; row 4 remains partial.

## Inputs and observations

On 2026-10-09, `git fetch origin main` in radio succeeded; `git rev-parse
origin/main` returned `db1d62e2cd1e4b2f309fa19bcc158bd29b44753d`. Created owned
`/Users/master/cyber/radio-kadek-slice-traversal`, branch
`fix/kadek-slice-traversal`, with `git worktree add -b ... <exact revision>`.
The original radio working tree was not edited or used as source/build input.
Read-only source investigation used `git show <revision>:<path>` and `git grep`.
At this preparation point no build, gate, production/test edit, commit, push or PR
had run. Subsequent implementation evidence is recorded below.

The probe used that radio commit and exact registry `cyber-hemera =0.3.1`, from
Hemera source `23f3bbcff910ea6d504ceb505680a539260869da`; registry checksum
`ebcf7ffcd69170adde7e792826d7cececda962ea220b9834c6535bbc71e5a6df`.
Its README pins archive/blob provenance, isolated manifest substitution, lock,
toolchain, commands and stdout. Exit zero reproduces defects; it is not a gate.
No full cyber-bao test result exists in that evidence; none is inferred here.

For a 16384-byte body `(i*31 + i/4096)%256`, log 0, requested chunks 2..4:
independently assembled proof equals extractor output, root equals the explicit
four-leaf Hemera tree, but decode_slice returns Truncated. Left-half and full
controls return exact leaves. Root Hash:
`ed9bec157f55deb7db92a3ae251e2b1e74a729b4bac2baa639b3c3b5dae8579c`.
Proof length 8328; SHA256
`6bb42600c99634ca87c9b407ab2febd3438c3df683f4c27fa27fbd9730c7dd05`.
Observed command: receipt's `cargo run --offline --locked --bin
kadek-bao-source-repro`, with unchanged archived Rust sources. The probe was
also independently repeated from the durable receipt. Three unused PAIR_SIZE
warnings occurred in `io/{encode,outboard,slice}.rs`; they were not suppressed.

## Cause and existing reusable mechanism

`cyber-bao/src/io/slice.rs::decode_slice:130–210` traverses
`tree.pre_order_chunks()`, pushes both children, and pops one expected hash for
both excluded parents and excluded leaves. Excluding the entire left subtree
pops its hash at the parent; its descendants then consume the pending right
hash. The included right parent has no expected hash and returns Truncated.

`tree.rs:630–744` already supplies `pre_order_chunks_filtered(ranges)` and
Parent.left/right visitation flags. Async decode (`io/fsm.rs:165–191`), sync
encode (`io/sync.rs:43–65`) and mixed traversal (`io/mixed.rs:99–130`) push only
visited children, right before left. Sync slice can adopt that same invariant
without changing tree geometry, extractor, error enum or hash calculations.
The filter still materializes a Vec; this is no finite-resource verifier claim.

The three PAIR_SIZE constants/imports are only used by private tests
(`git grep -n 'PAIR_SIZE\|OUTPUT_BYTES' ...`). Moving them into those existing
cfg(test) modules is a small explicit prerequisite for strict library checks.
Other formatting/Clippy/workspace failures have not been measured. Full source
files currently have 410/157/238 lines (slice/encode/outboard, `wc -l`, base above).

## Authority boundary and excluded defects

The decoder contract is verification against the caller's trusted BAO root
`Hash`. Kadek `Particle` is the plain Hemera body digest, implemented by
`kadek-ifac/src/provenance.rs` at 54cf261. Equal byte widths do not equate these
identities; even a canonical `fixed_chunk_root` is a tree root, not automatically
plain `hemera::hash(file)`. Authenticated Particle-to-root binding is separate.

The probe also observed lost ROOT domain in grouped single-block hashing:
8192 bytes at log 4 yield parent_cv(left,right,false), while log 0/fixed_chunk_root
use root=true. Correcting it changes affected BAO root identities, not proven
plain Particle identities. This task preserves both observed root values and
all root-flag/hash semantics; no fallback accepting two roots is introduced.

Static separate defects: provider ExportBaoProgress's 32-byte hashes copied into
64-byte halves; stale pair strides/import/storage checksums elsewhere. Task B
owns exporter repair. Single-block range handling, declared-size/trailing-byte
strictness, malformed extreme geometry, memory/work quotas and resumability are
also excluded. Existing README/docs/bao.md contain stale 64-byte hash/128-byte
pair and broad compatibility/completion claims. Those are recorded discrepancies,
not evidence of conformance or authority to change the root/profile here.

## Rules, gates and blast radius

`git ls-tree` and scoped file inventory found no radio/nested AGENTS.md or
CLAUDE.md, no .beads and no existing .claude artifacts at base. Parent
`~/cyber/AGENTS.md` and `cyberia/dev.md` apply; read dev plus fathership,
engineering, quality, projects, documentation and refinement. Required conduct:
research then frozen plan/different-vendor review; implementation only after
approval; owned worktree; explicit-path staging and conventional commits; no
shared-history rewrite/dirty sibling edits; zero warnings/green tests; report
results under audit with exact revision/command; new source files <=500 lines.
Full audit uses the documented quality passes; upstream approvals/release/tag
restrictions remain. Root subsequently authorized the reviewed implementation;
commit/PR/merge and the final audit receipt remain parent-owned.

`.github/workflows/ci.yml`, `tests.yaml`, `Makefile.toml` are executable upstream
gate definitions: cargo-make format-check; feature checks and nextest workspace
tests for default/no-default/all, doctests, all-feature docs, three Clippy feature
sets, MSRV 1.89, semver action, cargo-deny, platform and network simulation jobs.
Global RUSTFLAGS denies warnings; the docs job locally overrides RUSTDOCFLAGS
with `--cfg docsrs`. Some selectors retain old package names and omit cyber-bao
from targeted semver/feature lists. None has been run by this task; focused
crate results will not substitute for them. v0.1.0 is available as a tag baseline.

`git grep cyber-bao ... -- '**/Cargo.toml'` finds direct local dependents:
iroh-blobs, particle, radio-cli, tests/integration. soft3 origin revision
`94af9de717658b3e912bcfccc85409fd29b23a10`, release/components.toml:250–259 places
radio under soft3, layer 7; kadek under cyb, layer 8. This reaches registry ring 1;
a narrow API-preserving fix does not establish rung acceptance. Final review
must enumerate actual origin dependencies/checks and record any unmet gate.

## Implementation observations staged for the parent-owned audit

Fresh source-only plan review: `/tmp/radio-kadek-slice-traversal-plan-review.txt`,
APPROVE. No soundness or executed-gate result is inferred from review prose.
All following observations use base db1d62e2 plus the exact source patch below.
Original worktrees, hash domains, exporter, manifests and locks remain unchanged.

Staging root: `/tmp/radio-kadek-traversal.Oy2m4r`. `HANDOFF.md` indexes commands,
exits, source identities and limitations; `logs/` retains stdout/stderr and command
JSON, and the checked Nu scripts retain export/probe/gate recipes. Final audit,
commit, PR and fresh code review remain parent-owned. No commit/push/PR was made.

- `bootstrap.nu`: exact historical probe returned 0, stdout matched the committed
  receipt and all three fixture SHA256 checks passed. All 15 archived cyber-bao
  Rust blobs were subsequently checked against base; no dirty sibling input.
- `red.nu`: only the new test over unchanged source; debug and release both exit
  101 at `independently constructed valid proof must decode: Truncated`.
- Final implementation uses the existing filtered traversal; nine literal tests
  include the mixed in/outside five-leaf case and explicitly label the retained
  grouped ROOT discrepancy as observed non-conformance. No final stack/cursor
  assertion or additional traversal/hash mechanism was introduced.
- Required strict all-feature tests exposed unchanged `fsm.rs:287` unused
  `encoded`. Parent authorized only `(root, _encoded)`, preserving the encode
  call and variable lifetime. Debug/release all-feature tests then pass; this
  one-line prerequisite must be explicitly adjudicated in fresh code review.

Scope A copies the exact receipt manifest/lock, preserving upstream lints:
`missing_debug_implementations=warn`, `unexpected_cfgs=warn` with iroh_docsrs and
iroh_loom checked, `clippy::unused-async=warn`. Registry Hemera 0.3.1 has serde.
Tag v0.1.0 resolves f2b1298daa9f635c821d53996c4d1dc4f1042b3d and contains cyber-bao.
Scope B archives complete radio and Hemera 23f3bbc; tracked nettools/target is
excluded. Initial rs-only Hemera export lacked its parent workspace and was
corrected before meaningful checks. Locked fetch supplied four uncached registry
packages; full committed lock stayed byte-identical. Metadata reports 20 local
packages, all inside the isolated full root. Archive builds also emit vergen
warnings because archives are not Git worktrees; no fake Git metadata was supplied.

With RUSTFLAGS=-Dwarnings (and strict RUSTDOCFLAGS for docs), final observations:

| Command/scope | Result |
|---|---|
| A `cargo test -p cyber-bao --test slice_traversal [--release] --offline --locked` | 9 pass in each profile |
| A `cargo test -p cyber-bao --offline --locked` | 67 lib + 9 integration pass; 0 doctests |
| A `cargo test -p cyber-bao --all-features [--release] --offline --locked` | 69 lib + 9 integration pass in each profile; 0 doctests |
| B `cargo test -p cyber-bao --all-features --offline --locked` | 69 lib + 9 integration pass with exact committed Hemera |
| A `cargo check -p cyber-bao --all-targets --no-default-features --offline --locked` | pass |
| A `cargo check -p cyber-bao --lib --all-features --offline --locked` | pass |
| A `cargo doc -p cyber-bao --all-features --no-deps --offline --locked` | pass, strict docs |
| A `rustup run 1.89.0 cargo check -p cyber-bao --all-features --all-targets --offline --locked` | pass, scoped MSRV |
| A `cargo semver-checks check-release -p cyber-bao --baseline-root ../baseline` | 202 checks pass, 58 skip; no semver update required |
| A Clippy default/no-default/all features, all targets, `-- -D warnings` | red; first unchanged mixed.rs:115 clone_on_copy; more unchanged sync/fsm/tree/pre_order diagnostics preserved |
| B `cargo check --workspace --all-features --all-targets --offline --locked` | red; first unchanged iroh/bench/src/iroh.rs:7 unresolved radio; also gossip API mismatch |
| B `cargo test --workspace --lib --bins --tests --offline --locked` | red at same unresolved radio import; also incompatible local/registry PublicKey types in iroh-docs |
| B exact format-check expansion on nightly-2025-11-26 | red; first unrelated iroh-blobs/examples/get-blob.rs formatting drift |
| B cargo make / nextest / deny | commands unavailable (exit 101), not green |

Only the new test file was formatted (308 lines); its repository-option format
check and git diff --check pass. Full-workspace no-default/all test variants,
MSRV, pinned CI docs nightly, cross/Android/wasm/netsim and remote workflows were
not executed; the broad native build failures preclude a green upstream verdict.
No ring/release/row-4 completion is claimed. Read-only exact-base search found no
Truncated/decode_slice expectation in iroh-blobs/particle/radio-cli/tests/integration.
The duplicate hash_block_for_verify helper remains an unmodified follow-up.

Frozen `source.patch` SHA256:
`5a66daaadff2c20afb9a902f15f9141c50b92552b3615403a6329cc9c01cff62`.
`SOURCE-FREEZE.json` SHA256:
`5726e6ece1488a7635a6d0a3d32444e8858437ca1aec943b5da5cb3bb03c3065`.
It lists the four touched Rust files and new integration test with exact blob IDs,
SHA256 and line counts; both isolated candidate copies match those final bytes.
