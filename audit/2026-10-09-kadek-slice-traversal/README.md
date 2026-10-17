# Sync BAO slice traversal receipt

Recorded 2026-10-09 for kadek foundation row 4's upstream proof dependency.
The narrow source fix has approved plan/code reviews and passing scoped tests.
Broader gates remain red. No release, row-4 closure, bounded-verifier conformance
or equivalence between a BAO root Hash and a file's plain Hemera Particle is claimed.

## Inputs and change

- Radio base: `db1d62e2cd1e4b2f309fa19bcc158bd29b44753d`.
- Reviewed implementation: `590e69ea0eebcea4c21320a88eed214dc5459de1` (`wip:` commit
  explicitly records baseline Clippy and full-workspace failures).
- The five-file `git diff <base> <implementation> -- cyber-bao` has SHA256
  `5a66daaadff2c20afb9a902f15f9141c50b92552b3615403a6329cc9c01cff62`.
  The implementation Git pin is canonical; no redundant patch is included.
- [SOURCE-FREEZE.json](SOURCE-FREEZE.json), SHA256
  `5726e6ece1488a7635a6d0a3d32444e8858437ca1aec943b5da5cb3bb03c3065`, pins each
  touched source/test file by Git blob, SHA256 and line count.
- Registry `cyber-hemera =0.3.1`, checksum
  `ebcf7ffcd69170adde7e792826d7cececda962ea220b9834c6535bbc71e5a6df`.
  Source scope uses Hemera `23f3bbcff910ea6d504ceb505680a539260869da`.
- [gate-index.json](gate-index.json) records commands, exits, input scopes, tool
  versions, review verdicts/hashes, baseline classification and replay validation.

The old multiblock decoder consumed pending expected hashes while traversing
excluded descendants. The fix reuses the existing filtered walker and pushes only
visited children, right before left. Extractor bytes, hash domains, root identities,
public API, manifests and locks are unchanged. Three test-only PAIR_SIZE declarations
moved into existing test modules. An observed strict all-feature warning justified
one additional `encoded` → `_encoded` test binding rename, preserving the call and
value lifetime; fresh code review explicitly approved it.

Both fresh plan and code reviews returned APPROVE. They were source-only reviews,
not executed gates or soundness proofs. Optional generic property tests and hash
helper consolidation remain follow-ups; no extra walker or end-stack assertion
was introduced.

## Independent red-first evidence

[probe.rs](probe.rs), [expected output](expected-probe.stdout) and
[fixture digests](FIXTURE-SHA256SUMS) come unchanged from committed kadek
`16b53f7b85640be5a68a07787815a44ec6559377`,
`audit/2026-10-09-bao-source-repro/`. Running
`cargo run --offline --locked --bin kadek-bao-source-repro` against unchanged base
exited 0, matched stdout and all three fixture digests. That probe's successful
exit reproduces defects; it is not a product gate.

For body byte `(i*31+i/4096)%256`, four 4096-byte leaves and query 2..4, the test
constructs leaves with explicit counters and parents/root with explicit root flags
using public Hemera operations. Its literal wire is
`LE64(16384) || L || R || h2 || h3 || body[8192..]`, 8328 bytes; extractor equality
is a secondary check. Trusted tree root is
`ed9bec157f55deb7db92a3ae251e2b1e74a729b4bac2baa639b3c3b5dae8579c`;
proof SHA256 is `6bb42600c99634ca87c9b407ab2febd3438c3df683f4c27fa27fbd9730c7dd05`.

Only the new regression was copied onto unchanged production. The command
`cargo test -p cyber-bao --test slice_traversal literal_right_subtree_is_authenticated
[--release] --offline --locked` exited 101 in both profiles at the valid-proof
assertion with Truncated. After repair the output is exactly the 4096-byte leaves
at offsets 8192 and 12288. Nine tests additionally cover controls, nested/sparse/
grouped/partial/mixed-outside queries, corruption, truncation and retained observed
grouped ROOT non-conformance. This is not an independent cryptographic audit of Hemera.

## Isolation and gate outcomes

All builds used fresh Git archives; original dirty trees and tracked target files
were never build inputs. Fifteen archived baseline Rust blobs matched origin.
Scope A changes only the exported Hemera path to registry `=0.3.1`; its included
manifest preserves upstream lints and its included lock pins resolution. Scope B
exports complete radio and exact-source Hemera, excluding tracked nettools/target,
with radio's committed lock unchanged. Its twenty local package paths all resolve
inside the isolated root. Archive builds report vergen Git-metadata warnings;
no fake Git state or warning suppression was supplied.

The following results use the reviewed bytes now committed at 590e69ea. Rust
checks use `RUSTFLAGS=-Dwarnings`, except historical/red-first probes; docs also
use `RUSTDOCFLAGS=-Dwarnings`. Exact commands and diagnostics are in the gate index.

| Check | Observed result |
|---|---|
| A new regression target, debug/release | 9 pass in each profile |
| A default tests | 67 lib + 9 integration pass; 0 doctests |
| A all-feature tests, debug/release | 69 lib + 9 integration pass in each; 0 doctests |
| B exact-source all-feature cyber-bao tests | 69 lib + 9 integration pass |
| A no-default/all-target check, all-feature lib check, strict docs | pass |
| A Rust 1.89 all-feature/all-target check | pass; scoped MSRV only |
| A semver against v0.1.0's identical crate | 202 pass, 58 skip; no semver update required |
| A Clippy default/no-default/all, all targets | exit 101; 16 unique remaining all-feature diagnostics |
| Pristine baseline all-feature/all-target Clippy | exit 101; same 16 plus four warnings fixed by this patch |
| B workspace all-feature/all-target check | exit 101; unrelated bench import and gossip test API failures |
| B workspace default lib/bin/test run | exit 101; bench import and local/registry Endpoint/PublicKey mismatches |
| B make/nextest/deny commands | exit 101; tools unavailable |
| B expanded format task | exit 1; pre-existing formatting drift |

The [pristine Clippy log](diagnostics/clippy-pristine-baseline.stderr) and
[patched log](diagnostics/clippy-all-v2.stderr) establish the remaining baseline
diagnostics. First is mixed.rs:115 clone_on_copy; none names the modified traversal
or new regression. [Full-check diagnostics](diagnostics/full-check-v2.stderr)
show the independent package errors. Their source/manifests match base blobs;
a pristine full workspace was not rebuilt. No transitive repair was folded in.
Tag v0.1.0 is f2b1298daa9f635c821d53996c4d1dc4f1042b3d; its cyber-bao tree and the
base's are identical: `dce9cffd78068afd50daf408aa2f9be9b33f81e1`.

Unexecuted: full-workspace no-default/all test variants, full-workspace MSRV and
strict docs on CI's pinned nightly and cross/Android/netsim execution.
Scoped success does not substitute for these upstream gates.

## Remote CI snapshot

PR #31 head `9cd70949984088557f66aa63d6db787d17959367`,
[CI run 38000324106](https://github.com/cyberia-to/radio/actions/runs/38000324106):
`gh api repos/cyberia-to/radio/actions/runs/38000324106/jobs --paginate` and
`gh api repos/cyberia-to/radio/actions/jobs/<id>/logs` were read on 2026-10-09.
Clippy, format, semver, docs, MSRV, deny and wasm jobs fail while loading Cargo
metadata: the workflow has no sibling Hemera checkout (`../hemera/rs/Cargo.toml`).
The separate Docs Preview run fails at the same step. None establishes a compiler,
format, semver, policy or wasm-test result for this source revision. Job IDs and
excerpts are retained in the gate index and [remote diagnostics](diagnostics/remote-ci.txt).

Codespell exits 65 with 34 findings across 15 unchanged paths; `git diff --exit-code
<base> <head> -- <reported paths> .github/workflows` is empty. These are separate
from the local baseline Clippy/source failures. Native test, cross and netsim jobs
were still queued when observed; a superseded push run was cancelled. Queued and
cancelled jobs are not executed gates. This snapshot preserves remote reds without
substituting scoped local success for the upstream workspace gates.

## Replay

```sh
nu reproduce.nu \
  --implementation-revision 590e69ea0eebcea4c21320a88eed214dc5459de1 \
  --radio-repo ~/cyber/radio --hemera-repo ~/cyber/hemera \
  --full-workspace --fetch
```

[reproduce.nu](reproduce.nu) exports only committed inputs into fresh /tmp
workspaces, verifies source blobs, reproduces the historical probe/red-first test,
then records all scoped and optional broader native checks. `--fetch` retrieves
locked dependencies; omit it with complete caches. It never regenerates locks,
resolves dirty sibling inputs, edits repositories or makes commits. Named missing
tools/toolchains produce recorded failures.

Expected negative probes retain exit 101 and are not called passes. Every product
gate preserves its real exit/stdout/stderr; the script finishes nonzero if any
product gate failed. Current Clippy therefore makes a faithful replay exit 1.
Unexpected setup/red-first failures stop immediately with evidence retained.
The scoped recipe was executed against 590e69ea and behaved this way; its optional
full branch reuses the separately executed archive/gate sequence but was not rerun
as a complete new recipe. Generated fixtures/binaries/targets remain only in /tmp.

Provider 32/64-byte copying, Particle-to-root binding, grouped ROOT profile,
extreme geometry/quotas and single-block/trailing-byte policies remain separate.
