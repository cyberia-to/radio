# Bounded BAO group reducer — execution

Serves Kadek phase-1 foundation row 4 through Radio/soft3. Parent is
`dacd030c9d6301b316a96b5bc6e4ea1e1cec79f1`; Hemera remains pinned to
`d5f0a09539360934fb32db9b2e15a91995607db6`. This calculates hashes only.
No authenticated particle/root association, proof parser, range owner, phase,
rung, or release closure is claimed.

The frozen PLAN received fresh Grok APPROVE at 2026-10-11T22:15:45Z, with no
blockers. Raw review SHA256 is
`63c4a0496c9a0893fdc5ebbb7c62a4619db9550af14a26f7e1e52744ff12add3`.
Reviewed PLAN bytes remain unchanged. Advice incorporated: intermediate None
and !is_complete are explicit; the allocation witness is std-gated; the isolated
embedded graph establishes no_std separately from host allocation observation.
Ordinary Rust tree/traversal.rs module layout compiles without a path attribute.
InputTooLarge is structurally guarded but cannot be exercised by a real slice on
this host; no fake oversized-slice runtime test exists.

## Frozen witnesses and initial parent

Execution evidence lives in `/tmp/radio-bao-bounded-reducer-execution/`, with
exact argv, matched Rust tools, environment, timestamps, before/after source
identity, exit/signal, and two raw streams per record. `verify.rb` reconstructs
retained streams, runner bytes and full source snapshots. Independent replay may
set RADIO_BAO_REDUCER_EXEC_OUTPUT to avoid modifying the original receipt.

`parent-freeze.json` was written before any production change. Three witness
files are retained under frozen-tests/: public symbolic/concrete cases, allocation
observation, and the private u64 geometry table. The actual dacd parent has:

- Records 01/02: new public tests fail to compile in debug/release with E0432,
  missing cyber_bao::group. The std-gated allocation file also warns that the
  parent's feature set has no std feature. These are compile failures, not
  runtime-red assertions.
- Records 03–05: a separate isolated consumer uses only the already-existing
  backend API. Its parent thumbv7em-none-eabi check fails with E0463 for std;
  its complete feature graph and 36-package generated lock are retained.
- Records 06/07: unchanged parent default tests pass, 85 tests in each mode.
  The historical pin's 88 count belongs to its all-feature run, not these runs.

## Implementation and finite evidence

GroupHasher keeps 53 optional hashes, borrows the backend/input, validates all
absolute counters before hashing, and does exactly one kernel per pending step.
The hash is returned on the completing step. No placeholder, Clone call, heap
storage, input-dependent scan or hidden kernel is used by the reducer. Arbitrary
backend code/hash destructors remain outside its cost/allocation bound.

The approved feature split preserves default std APIs. Removing eager I/O/ranges
from no-default is deliberate and has a major compatibility floor. Legacy
hash_group and geometry arithmetic stay unchanged. The extracted traversal and
old tree test bodies are checked against actual parent bytes after rustfmt;
the two old integration test bodies differ only by their std crate gate.

Final owning records 23b pass in debug and release: 92 default tests, 95 with all
features, and 21 without defaults. The five public tests contain the 60 literal
shape/counter/root cases, exact caller-pause/total cases, MAX counter errors and
fixed roots. The geometry unit uses exact u64 integer bounds rather than huge
inputs. The allocation witness covers construction, all steps, completed polls
and drop of the real Poseidon2 machine with a positive control. Shared Hemera
kernels in concrete oracle comparisons are disclosed; this is not independent
cryptographic verification.

Records 14/15 initially refuse the obsolete external parent lock under --locked.
Record 14b regenerates only that isolated consumer lock offline, reducing its
resolved closure to two dependencies. Records 14c/15b then pass: isolated thumb
build and normal graph are consumer → cyber-bao → pinned cyber-hemera, with no
std feature. Hemera's own alloc import remains; no no-alloc dependency claim.
Workspace Cargo.lock is unchanged.

The first owning Clippy run (19) found one new manual_is_multiple_of suggestion.
Only the geometry expression changed to the MSRV-supported integer method;
all six owning configurations were rerun. Final no-default strict Clippy (23d)
and strict docs (23e/23f) pass. All-feature strict Clippy (23c) retains exactly
11 existing findings: nine in I/O and two in the mechanically moved legacy
traversal, paired with actual parent record 20. No off-scope lint
repair or blanket warning suppression was made. Records 16–18 check each std,
serde and tokio_fsm feature independently.

Mechanical verifier record 23g accidentally invoked cargo ruby and exited 101;
this is a harness diagnostic. Corrected 23h invokes Ruby directly and passes,
reconstructing both extracted files and the unchanged old integration bodies.
This failed attempt is retained, not counted as a source failure or pass.

## Remaining gates and review

The runtime comparisons and focused repeat are complete below. Existing broader
reds remain visible and are paired against
the actual parent where relevant. Current CODE review is pending; root owns
final review, decision, explicit staging, ordinary commit and PR merge. No
version, tag, publication or release action is authorized by this unit.

## Gate continuation on 2026-10-12

Timestamps retain their actual command epochs: the initial matrix ran on October
11; API and remaining workflow checks resumed on October 12 with the same
693-file selected source digest
`398012be57ffe2facb284f541ea54ce7905d56ee5347fb3b82af1ba5d61faf12`.
This inventory covers selected Rust/manifests/locks, not every repository asset;
workflow bodies are separately pinned in the primary source packet.

Workspace doctests and Rust 1.89 workspace/all-targets pass on both candidate and
actual parent. All three strict workspace Clippy variants remain paired red:
default/none stop at the existing sort_by_key finding; all features stop at the
11 existing BAO findings. Initial nextest/make/deny invocations did not locate
the task-local tools and are preparation failures, followed by explicit pinned
`/tmp/radio-gate-tools/bin` runs.

Fresh compiler-nonstrict nightly supplements 33/34 both fail with rustdoc’s
“failed to read column from disk … invalid type: null” error. This is a paired
observation, not a proven cache cause. The exact CI environment also sets
RUSTFLAGS=-Dwarnings while overriding RUSTDOCFLAGS; separate fresh 33b targets
are used for that required gate. Output-name collision warnings remain visible.
The exact-environment 33b pair also exits 101 with the same rustdoc error;
candidate stops in cyber-radio/base and parent in cyber-bao. This establishes
paired failure, not a causal diagnosis.

API archive preparation 40 failed before comparison because git archive exported
CRLF in historical iroh-ffi/kotlin/gradlew.bat while its Git blob uses LF. The
original archive remains unchanged. A separate canonical blob materialization
verifies 4,489 file/symlink entries at Radio v0.1.0 and pinned Hemera d5f. This
uses current pinned Hemera for the historical path, not a historical release
closure. Default API records pass 202 checks / 58 skips against both baselines.
Initial no-default invocations used an unsupported Cargo-style flag (exit 2);
corrected fresh-target --only-explicit-features runs each exit 100 with 6 major
check categories failing (covering many removed items), confirming the reviewed
std-surface removals and major floor.
No API success is inferred from rejected CLI invocations.

Obsolete owned target cleanup is inventory-bound in record 44; source snapshots,
raw records, API baselines and proofs remain. No generated targets enter the audit.
Concurrent parent test compilation later reached 21,769,040 KiB of targets,
crossing the 20 GiB cap before observation. Record 44c immediately removes only
completed nightly/API-output/release directories (2,347,597,824 bytes), leaving
19,476,464 KiB. Record 44b's mistaken cargo-ruby invocation is a retained harness
diagnostic; it performed no cleanup. API Git baselines remain unchanged.
The separate bounded traversal follow-up owns existing eager geometry and its
arithmetic defects; this reducer never calls BaoTree/BlockSize/TreeNode arithmetic.

## Final workflow observations

All entries bind actual parent dacd or selected candidate source 398012be through
their command records; labels below refer to execution/logs in the portable audit.

| Records | Observed result |
| --- | --- |
| 24 | Five direct-owner all-target checks pass; non-strict supplement. |
| 25b | Default nextest: 554 run, 518 pass, 14 fail, 22 timeout, 9 skipped. |
| 26b | No-default nextest: 554 run, 518 pass, 13 fail, 23 timeout, 9 skipped. |
| 27b/28b | Both all-feature nextest builds stop at existing iroh-gossip E0599: Result has no add method. |
| 29/30, 31/32 | Paired workspace all-feature doctests and strict Rust 1.89 all-target checks pass. |
| 33b | Exact-environment private nightly docs fail on both sources; warnings remain visible. |
| 35–37 | All three strict workspace Clippy variants remain paired red. |
| 38b/39b | Paired workspace format exits 105; deny exits 13 (advisories, licenses and sources fail; bans pass). |
| 41/41b | Four default selectors pass both non-strict and corrected strict checks; these are separate records. |
| 42 | Owning source formatting passes. |
| 43 | Scoped Clippy supplement remains red on four pre-existing findings; it does not establish a std-test lint pass. |

The inherited selectors iroh/iroh-relay resolve registry packages v0.96.1,
not workspace cyber-radio/cyber-radio-relay v0.1.0. Their checks cannot replace
current-owner coverage. Strict workspace nextest builds and MSRV separately
include the actual workspace owners. No full platform/minimal-version/netsim,
product, rung, specification/Kelvin or release closure is inferred.

Parent default runtime record 45 selects every failed candidate binary/test
tuple: 36 run, 1 pass, 13 fail and 22 timeout, with 520 skipped. The integration
test simple_endpoint_id_based_connection_transfer differs: candidate default
fails with DNS TXT resolution/ConnectError, parent passes; candidate no-default
also passes. The 35 other default statuses match. The no-default candidate adds
a connection_pool_idle timeout. These are observations, not a causal diagnosis.
Parent no-default record 45 runs all 36 selected cases: 3 pass, 13 fail and
20 time out, with 520 skipped. Candidate timeouts in connection_pool_idle,
gossip_net_smoke and subscription_cleanup pass on parent; the other 33 statuses
match. runtime-comparison.json preserves every actual binary/test tuple and all
differing outcomes, without treating parent passes as inherited failures.

Records 47 show the default workspace normal/build/dev feature union differs
only by cyber-bao's new std flag. Six DNS/endpoint/integration/manifests match
exact parent Git bytes. The initial comparison wrapper tripped on UTF-8 versus
binary String encoding; its original script is retained, but that tool-console
failure has no standalone raw receipt. Corrected byte comparison 47b passes
without rerunning either graph. The test itself documents deployed DNS/relay
dependencies; their availability is not inferred from source equality.

All-feature compilation again crossed the target cap; records 49/49b inventory
and remove only completed candidate executables/cache before subsequent checks.
Raw evidence and API source baselines remain. The focused repeat runs serially,
with completed parent cache removed before rebuilding candidate binaries.
Record 48 repeats only the differing default integration test: parent and
candidate both pass (one test each; 555 and 562 skipped respectively). The
original candidate failure remains evidence; the repeated pass establishes
variation, without identifying its cause. The three differing no-default
timeouts remain open observations, with no additional broad rerun.

Record 51 inventories and removes the remaining completed compiled targets.
Source/API baselines and all raw evidence remain. No source changed after the
final owning matrix; the CODE packet binds the same 693 selected inputs. All
preparation failures and observed broader red gates remain part of this audit.
