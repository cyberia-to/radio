# Root review

Serves Kadek foundation row 4's authenticated transport prerequisite. Scope is
the in-memory parent-pair representation used by MemStore and FsStore's temporary
memory path. Phase, bounded-proof, persistence-recovery and release closure remain
open.

## Reviewed inputs and result

Radio base `0d11468503c052aa5dcefb0dabc4602bd8efdc60`, Hemera
`23f3bbcff910ea6d504ceb505680a539260869da`; final six-path source manifest
`d7c6cc1560eeeadc1b0c880cca79a3e2b09a2379489bac37706b0603db7069ca`.
The initial source freeze and named-formatter correction remain in this audit.
The correction moved one test import; production and fixture bytes stayed equal.

Root read the production diff and complete new test modules, reran the CODE-pack
verifier, and independently checked the committed source exports and raw command
streams. The private derived width and encoder agree with both existing readers.
The three-group oracle exercises a nonzero parent ordinal; complete and selected
wire comparisons bind its stride. FsStore's equality-threshold test reaches the
temporary-memory writer and verifies complete data after shutdown and reopen.
The failure-first overlay leaves production unchanged and fails on both original
writers. No code blocker found.

Fresh Claude Opus PLAN v2 and CODE reviews returned APPROVE. CODE ran with
`--no-session-persistence --strict-mcp-config --mcp-config '{"mcpServers":{}}'
--tools '' --max-turns 2`, using the full frozen bundle. Exact pack/index and
verdict digests are in `review-identities.json`; original verdicts are retained
in the receipt capsule. No four-vendor convergence is claimed.

The CODE reviewer incorrectly wrote that the ten selected tests plus FS smoke
and observation all passed serially on both versions. Raw receipts establish:
the ten selected tests passed on both; FS smoke failed on both with the existing
empty-input error; observation failed on the parent, timed out at 30.010s on the
candidate, then passed at 31.851s in the separate one-shot 60s diagnostic. The
named 30-second result stays red. No near-30-second CPU or stack sample was
obtained in that diagnostic. See `timeout-diagnostic.md` for exact commands and
timings. This correction supersedes only the reviewer's result summary.

## Verification limits

Final-byte focused tests passed with all features (11), without default features
(10), and release (11). The default-feature run passed 11 before the test-import
reorder; it was not repeated afterwards. Exact-parent witnesses produced 2 passes
and 9 failures in both profiles. `code-gates.md` in the capsule records commands,
toolchains, first errors and outputs; these counts come from those commands on
the pinned base plus the recorded overlay.

Broad compilation, lint, format, dependency-policy, nightly documentation and
native nextest gates remain red. Owning Clippy stops in dependencies before all
new tests: there is no full lint certificate. Initial concurrent nextest outcomes
and later serial diagnostics are distinct results. API checks against the exact
parent and tag passed, using the tool's recorded scratch resolution; they do not
prove a historical release closure or behavioral compatibility.

Root's source verifier initially assumed every exported file equalled a regular
Git blob. The committed `iroh-ffi/kotlin/.gitattributes` explicitly exports BAT
files with CRLF, and license entries include symlinks. The corrected verifier
checks that exact attribute conversion and link targets, then verifies 1,023
Radio and 88 Hemera source-export paths, six candidate paths and 202 command
records with 404 raw streams. Tracked `nettools/target` is explicitly excluded.
These were verifier assumptions, not product-test failures. The script and its
JSON result accompany this file.

The touched legacy `mem.rs` remains over the 500-line guideline; changes there
are confined to the pair representation and test-module declaration. New test
modules stay below that limit. Source changes introduce no public API, manifest,
version, tag, persistent-format or native provider change.

## Merge accounting

This source repair uses the owner's existing instruction to review, fix and
merge. Required red gates require a `wip:` commit with an actual first error and
a `decision` PR label; no repository-green or release claim follows. Remaining
work includes canonical empty-root identity, partial-checkpoint checksum width,
bounded proof work/allocation and authenticated body/root association.
