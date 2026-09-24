# CLI cutover to shared file storage

Implementation: Radio `db8cf0e5ac3dc49a84ace1450f58af0c2188f894` (full revision and dependency closure in
[sources.json](sources.json)), with Cybergraph `56680f589727e52bb5803e470b0fb206f0fe550b`.
[Checks](checks.json) record exact commands, revisions and output hashes.
[Legacy inventory](../extraction-2026-09-24.md) remains the removal checklist.

## Result

The real `radio` executable now imports, lists, serves, downloads and exports
through Cybergraph/BBG. `MemStore` and `BlobsProtocol` were removed from its
implementation and `iroh-blobs` from its dependency manifest. The executable's
resolved production closure contains BBG and the new source/sink adapter, with
no old blob/docs/Willow storage package. Both software backend profiles work.

Names now expose set/resolve/rename/remove/list/history, historical selection,
conditional writes and retry. Existing byte identities survive rename. Hash
sum and verify now agree with file import; legacy BAO inspection remains explicit.

| Exercise | Command (Radio working directory) | Observed result |
|---|---|---|
| Actual CLI subprocesses | `cargo test -p radio-cli --release --tests --locked --offline` | All 6 integration test entries passed; file and name scenarios run on both profiles |
| Descriptor/range framing | `cargo test -p cyber-radio --release --test file_stream --locked --offline` | All 5 entries passed, including empty-file lookup, auth, wrong identity and malformed frames |
| Gossip regression | `cargo test -p iroh-gossip --release --lib gossip_net_smoke --locked --offline` | Selected test passed |
| Retained legacy diagnostics | `cargo test -p cyber-bao --lib --locked --offline` | All 67 existing entries passed after scoping fixture-only constants/imports to tests |
| CLI storage boundary | `python3 scripts/check-cli-storage.py` | Shared owner present; old stores absent from CLI production closure; remaining workspace packages reported |
| Lint | Commands in [checks.json](checks.json) | Strict CLI/all-target and transport checks passed without warnings |

The subprocess fixtures import empty and binary input, reopen between invocations,
list each particle once, export exact bytes, and reject overwriting an output.
Recognized old Radio directories are refused before BBG opens; the fixture
asserts their original bytes and directory entries remain unchanged.
Live transfer runs SSD→HDD and HDD→SSD, stops the server process and reopens both
owners offline. A denied peer receives no file; an explicitly allowed peer
retrieves the same private fixture. Names preserve old lookup/list states,
reject stale writes and recover identical requests after later commits.

The tests use explicit loopback addresses. An initial fixture selected an
advertised VPN-interface address and timed out; choosing loopback made the local
transport experiment deterministic. This is not evidence of external-network
reachability. Both backend profiles ran on the same local SSD, not a physical
HDD. The existing interrupted-transfer test was also rerun through the adapter;
its receipt is [[cybergraph/audit/storage/catalog-2026-09-24/README]].

## Remaining milestone

Old blobs/docs/Willow stores still exist in the Radio repository; dormant FFI
also contains registry-based stores. The CLI cutover is complete locally;
full extraction requires metadata sync parity, retained aliases and reclamation,
legacy data import and physical package removal. Node/Cyb assembly is a separate
consumer integration. Names/history here are trusted local publication, without
signed remote patches, channels or merge semantics. S1 still owns structural
identity and authenticated ranges. No complete storage acceptance row or release
was promoted by these checks.
