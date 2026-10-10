# Execution notes

Fresh PLAN v2 APPROVE received; source scope remains the approved two store writers.
The original immutable PR32 right-proof.bin will be copied byte-identically into
iroh-blobs/src/store/mem/parent_pairs/right-proof.bin for package-safe include_bytes!.
This preserves the approved exact golden bytes, avoids a new hash dependency and
does not change the existing exporter test/audit packaging. Both locations must
match SHA256108022aa95ee61a1058d6d4bb53979a95bc46de114b036fcc6620fbd65648a51.

Pinned n0-future0.3.2 src/time.rs:6–9 reexports tokio::time::timeout for native
targets; all asynchronous witnesses will use its finite30s timeout.
Exact-parent fixture controls and public success expectations remain ordinary
tests. Only synchronous print96 rejection uses exact-assert should_panic.

Expected paired broad-test improvement: reader_partial_memory imports parent
proofs and may change red→green. Compare actual current-parent/candidate test
names and errors; do not borrow prior27-failure counts as current observations.
No claim about Hash::EMPTY, partial checkpoint checksums/recovery, actor lifecycle,
bounded proof admission or particle/root association follows from this repair.
