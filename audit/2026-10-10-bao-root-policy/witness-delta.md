# ROOT-policy witness count annotation

Source-only audit clarification after approved CODE review; no source edits or Cargo rerun.

The exact-parent failure-first witness ran six default-feature integration tests: one passed and five failed. A seventh default-feature control, `non_root_partial_and_odd_groups_verify_with_absolute_counters`, was added before the source-v2 candidate gates. It tests (24576, log2), (28672, log2), and (65537, log4), requests only the right-side groups, and checks the independent primary `hemera::tree::fixed_chunk_root`, decoded absolute offset/data, and sync-encoded wire equality. These lengths require multiple stored groups; they exercise non-ROOT partial/odd reductions at nonzero absolute counters, outside the affected single-group ROOT interval. This was additional unchanged-behavior control coverage, not an additional red-first defect witness. It was not executed on the parent; no measured parent-pass claim is made.

The only other source delta is equivalent assertion spelling in `literal_proof_accepts_canonical_root`: exact equality to a one-range array became an exact cardinality assertion followed by equality of its sole range, avoiding Clippy's range-array lint. It changes no test count. The FSM test already existed in the witness source behind `tokio_fsm`; final all-features has eight tests (seven default plus FSM).

Source hashes:
- Witness: `329acf7273dc79086cbf20922aa110c755fe557b14f5cb49796cad045fc26e03`; retained source `/tmp/radio-bao-root-policy.rPXzYh/witness/radio/cyber-bao/tests/root_policy.rs`, bound by `/tmp/radio-bao-root-policy.rPXzYh/witness-test-overlay.json`.
- Candidate source-v2: `0381ed3a33c7647350c9ee71700bb394c057ddd4e74d24a03b7b2e7974e48301`, in `/tmp/kadek-bao-root-policy-source-v2.json` (added control, original range-array assertion).
- Final v3/v4: `779a5b92d158c5b370d0c01e1692cf3585e0c39f31fc730794f77f115d9a84f3`; `/Users/master/cyber/radio-kadek-root-policy/cyber-bao/tests/root_policy.rs`. v3 changed assertion spelling; v4 changed only one blank line in another test helper.
- Exact diff: `/tmp/kadek-bao-root-policy-witness-delta.diff` SHA256 `99a520663d3dd20f6b1c459a2e3baae3e3b9326d78362f93145605854dc235c3`.

Existing raw command/exit receipts (stdout/stderr hashes reverified against each JSON):
- `/tmp/radio-bao-root-policy.rPXzYh/logs/witness-root-policy-default.json` SHA256 `f79780a67ea87931631b1839588cef5e6e18b04e02c17b85835531813d35ac0d`; exit 101; test result: FAILED. 1 passed; 5 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.04s
- `/tmp/radio-bao-root-policy.rPXzYh/logs/candidate-root-policy-default.json` SHA256 `2f555d7eee9e7232e866ab77f89cb878df8c846c68f917e0f1c4688dd643aff4`; exit 0; test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.93s
- `/tmp/radio-bao-root-policy.rPXzYh/logs/candidate-v3-bao-all.json` SHA256 `4eacda7dbf46705f75af38cd69ab8aa7be82626429133f95c140fe4c09a1c84f`; exit 0; test result: ok. 71 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.43s; test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.45s; test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.17s; test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

Default command: pinned Rust 1.95.0 `cargo test -p cyber-bao --test root_policy --locked --offline`; all-features command: same compiler `cargo test -p cyber-bao --all-features --locked --offline`. Full executable paths, cwd, flags, and timestamps are retained in the receipts.

Verification commands: `diff -u` on the two source paths above; SHA256 comparison of both sources and receipt-declared stdout/stderr; inspection of source-v2 freeze and v3/v4 overlay records. The annotation resolves count provenance without representing the seven-test candidate run as a byte-identical replay of the six-test failure-first witness.
