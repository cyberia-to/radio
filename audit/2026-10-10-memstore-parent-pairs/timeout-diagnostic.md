# Focused timeout diagnosis

Radio exact parent0d11468503c052aa5dcefb0dabc4602bd8efdc60; candidate final freeze d7c6cc1560eeeadc1b0c880cca79a3e2b09a2379489bac37706b0603db7069ca. Production bytes match the initial candidate; only one test import moved.
Original bounded native nextest: parent113 run,82 pass,27 fail,4 timeout,2 skip; candidate124 run,83 pass,25 fail,16 timeout,2 skip. Both exited100. Status changes:10 PASS→TIMEOUT,2 FAIL→TIMEOUT,11 new PASS;25 common FAIL,4 common TIMEOUT,72 common PASS. Original receipts are retained unchanged.
Focused commands use the same Rust1.95.0/source closure, four build jobs, nextest0.9.80, --test-threads1 --profile default with committed slow-timeout period10s/terminate-after3. The -E expression selects exactly the ten names below; full argv/env and before/after clock,disk,vm_stat,load,process observations are in logs/{parent,candidate}-focused-timeouts-t1-v2.*. No timeout extension or entire-suite rerun.

| Selected existing test | Parent serial | Candidate serial |
|---|---:|---:|
| api::downloader::tests::downloader_get_all | PASS 26.796s | PASS 27.702s |
| api::downloader::tests::downloader_get_smoke | PASS 27.251s | PASS 26.933s |
| store::fs::import::tests::smoke | PASS 28.706s | PASS 29.098s |
| store::fs::tests::test_export_path | PASS 14.505s | PASS 14.721s |
| store::fs::tests::test_import_byte_stream | PASS 21.538s | PASS 22.047s |
| store::fs::tests::test_import_bytes_persistence_full | PASS 22.095s | PASS 22.213s |
| store::fs::tests::test_import_bytes_simple | PASS 21.876s | PASS 22.012s |
| store::fs::tests::test_import_path | PASS 21.910s | PASS 21.992s |
| util::connection_pool::tests::connection_pool_idle | PASS 6.872s | PASS 6.925s |
| util::connection_pool::tests::connection_pool_smoke | PASS 19.526s | PASS 9.281s |

Both focused commands exited0: parent10/10 pass in211.077s (9 slow), candidate10/10 in202.925s (8 slow). Selected-test CPU activity was sampled in parent-focused-mid/candidate-focused-mid receipts. Before these runs disk snapshots showed48GiB/45GiB free and load averages2.80/2.61 (1-minute). Initial broad-run machine load was not captured, so no causal attribution to contention, disk or networking is established.
These focused results do not reproduce a functional hang in the selected cases. The29.098s candidate FS import is close to the unchanged30s bound. Original concurrent failures remain red; neither uniform performance nor entire-suite parity is claimed.

The two other transitions are distinct: parent fs::tests::smoke eventually reports invalid size for hash after large imports; parent tests::two_nodes_observe_mem hits the repaired32→64 mem.rs copy panic and Sender closed. Focused serial outcomes follow when recorded:

- parent store::fs::tests::smoke: FAIL 22.709s.
- parent tests::two_nodes_observe_mem: FAIL 13.810s.
- candidate store::fs::tests::smoke: FAIL 21.957s.
- candidate tests::two_nodes_observe_mem: TIMEOUT 30.010s.

The separately authorized one-shot candidate-only60s diagnostic completed PASS in31.851s: 1.851s beyond the original30s boundary. Its out-of-tree full config copy changes only terminate-after3→6 (observe-60-config.json), with --test-threads1 and the exact test filter. This is diagnostic evidence of completion, not a replacement for the red named gate.
No near30s CPU/stack sample was obtained in this run: process checks first found compilation active, then found the test had already exited. No sample command executed. The dedicated run was not repeated. Before/after machine observations and exact argv/result remain in candidate-observe60-* receipts.

The original25 common failed-test stderr bodies match after thread-ID normalization. The common test_import_bao_ranges timeout exposes the same separate checksum copy panic at util.rs227→237; the line shift comes from the inserted helper. Full per-test error text remains in nextest-failure-details.json and raw native-nextest logs.
