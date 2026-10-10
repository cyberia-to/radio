# radio workspace gate — `cargo test --locked`, 2026-10-10

The release train's stack gate for radio is `cargo test --locked` at the workspace root, red if it exits non-zero or prints a `warning` line (`soft3/release/train_gates.py`). This records the gate before and after the branch `fix/radio-gate-green`.

Machine: Apple M4 Max, macOS 26, rustc/cargo 1.95.0 (Homebrew), shared with other agents (load average ~50). Siblings: hemera `d5f0a09` (origin/main). Detached worktrees under `~/cyber/.stands/G3`, one `CARGO_TARGET_DIR` per tree. Result lines only (`*.results.txt`, ANSI stripped).

## before — origin/main 344ac162

`radio-main-gate.results.txt`: exit 101 at compile time. `iroh-docs` 9 errors (registry `iroh-base` 0.96 mixed with the fork), `iroh-bench` 5 errors (`radio` crate name), two `warning: output filename collision` for the `transfer` examples. No test ran.

## after — branch head

| run | command | real | exit | warnings | passed / failed / ignored |
|---|---|---|---|---|---|
| gate 1 | `cargo test --locked` | 54.5 s | 101 | 0 | 180 / 3 / 1 (stops at the first failing binary, `cyber-radio --lib`) |
| gate 2 | `cargo test --locked` | 16.9 s | 101 | 0 | 180 / 3 / 1 |
| full | `cargo test --locked --no-fail-fast` | 211.5 s | 101 | 0 | 578 / 3 / 9 across 47 test binaries |

The three failures in every run are `address_lookup::mdns::tests::run_in_isolation::{mdns_publish_resolve, non_advertising_endpoint_not_discovered, test_service_names}` (timeouts; on other runs the same module lost 2–5 of its 5 tests). They are the machine, not the fork:

- upstream `iroh` 0.96.1 from crates.io, built alone on this machine with `cargo test --features address-lookup-mdns,test-utils --lib mdns`, fails the same 5 tests the same way;
- `route -n get 224.0.0.251` resolves to `utun4`, the NordVPN tunnel, so mDNS multicast never reaches the LAN.

The gate is therefore red on this machine until mDNS multicast is routed to a LAN interface (or the train runs elsewhere); no test was skipped or weakened to hide it.

## what changed

1. radio#5 (cherry-picked): `iroh-docs` takes `iroh-blobs`/`iroh-gossip` from the fork; multi-hop gossip test.
2. radio#6 (cherry-picked): `iroh-bench` uses `iroh::` and the vendored quinn.
3. `iroh-blobs` on 32-byte Hemera hashes and 4 KiB chunks: `Hash::EMPTY` was a zero placeholder (every empty-blob path failed with "invalid size for hash"), now the tree root of `b""` pinned by `test_empty_hash`; the checksummed state file and hash-seq child counts/offsets still used 64-byte widths; tests rescaled to `CHUNK_SIZE`, 64 KiB blocks and `OUTPUT_BYTES`. Before this the unfiltered `iroh-blobs` library suite had 27 failures and hung (also recorded in `../2026-10-10-bao-root-policy/`).
4. examples: `random_store` carries a ticket over the forked `EndpointAddr`; `custom-protocol` reads 32-byte hashes; `iroh-blobs/examples/transfer.rs` → `blobs-transfer.rs`.
5. `[profile.dev.package.cyber-hemera] opt-level = 3`: the `iroh-blobs` library suite went from 337 s (with two-node QUIC tests timing out under load: `two_nodes_push_blobs_fs`, `two_nodes_get_blobs_fs`, iroh-docs `test_download_policies`) to 41 s; none of those failed in the three runs above.
