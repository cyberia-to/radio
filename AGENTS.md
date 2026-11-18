# radio

a fork of iroh with every hash routed through hemera (Poseidon2 over Goldilocks). the crate map and the boundary table are in `README.md`; this file is the working rule.

## boundary

radio's verb is **transmit**. before adding code here ask which repo owns the mechanism:

- a hash, a tree rule, a stream format → [hemera](../hemera). `cyber-bao` may adapt hemera's format to ranges and async I/O; it may not define a second format. `cyber-bao/tests/hemera_format.rs` fails if the two drift.
- a merge, a set reconciliation, an ordering rule → [foculus](../foculus). `iroh-docs` and `iroh-willow` are here only until their transport-independent cores (`ranger`, willow `proto`) move to foculus; do not grow new reconciliation logic in radio, and do not delete these engines — they are the stack's set-reconciliation substrate.
- a wire envelope → [tade](../tade).
- a key agreement or a cipher → [mudra](../mudra). the vendored rustls/ring/ed25519 are the classical placeholder for a post-quantum handshake mudra has not implemented yet; do not extend them with cyber-specific crypto.

## workspace

- `cargo test -p cyber-bao` and `cargo check --workspace --tests` before a commit; the integration tests (`tests/integration`) cover blobs and gossip over in-memory endpoints.
- vendored iroh crates keep their upstream layout; cyber changes are the hash substitution and the removal of what other repos own. do not reformat upstream files.
- never commit to `main` directly — branch + PR.
