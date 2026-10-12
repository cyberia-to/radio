# Bounded traversal prerequisite

Research only at Radio `dacd030c9d6301b316a96b5bc6e4ea1e1cec79f1`.
No production changes, candidate gates or complete proof verification.
The separate bounded-reducer task does not modify these geometry semantics.

The Rust public consumer, exact source inputs and lock, recorded argv/environment,
tool executable hashes and raw output are preserved in the hash-indexed capsule.
`evidence-index.json` maps logical paths to regular files in `evidence.tar.gz`.
`nu verify.nu .` checks the archive, source SHA-256/Git blob identities, command
input/output bindings and literal observations. It does not rerun Cargo or
establish Git commit authenticity from a remote server.

All observations below come from these commands, with cwd the frozen consumer
at `/tmp/radio-bao-bounded-traversal-research/probe` and source revision above:

```text
/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo generate-lockfile --offline
/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo run --offline --locked
/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo run --offline --locked --release
```

These are the exact absolute executable argv in
`resolve/command.json`, `debug/command.json` and `release/command.json`.
Both executions exit 0 because the probe catches and reports the intended
panics. Panic text remains on stderr; exit 0 is not a correctness verdict for
the observed API. Both use matched Cargo/rustc/rustdoc, jobs 2, incremental 0,
private targets, macOS arm64 and 64-bit usize. Production inputs stayed identical.
The consumer resolves its own pinned lock; it is not a Radio workspace gate.

## Measured boundaries

Both debug and release produce this subset of the retained allocation output:

| Leaves | Postorder items built before first next | Constructor allocation/reallocation calls | Sum of requested allocation bytes |
|---:|---:|---:|---:|
| 1 | 1 | 1 | 24 |
| 16 | 31 | 4 | 1440 |
| 257 | 513 | 9 | 49056 |
| 4096 | 8191 | 12 | 393120 |

The first `next()` records zero allocation calls in every measured case.
`post_order_chunks_iter` constructs the entire Vec first; its name does not
establish bounded setup. Requested-byte sums include old and replacement
reallocation requests. They are neither peak live nor resident memory.
The thread-local allocator has a positive allocation control; setup and
printing sit outside the measured region. No file body is allocated.

The same commands report these checked-width failures:

| Public call | Debug | Release |
|---|---|---|
| `BaoTree::new(1, BlockSize(64)).blocks()` | shift overflow panic | 1 |
| `BlockSize(52).bytes()` | 0 | 0 |
| `BaoTree::new(1, BlockSize(52)).shifted()` | shift overflow panic | two apparently valid node values |
| last-only log-0 traversal at length `u64::MAX` | multiply overflow panic | leaf at chunk 4503599627370495, size 4096 |

For the last row, exact division of hexadecimal `ffffffffffffffff` by 4096
gives quotient 4503599627370495 and remainder 4095. The reported final size is
one byte too large. The portable verifier independently long-divides the literal
without allocating a body or overflowing its own integer domain. The source
computes the unclipped end product before `.min(self.size)`. This finite
geometry witness does not establish behavior of an actual authenticated proof.

## Reproduction and limits

Use a clean checkout of the named Radio commit. Materialize the capsule's
consumer files, changing only its dependency path to that checkout's
`cyber-bao`; keep `probe/Cargo.lock`. Execute the debug/release argv above with
Rust 1.95.0. That path substitution is a reproduction adaptation, not a claim
that the original recorded command was portable or rerun here.

The next implementation needs admitted geometry and bounded traversal before
the group reducer can support bounded slice verification. This research chooses
no new wire policy, empty-request behavior or legacy API migration. Particle to
root authentication remains another prerequisite.

The first local portable-check attempt misspelled the audit directory; the
second exposed unavailable Nushell `hash sha1`. Both raw attempts and the
failed verifier source remain under `portable/` / `verify-attempt1.nu.txt`.
The final verifier uses `git hash-object --stdin` and passes. These are harness
diagnostics, with no bearing on the unchanged Rust observations.
