---
title: injected file-stream validation
tags: radio, audit, storage
status: partial
---
# injected file-stream validation

Radio revision `fe72dbd2f15370bfc333709d4870cb2f2b1d0d15` adds the opt-in
`radio::files` protocol to its existing endpoint/router. Storage and per-file
authorization enter through Provider/Source/Sink capabilities. This path opens
no database or persistent spool and computes no alternate file identity.

[Source closure](sources.json), [commands and log checksums](checks.json), and
the pinned revision's [Cargo.lock](../../../Cargo.lock) identify the tested
inputs. The commands ran against the source committed at that revision.

## executable checks

Run from the Radio repository with
`CARGO_TARGET_DIR=/tmp/cyber-content-storage-20260924/target`.

| command after `cargo` | result | evidence |
|---|---|---|
| `test -p cyber-radio --release --test file_stream --locked --offline` | 4 passed | [protocol tests](logs/radio-files-tests.log) |
| `test -p cyber-radio --release --lib path_state::tests --locked --offline` | 10 passed | [path pruning regression](logs/radio-files-regression.log) |
| `clippy -p cyber-radio --lib --test file_stream --locked --offline --no-deps -- -D warnings` | pass | [lint](logs/radio-files-clippy.log) |

The protocol target uses actual authenticated QUIC connections with loopback
addresses, relay disabled and synthetic keys. Its parameterized cases check:

- Malformed, oversized, overflowing, out-of-range, truncated and trailing
  request frames fail before the provider is called.
- Truncated/extended payloads and invalid response status never call the sink.
- Closing the server during a partial response and expiration of the client's
  deadline both fail without acknowledging a sink write.
- Every range rechecks authorization. Revocation rejects the next range on an
  established connection. The connection admission budget rejects excess work
  while the admitted connection remains usable.

The path-state suite covers the behavior-preserving descending-sort cleanup
required by the current Clippy gate. Counts are test harness entries; protocol
cases loop over several distinct frames/failure modes. No compiler warnings
were emitted by the recorded commands.

## limits and integration

The new [file-stream contract](../../../specs/file-stream.md) carries staging
bytes; its receiver supplies full identity verification. These checks establish
framing and capability boundaries, not authenticated sparse-range proofs.
The [[cybergraph/audit/storage/radio-2026-09-24/README|BBG adapter receipt]]
records persisted resume and publication on both storage profiles.

Both workspaces have independent dependency locks and use separate target
directories in reproduction. Reusing an artifact directory during development
produced incompatible cached dependency types; separate targets removed that
build-input collision. No transport dependency versions were changed in Radio.

Legacy BAO/blob/doc stores remain on their existing path until verified migration
and product cutover. Relay/NAT, mobile targets, sustained load, private retrieval
leakage and physical power-loss were not qualified here. The new protocol uses
the existing endpoint handshake; it adds no neuron authority or remote retention
receipt. Complete S5/A4 qualification remains in
[[soft3/roadmap/storage/README|the storage project]].
