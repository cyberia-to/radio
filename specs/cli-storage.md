---
title: CLI file storage composition
tags: radio, spec, storage
status: implementation
---
# CLI file storage composition

The `radio` executable composes the shared Cybergraph/BBG owner with Radio
transport. `--database` and `--namespace` explicitly select the local owner and
scope. `--backend ssd|hdd` selects Fjall or redb. There is one BBG store;
network protocol handlers receive scoped source/sink capabilities.
Recognized legacy Radio directories (`blobs.db`, `docs.redb` or nested
`blobs/blobs.db`) are rejected before opening BBG, preserving their source data
for explicit import. This recognition covers known layouts rather than arbitrary
foreign database formats.

`file` (also accepted as `blob`) provides add, list, get and export operations.
Add streams exact bytes into BBG, verifies the existing Blob particle and prints
it. List pages sealed descriptors; interrupted staging stays invisible. Get
obtains an authorized descriptor from the named endpoint, resumes a deterministic
namespace/particle/length-bound upload, verifies the complete file and exports
it to the requested path. Retry reuses durable coverage. Export reads a sealed
local file with Radio stopped. Empty and binary files use the same path.
No command silently overwrites an existing output file. Output is created only
after complete verification; an interrupted export may leave a partial output
file which the caller must explicitly remove or choose another path for.

Sealed content has the current BBG indefinite local protection policy. A file
command reports local content availability; remote replication obligations,
FS naming and application history use their respective services.

`node start` serves this selected scope and gossip. The caller explicitly opts
into either public serving with `--public` or a peer allowlist with
`--allow-peer`. Each descriptor/range request rechecks that policy. Transport
credentials come from the existing host-supplied `RADIO_SECRET`; absent credentials
produce an ephemeral endpoint whose secret is not logged. `node id` remains an
explicit endpoint-key generation/export command. Local CLI access is trusted;
namespace selection alone is not remote authorization.

`hash sum` and `hash verify` use the same streaming exact-byte Hemera construction
as file import. BAO encode/decode/outboard commands remain explicitly legacy
inspection tools; their roots are not accepted as Blob particles without full
byte verification. S1 still owns the final structural identity and range-proof
contract. Old BAO peers cannot serve the new file-stream ALPN; protocol mismatch
is reported, never silently bypassed.
