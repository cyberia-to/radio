---
title: file streams through injected storage
tags: radio, spec, storage
status: implementation
---
# file streams through injected storage

Radio's `files` module transfers bounded ranges over the existing authenticated
QUIC endpoint and router. It receives capabilities supplied by the host. BBG
owns durable bytes and progress through the Cybergraph adapter described in
[[cybergraph/specs/file-transfer]].

## capabilities and authority

`Provider::open(peer, file)` authorizes the authenticated remote endpoint for a
specific particle and verifier profile, then returns a `Source`. Every range
request repeats this authorization. `Source` binds the complete descriptor and
reads bounded ranges. A rejected or absent file produces the same wire response.
Host policy runs before reading its descriptor or payload.

`Sink` binds the expected descriptor and accepts a complete received range.
Its completion means the host accepted that bounded write. The Cybergraph
adapter returns only after BBG's durable write succeeds. Namespace, upload
request, local database path and retention policy stay at the host.

Endpoint authentication identifies the transport peer. The host decides its
content permissions; neuron authority retains [[radio/specs/neuron-context|its
separate contract]]. A particle supplies an address; host authorization supplies
access. An already authorized range may finish during revocation; each later
range requires a new authorization decision.

## transfer framing

The opt-in ALPN is `/cyber/file-stream`. One connection carries sequential
bidirectional streams, each with one request. The fixed 85-byte request contains
an operation byte, particle (32 bytes), verifier profile (32 bytes), total length
(8 bytes), byte offset (8 bytes) and range length (4 bytes), followed by FIN.
Integers use unsigned big-endian encoding. Operation 0 reads a range; its response
contains a status byte and exactly the requested bytes followed by FIN.

Operation 1 describes an authorized file. Its length, offset and range length
fields MUST be zero; the response is status 0, the 8-byte total length and FIN.
The provider repeats the same authorization used for ranges and the returned
source MUST match the requested particle/profile. Descriptor lookup performs no
payload read. Status 1 means unavailable for either operation. Other operations,
statuses and noncanonical fields fail. Descriptor length is an untrusted staging
claim until complete identity verification succeeds; obtaining it grants no
retention or publication authority.

The request length is bounded independently of total file length. Both parties
validate offset/length arithmetic, the range budget and exact stream termination.
Malformed, truncated or trailing bytes fail the operation. A receiver passes a
range to its sink only after its complete frame and FIN have arrived.

The server sets an explicit concurrent-connection budget and inactivity/request
deadline. Requests on one connection run sequentially. The client sets a request
deadline and waits for sink completion before fetching the next range. Storage
operations and network waits are separate; no database transaction spans a
network await. Dropping a transfer future stops transport work and leaves any
already accepted sink writes governed by their storage contract.

## verification and delivery

The host supplies the expected descriptor and its verifier. This path carries
staging bytes; complete identity verification occurs at the receiver before
publication. It preserves existing exact-byte Blob identity while
[[soft3/roadmap/storage/identity|S1]] settles the structural construction and
authenticated range proofs. This ALPN is an implementation path; freezing the
public file protocol remains part of S1/S5.

Radio computes no competing file address. QUIC delivery establishes transport
progress. Durable local acceptance, complete verification, application retention
and a remotely authenticated protection receipt have separate meanings.
This read protocol issues no protection receipt.

Radio holds bounded transient buffers and source/sink handles. Restarting its
endpoint/router leaves storage and coverage at BBG. Legacy iroh-blobs, BAO,
iroh-docs and their stores remain accounted for by the
[[soft3/roadmap/storage/README|extraction ledger]] until content-aware migration
can retire them. Registering this protocol creates no legacy blob store.
