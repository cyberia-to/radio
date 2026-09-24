---
title: local file names through the Radio CLI
tags: radio, fs, spec
status: implementation
---
# local file names through the Radio CLI

`radio name` exposes [[cybergraph/specs/catalog|the local catalog]] over the
explicit `--database`, `--backend` and `--namespace` selected by the host.
Radio owns command parsing and output; Cybergraph owns name semantics and
conditional publication, and BBG owns the durable data. These commands require
no network connection and create no separate Radio store.

| Command | Result |
|---|---|
| `name set PATH PARTICLE` | Create a name or edit its existing binding to a sealed payload |
| `name resolve PATH [--at INDEX]` | Print payload particle, binding identity and content revision |
| `name rename FROM TO` | Atomically move the binding to an absent destination |
| `name remove PATH` | Remove the selected name while preserving retained history |
| `name list [--at INDEX]` | Stream the selected state's names in bounded ordered pages |
| `name history [--after INDEX] [--limit COUNT]` | Print one page of revision indexes and commits |

Mutations accept `--expected INDEX` and `--request HEX`. An explicit expected
index pins the prior state; a stale state conflicts. With no expected index,
a fresh operation reads the current head once. Each request identifies the
complete operation. The CLI prints its request before publication, allowing
recovery after an uncertain outcome. A supplied request that already has a
receipt and omits `--expected` reconstructs its original prior state. Identical
retries return the original commit even after later changes; changed arguments
conflict. An explicitly supplied expected index takes precedence over recovery.

Omitting `--request` generates a fresh random 32-byte request. Successful writes
print the committed index and commit particle. A particle must already be sealed
in the same storage namespace, normally through `radio file add` or a verified
download. Name operations preserve payload retention and use the catalog's
path validation, binding checks and atomic publication.

`--at INDEX` resolves an exact historical head through a bounded history lookup.
Without it, reads pin the current head once. Listing uses pages of 256 entries,
keeping that head across all pages. Its final column quotes paths so control
characters cannot impersonate additional output rows. History defaults to 256
entries and accepts 1–4096 per call; `--after` resumes exclusive of that index.
These bounds limit individual calls, independently of total names or revisions.

These commands expose local retained history. Signed remote patches, aliases,
channel merge and complete catalog-plus-payload device migration retain the
implementation boundaries described by the catalog contract.
