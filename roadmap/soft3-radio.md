---
tags: cyber, radio, roadmap, soft3
crystal-type: process
crystal-domain: cyber
status: draft
date: 2026-10-08
---
# soft3 radio — the transport the stack actually needs

radio is the largest module in the stack by a wide margin: 194,163 lines of Rust in 497 files, 334 dependency crates for `cyber-radio` alone, 646 for the workspace. it was forked from iroh 0.96 wholesale to change one hash. the fork delta in the core transport is +72/−71 lines; the stack's consumers use an endpoint, `connect`, `accept` and two streams. this page measures what is there against what the specs require, names the optimization vectors, and projects the module the way soft3 would build it — transmit only, addresses from the graph, identity from the neuron, format from hemera, frame from tade, store in bbg — with a line budget.

## 1. what is there

| crate | lines | role | consumers in the stack | verdict |
|---|---:|---|---|---|
| `quinn` (vendored n0 fork: multipath, QNT hole-punch, QAD) | 50,816 | QUIC | transitive | dependency, unmodified by us; counts as a dep, not as radio |
| `iroh` | 23,146 | endpoint, socket/paths, relay client, net_report, address lookup, raw-public-key TLS | `cy wire` (Endpoint, connect/accept, bi-streams) | core; ~25% used |
| `iroh-blobs` | 23,815 | get/provide protocol, redb fs store (9,210), tickets, collections, irpc rpc | none | protocol needed; store is bbg's; rpc pulls a second quinn |
| `iroh-willow` | 15,294 | 3D range reconciliation, meadowcap | none; broken build | reconciliation is foculus's |
| `iroh-docs` | 14,991 | range-based set reconciliation, replicas | none; does not compile (registry blobs/gossip types) | same |
| `iroh-relay` | 9,973 | DERP relay client+server: HTTP/WS/TLS/ACME, DNS resolver, pkarr endpoint_info, QAD server | every consumer passes `RelayMode::Disabled` | the rented-relay model the specs reject |
| `iroh-ffi` | 9,364 | uniffi bindings against upstream iroh 0.35 | not a member; broken feature | dead |
| `iroh-gossip` | 7,549 | HyParView + Plumtree, sim, rpc | none yet (soft3#26 pending) | membership + broadcast core needed; sim/rpc not |
| `nettools` | 7,429 | netwatch (interface monitor), portmapper (UPnP/PCP/NAT-PMP) | transitive | byte-identical upstream; dependency |
| `cyber-bao` | 3,807 | ranged verified-streaming adapter over `hemera::stream` | none yet (cyb#1402 pending) | ours; keep, pinned to hemera's format |
| `iroh-dns-server` | 3,782 | pkarr/DNS server | none | dead |
| `iroh-car` | 562 | CAR / CID / DAG-CBOR | none | IPFS legacy; dead |
| `particle`, `radio-cli`, `tests` | 1,483 | CLI, integration | — | ours |

our own code in the tree: cyber-bao + particle + radio-cli + tests ≈ 5,300 lines — 2.7%. everything else is upstream iroh with the hash swapped in blobs (766 diff lines) and gossip (98).

the dependency graph carries the IPFS era twice: upstream `iroh 0.96` + registry `iroh-quinn` next to the vendored fork; `blake3 1.8.3` + `bao-tree 0.16` through registry iroh-blobs under docs and willow (the README's "zero BLAKE3" is false); `ed25519-dalek` 2 and 3; `redb` 2 and 3; `cyber-hemera` 0.1.2 and 0.3.1. `iroh-docs` does not compile; `iroh-ffi` depends on a feature that does not exist; launch row 39 records that radio fails from a clean checkout.

## 2. what the stack requires of it

from `soft3/specs/routing.md`, `foculus/specs/gossip.md`, `cyb/decide/wire.md`, `cybergraph/specs/address.md` (branch `docs/locus-0927`), `radio/specs/neuron-context.md`, `tade/spec`, `cyber/network.md`, `cyber/launch.md`:

| concern | the spec says | iroh does |
|---|---|---|
| discovery | "the routing table is the graph": ANTENNA (endpoint id), SOCKET (`ip:port`), LOCUS, FOLLOW are cyberlinks on the neuron's book; "no address book, no peer list, no config"; the bootstrap contact is the only address a human types | pkarr over `dns.iroh.link`, DNS TXT, mainline DHT, mDNS, n0 relay map |
| relay | "C reached A through B": a peer that follows both forwards; "no rented relays"; relays earn focus for proven delivery | DERP: HTTP/WebSocket servers with ACME certificates, run by n0 |
| identity | endpoint key ≠ NeuronId; neuron = Hemera(pk), bound to the endpoint by a signed ANTENNA link; transport authentication grants nothing | ed25519 endpoint key is the identity; pkarr signs with it |
| framing | tade frames (`0x1F · type · LEB128 · data`); no other framing; the tade QUIC binding is not yet written | postcard in every protocol; `u32 LE len` in settle; three framings in flight |
| the message | "the gossip message is the signal": no envelope, no message id other than the signal's own particle, dedupe by content identity | Plumtree message ids (hemera, fine), postcard envelope |
| topology | subscription to ε-support domains plus a random baseline; push signals, pull completeness proofs | HyParView random overlay + Plumtree tree (close enough as the core) |
| streaming | hemera's tree format; every chunk verified; resume from the last verified chunk; lookup by particle | cyber-bao over hemera (done); blobs keyed by blob hash (radio#18 open) |
| store | bbg / the file store that answers by particle | redb fs store inside blobs, 9,210 lines |
| reconciliation | foculus owns ordering, CRDT merge, availability, DAS | iroh-docs ranger, willow — 30K lines nobody calls |
| transport crypto | classical placeholder now; PQ handshake through mudra seal (ML-KEM-768) later | rustls + ring, TLS 1.3, raw public keys |
| the second network | "there is no second network"; radio "receives an endpoint to dial and a stream to open" | iroh is a network: discovery, relays, DNS, metrics, a server fleet |
| interplanetary | store-and-forward, delay-tolerant, out-of-order delivery converges | QUIC idle timeouts, live-connection assumptions, no custody |

the gap is not a missing feature. it is that iroh is a *network product* and the stack wants a *wire*.

## 3. optimization vectors

### 3.1 cut: zero consumers, zero spec (−~78K lines, −~250 crates)

| cut | lines | why |
|---|---:|---|
| iroh-docs, iroh-willow | 30,285 | reconciliation is foculus's by `component-boundaries.md`; both broken; they are the only path by which blake3 and bao-tree re-enter the build. the algorithms worth keeping (`ranger.rs` 1,685; willow `proto/`) move to foculus as a refactor, not here |
| iroh-ffi | 9,364 | built against upstream 0.35; the stack's bindings are cyb's own |
| iroh-dns-server | 3,782 | discovery is the graph |
| relay server, HTTP/WS client, ACME, DNS resolver, pkarr endpoint_info, QAD server | ~7,800 of iroh-relay | rented relays are rejected; the one piece worth keeping is the relay *protocol* over a stream (§3.2) |
| address_lookup: pkarr, pkarr/dht, dns, mdns, n0 presets, default relay map | ~2,100 | addresses come from the graph. mdns is the one optional convenience; keep it only behind a feature if LAN bootstrap matters |
| net_report HTTPS probes, reportgen | ~2,300 | observed address comes from QAD on any connected peer (already in quinn); no relay fleet to probe |
| iroh-blobs: redb fs store, mem store, entity_manager, tickets, collections, irpc rpc, examples | ~14,000 | the store is bbg's file store; tickets are cyberlinks; rpc pulls a second quinn stack |
| iroh-gossip sim, rpc, bin | ~1,800 | — |
| iroh-car | 562 | CID/DAG-CBOR is the IPFS address model the stack left |
| examples, bench, test_utils, metrics, wasm/browser paths, qlog | ~6,000 | lytics is the measurement layer; the browser target is cyb's |

### 3.2 replace with our components (−~12K, and the module becomes soft3's)

| iroh piece | replaced by | size of the replacement |
|---|---|---|
| postcard wire envelopes (blobs, gossip, relay, settle `u32 LE`) | one tade binding over QUIC: a stream is a sequence of tade frames; type byte selects the protocol; the gossip payload *is* the signal frame | ~300 lines + a page in `tade/spec/5-transport-bindings.md` |
| discovery stack | the node reads ANTENNA/SOCKET/LOCUS from bbg and hands radio an `EndpointAddr`; radio exposes `dial(addr)` and nothing that resolves | 0 in radio; the record parser lives in soft3/cybergraph |
| DERP relay (WebSocket actor 1,560 + transports/relay 353 + mapped_addrs 344 + server) | relay-through-peer: any connected peer forwards datagrams between two of its connections on a `radio/relay/1` stream; the relay path is a quinn multipath path whose address is the relaying peer; who relays is read from FOLLOW overlap, and proven delivery is a receipt the relay can be paid for (`cyber/network.md` relay reciprocity) | ~600 lines |
| ed25519 endpoint identity as *the* identity | ed25519 stays the transport key (TLS needs one); authority is the NSIG1-signed ANTENNA link binding transport key → neuron, verified by the node, never by radio | ~0 in radio; the binding is mudra/neuron-auth |
| classical KEX | hybrid X25519 + ML-KEM-768 in the TLS 1.3 handshake through the rustls provider (`rustls-post-quantum` / aws-lc-rs) — a provider swap, no protocol change; this is the one cheap post-quantum win and it does not wait on mudra | ~50 lines + a dependency change (ring → aws-lc-rs) |
| blobs fs store | bbg file store answering by particle; radio keeps get/provide + ranged verified streaming only | 0 in radio |
| net_report | QAD observed-address from peers + netwatch interface events | ~300 lines |
| 64-byte digest in radio docs vs 32 in hemera | radio takes the digest width from `hemera::Hash` and hardcodes nothing; profile v2 may change it again (hemera PR #15) | a type, not a constant |

### 3.3 keep, and keep upstream

QUIC (quinn with multipath, QNT hole-punching, QAD), TLS (rustls, raw public keys), HyParView + Plumtree, netwatch, portmapper for home NATs. these are the parts where a rewrite is the trap: a QUIC implementation is 40K lines of state machine and a decade of interop; the n0 fork's hole-punching inside QUIC is the best available and is being upstreamed. vendoring them under cyberia-to names for publication is right; editing them is not.

## 4. the projection — radio in the soft3 taste

one verb: transmit. radio dials, punches, relays through a peer, gossips, and pipes verified streams. it holds no address, no identity, no store, no reconciliation, no format, no frame of its own.

```
radio
├── endpoint   bind · dial(EndpointAddr) · accept · ALPN registry · raw-pk TLS, hybrid PQ KEX    ~1,500
├── paths      ip paths · QNT punch events · peer-relay path · path selection (from socket/)     ~2,000
├── relay      forward datagrams for two of my peers over radio/relay/1 · delivery receipt       ~600
├── observe    observed address by QAD from peers · interface changes (netwatch)                  ~300
├── gossip     HyParView membership · Plumtree broadcast · topic = hemera id · message = signal   ~2,000
├── stream     the tade binding: a QUIC stream is a sequence of tade frames                      ~300
├── fetch      get/provide by particle · ranged verified streaming · resume at last good chunk   ~2,500
└── custody    store-and-forward queue for signals when a path is dark (the interplanetary case) ~800
cyber-bao      the ranged adapter over hemera::stream (ours today)                               ~3,800
                                                                                        own code ~13,800
deps: quinn fork (~50K, vendored for publication) · netwatch/portmapper (~7K) · rustls · tokio
```

the IPFS era, named so it stays gone: CID and multiformats → particle; DHT, DNS seeds, pkarr → cyberlinks on the book; bitswap-shaped blob store → bbg; DERP relay fleet → the peer that follows you, paid in focus; docs/willow → foculus; postcard → tade; ed25519-as-identity → neuron bound by signature; a measurement pipeline → lytics.

what the interplanetary row adds that iroh has nowhere: `custody` — a signal accepted for forwarding is kept until a path confirms delivery; idle paths are dark, not dead; streams resume by particle range. gossip's "eventually connected ⇒ every correct node receives it" (VEC P4) is a transport property only if the transport holds the bundle across the dark.

budget: ~14K lines of own code against 194K in the tree today — fourteen times smaller — with ~80 crates instead of 334, one quinn, one ed25519, one hemera, zero blake3. counted with the vendored quinn and nettools the tree is ~70K, of which 80% is a QUIC stack we do not edit.

## 5. order of work

1. trim (a week, no design): delete docs, willow, ffi, dns-server, car, relay server, gossip sim/rpc, blobs rpc/store/tickets/examples; dedupe the lock (one quinn, one ed25519, one redb → none, one hemera); the tree builds from a clean checkout (launch row 39). −~78K.
2. the tade binding and the signal-as-message: one framing for settle gossip, signal gossip and fetch; `u32 LE` and postcard envelopes retired. closes the three-framings conflict.
3. graph addressing: `dial(EndpointAddr)` only; the node parses ANTENNA/SOCKET; ANTENNA carries the NSIG1 binding; `cy wire` stops deriving neurons from endpoint keys (`cyb/decide/wire.md:60`).
4. relay-through-peer over `radio/relay/1`; delete the WebSocket relay actor and mapped-addr machinery once the peer path works across two machines (the `soft3/status.md:80` milestone).
5. hybrid PQ KEX by provider swap; the ed25519 transport key becomes explicitly ephemeral and bound.
6. custody for the dark-path case, behind the foculus delay-tolerant regime.

what this page does not decide: whether mdns stays as an optional LAN bootstrap; whether `ranger.rs` moves to foculus before or after launch; the relay receipt format (a cyberlink, presumably). launch rows touched: 21, 22, 34, 39, 42.

see `soft3/roadmap/component-boundaries.md` · `soft3/specs/routing.md` · `foculus/specs/gossip.md` · `cyb/decide/wire.md` · `radio/specs/neuron-context.md` · `cyber/launch.md` §critical dependencies 3
