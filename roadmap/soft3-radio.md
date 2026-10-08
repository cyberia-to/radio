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

## 6. QUIC — the boundary, and where the stack enters it

### what QUIC is, and why its core is not ours to rewrite

QUIC (RFC 9000/9001/9002) is a transport over UDP that folds four things that TCP+TLS keep apart into one state machine: connection establishment with TLS 1.3 inside the handshake (1-RTT, 0-RTT resumption); per-packet AEAD protection with separate key levels (initial, handshake, 1-RTT) and key update; loss detection and congestion control driven by ACK ranges, probe timeouts and pacing (RFC 9002); and many independent streams per connection with per-stream flow control, so one lost packet stalls one stream, never the connection. on top: connection ids that let a connection survive an address change, path validation (PATH_CHALLENGE/RESPONSE), anti-amplification before validation, PMTU discovery, version negotiation. the n0 fork adds three extensions: multipath (several validated paths under one connection, each with its own congestion state), QAD (a frame that tells a peer which address it is seen at), and QNT (ICE-style candidate exchange and simultaneous open inside the connection — hole-punching with no external signalling).

`quinn-proto` is 38,665 lines because every one of those is a state machine with a corner-case budget written in RFC prose and paid for in interop events since 2017: ACK-of-ACK rules, PTO backoff, stream state transitions, retry and stateless reset, key phase bits, amplification limits, migration under NAT rebinding. none of it carries any assumption about who the peers are, what the bytes mean, or how a path was chosen. that is exactly why it is reusable and exactly why rewriting it buys nothing: there is no cyber-specific invariant inside it to express. the trap is that a transport that is 95% right looks finished and is not; the last 5% are the attacks (amplification, reset injection, congestion collapse) and the interop with every other implementation on the planet.

### where the stack enters — the extension points QUIC already exposes

the n0 fork proved the pattern: QAD and QNT are *extension frames* and *transport parameters*, added without touching the core. cyber enters the same way, at five points, with two things the stack has that no other transport has: location proofs and a graph that is also the routing table.

| layer | what is pluggable | what cyber puts there | where |
|---|---|---|---|
| transport parameters | `initial_rtt`, idle timeouts, ack delay, flow-control windows, datagram buffers | derived from the location proof instead of guessed: the RTT floor is the light-time between the two loci (nothing below it is honest), the bandwidth-delay product sizes the windows, and the idle timeout is a function of distance — a Mars path is dark for minutes and is not dead | `iroh/src/endpoint/quic.rs` builder; `quinn-proto` `TransportConfig` |
| congestion control | the `Controller` trait (`quinn-proto/src/congestion/`: cubic, newreno, bbr) | a physics-aware controller: BBR-shaped, with min_rtt pinned to the light-time floor from locus rather than re-measured, so startup does not probe for a delay that is already known; across planets this is the difference between converging and never leaving slow start | one new module beside `bbr`; selected per path |
| stream priority | `SendStream::set_priority` | focus is scheduling: a fetch of a high-φ* particle, a settle ticket in the open window, a beacon — ahead of a backfill. §2.4 of the whitepaper says focus is attention, fuel and consensus weight; the transport is where "scheduled first" becomes literal | policy in `fetch` and `gossip`, no proto change |
| extension frames | the n0 pattern: `ObservedAddr` (QAD), `ReachOut`/`AddAddress` (QNT) | **PLACE frames — the location proof inside path validation.** QUIC's PATH_CHALLENGE/RESPONSE already proves "this peer answers at this address within one RTT"; `mudra/specs/place.md` wants "this peer is within RTT·c of me", measured by a challenge the responder cannot precompute. the two are one exchange: a PLACE_CHALLENGE carrying a fresh nonce bound to the beacon, a PLACE_RESPONSE bound by hash to the challenge and the responder's neuron, and both sides keep the signed RTT sample as evidence. the transport's own validation becomes the RTT mesh; no separate measurement protocol, no extra round trips, and relay fees ∝ 1/latency read the same samples | `quinn-proto/src/frame.rs` + a small handler, exactly where `iroh_hp.rs` lives; evidence export in `observe` |
| multipath path choice | `open_path(addr, PathStatus)`, path stats with `min_rtt` | which paths to open and which to prefer is read from the graph and the locus: ANTENNA/SOCKET give candidates (QNT's candidate list comes from cyberlinks, not from a relay), locus distance orders them, the relay-through-peer path is opened as a backup path with the relaying peer's address | `paths` module; policy over the fork's API, no proto change |

and two places where cyber's routing lives *above* QUIC, because QUIC is point-to-point and the graph is not:

- forwarding: greedy by locus over FOLLOW with gravity-pressure fallback (`soft3/specs/routing.md`) is an overlay that chooses the *next QUIC peer*; the hop carries a tade frame on a stream or a QUIC datagram (RFC 9221, in the fork) when the payload is itself a QUIC packet being relayed — datagrams avoid reliability-on-reliability.
- custody: delay-tolerant delivery is a bundle layer, not a transport feature; QUIC stays the protocol of one pond, custody bridges ponds. this is the CCSDS lesson (bundles over a convergence layer) applied with our own convergence layer.

### what this buys that nobody else has

every QUIC stack measures RTT; none can say whether the RTT is *honest*. with PLACE frames a path's RTT is evidence with a signature on both ends, so congestion control can trust its floor, relays can be paid by proven latency, a sybil at the rim cannot fake proximity, and a Mars node's minutes are a known constant rather than a timeout. that is the stack reaching into the transport at the one point where it has something to add — the physics — and leaving the state machine alone.

## 7. the task, as work

each step is a PR against `main`; each has a gate that is a test or a measurement, not a review opinion. estimates are lines removed/added and calendar for one agent; launch rows from `cyber/launch.md`.

| # | step | scope | out of scope | acceptance | gate | estimate | launch rows |
|---|---|---|---|---|---|---|---|
| 1 | trim | remove iroh-docs, iroh-willow, iroh-ffi, iroh-dns-server, iroh-car, the relay `server` feature and its deps, gossip `sim`/`rpc`/`bin`, blobs `rpc`/fs+mem store/tickets/collections/examples, iroh examples/bench/test_utils, `metrics` features, wasm cfgs; dedupe the lock: one quinn, one ed25519-dalek, zero redb, zero blake3/bao-tree, one cyber-hemera | any behavior change in endpoint/paths/gossip/fetch | `cargo build --locked` from a clean checkout; `cargo tree -i blake3` empty; `cargo tree -d` shows no duplicate of quinn/ed25519/hemera; all remaining tests green; `ranger.rs` and willow `proto/` archived to a tag `pre-trim` for foculus to lift | lines ≤ 115K in tree, crates ≤ 180 | −78K · 1 week | 39 |
| 2 | tade binding | `stream` module: a QUIC stream is a sequence of tade frames (`0x1F · type · LEB128 · data`), type byte = protocol; settle gossip (`u32 LE`), signal gossip and fetch envelopes move to it; postcard leaves the wire; the binding page lands in `tade/spec/5-transport-bindings.md` | tade's own encoding | a `cy wire` HELLO/FRAMES session and a foculus settle session decode with one codec; no `postcard` in `cyber-radio*` deps; a frame is forwarded byte-identical (the message is the signal: hash before = hash after) | fuzz on frame boundaries; 64 MiB limit and depth 64 enforced | +300 / −1,200 · 3 days | 21 |
| 3 | graph addressing | radio exposes `dial(EndpointAddr)` and `accept` only; `address_lookup` (pkarr, dht, dns, presets, relay map) deleted; the node parses ANTENNA/SOCKET/LOCUS from bbg and dials; ANTENNA carries the NSIG1 binding transport key → neuron and the node verifies it; `cy wire` stops deriving neuron ids from endpoint keys | mdns (kept behind `lan` feature or deleted — decide in review); routing policy (soft3's) | three nodes on three machines find each other from one bootstrap contact and the graph alone; an endpoint whose ANTENNA signature fails is not treated as that neuron | network gate with `RelayMode::Disabled`, no DNS egress (verify with a firewall rule) | −2,100 / +150 (node side +300) · 1 week | 42, 21 |
| 4 | relay through a peer | `relay` module: a peer forwards datagrams between two of its connections on `radio/relay/1`; the relayed path is a quinn backup path addressed at the relaying peer; who relays is chosen from FOLLOW overlap; delivery receipts are emitted as evidence; the WebSocket relay actor, `mapped_addrs`, `transports/relay` and the HTTP client stack are deleted once the peer path passes the two-machine test | paying for relay (tok) | C behind a symmetric NAT reaches A through B on three machines; a direct path replaces the relay path when QNT succeeds; receipts match forwarded bytes | the `soft3/status.md:80` milestone; relay bytes ≤ 1.1× payload | +600 / −4,500 · 2 weeks | 21, 34 |
| 5 | observe | `observe` module: observed address by QAD from any connected peer; interface changes from netwatch; `net_report` HTTPS probes and reportgen deleted; portmapper kept for home NATs | — | a node learns its public address with zero HTTP egress; address change triggers rebind within one idle period | no `reqwest`/`hyper` in `cyber-radio` deps | +300 / −2,300 · 3 days | 39 |
| 6 | fetch by particle | `fetch` module: get/provide keyed by particle, ranged verified streaming through cyber-bao, resume from the last verified chunk, multi-peer range fetch; the store is a trait implemented by bbg's file store; digest width taken from `hemera::Hash` | the file store itself | cyb opens a file it never had from a peer (row 22); a corrupted chunk is rejected at that chunk and the fetch resumes from the previous one; a 1 GiB file streams from two peers | row 22 test on three machines; throughput ≥ 80% of raw QUIC | +2,500 / −14,000 · 2 weeks | 22, 34 |
| 7 | PQ handshake | hybrid X25519 + ML-KEM-768 KEX through the rustls provider (aws-lc-rs / `rustls-post-quantum`); the ed25519 transport key documented as ephemeral and bound; `component-boundaries.md:63` row updated | PQ signatures in TLS; mudra seal integration (later, when seal is implemented) | handshake negotiates the hybrid group with a peer on the same build; classical fallback only by explicit flag | `cargo tree` shows one TLS crypto provider | +50 · 2 days | — |
| 8 | PLACE frames | the location proof as path validation: PLACE_CHALLENGE/RESPONSE extension frames in quinn-proto beside `iroh_hp.rs`; RTT samples exported with both signatures from `observe`; transport params (`initial_rtt`, idle) derived from locus distance; a physics-aware congestion controller module with the light-time floor | relay pricing (tok); the RTT mesh aggregation (mudra place) | two nodes with known loci produce RTT evidence that `mudra::place` accepts; a path whose RTT is below the light-time floor is flagged; the controller leaves slow start in one RTT on a 2-second emulated link where cubic takes >10 | emulated-delay test matrix (10 ms, 200 ms, 2 s, 20 min with custody) | +1,500 · 3 weeks, after 3 and 5 | — |
| 9 | custody | `custody` module: signals accepted for forwarding are held until a path confirms delivery; dark paths are retried on reconnect; streams resume by particle range; integrates with foculus's delay-tolerant regime | the bundle semantics (foculus) | a 4-node chain with one link dark for 10 minutes still delivers every signal once the link returns, with no duplicates past dedupe | partition case of the network gate | +800 · 2 weeks | 34, network gate |

order: 1 → 2 → 3 → 5 → 4 → 6 → 7 → 8 → 9. steps 1–3 and 5–6 are phase-1 material (rows 21, 22, 34, 39, 42); 4 is the two-machine milestone; 7–9 are the design target and can land in the canary.

exit state: `radio` = endpoint · paths · relay · observe · gossip · stream · fetch · custody, ~14K own lines, cyber-bao beside it, quinn and nettools as vendored dependencies, ~80 crates, one of everything.

see `soft3/roadmap/component-boundaries.md` · `soft3/specs/routing.md` · `foculus/specs/gossip.md` · `cyb/decide/wire.md` · `radio/specs/neuron-context.md` · `cyber/launch.md` §critical dependencies 3
