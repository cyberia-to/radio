---
alias: soft3 internet, the soft3 internet, native wire, post-ip internet
tags: cyber, radio, soft3, article
crystal-type: pattern
crystal-domain: cyber
status: draft
date: 2026-10-08
---

# the soft3 internet

> the internet moves bytes between addresses. the soft3 internet moves knowledge between minds, and the wire obeys the graph.

the internet was built on one decision in 1974: a packet carries a destination address, and routers forward it there. everything since — TCP, TLS, DNS, NAT, CDNs, QUIC — repairs a consequence of that decision. addresses are not identities, so we bolted on certificates. addresses are not names, so we bolted on DNS. addresses are not content, so we bolted on caches that lie. a packet proves nothing about itself, so the transport must deliver every byte in order and the application must trust the pipe. a connection must exist before a byte means anything, so every exchange begins with a round trip to agree who is talking.

[[cyber]] made a different first decision: a particle is the hash of its bytes, a neuron is a key, a cyberlink is a signed claim between particles, and the graph of those claims is the only name space. from that decision a different wire follows — not as a feature, as a consequence. this page describes it.

---

## the four replacements

| the internet | the soft3 internet | why it follows |
|---|---|---|
| address → ip:port | address → neuron or [[particle]] | a neuron publishes where it answers as cyberlinks on its own book: ANTENNA, SOCKET, LOCUS. "no address book, no peer list, no config: the routing table is the graph" |
| route → a table in every router, converged by a protocol | route → the [[locus]]: a proven coordinate; forward greedily toward the target's locus over FOLLOW links | a geometric metric needs no table and no convergence; state per node is O(degree); a sybil sits on the rim where nobody forwards to it |
| reliability → the transport delivers every byte, in order, acknowledged by offset | reliability → every chunk verifies against its particle; a receiver asks again for what it lacks, from anyone who holds it | when a byte proves itself, order is a property of the data (signals carry `prev` and `step`), and loss is a missing chunk, not a broken pipe — reliability is reconciliation |
| security → a TLS handshake between two addresses, then a stream | security → integrity by hash, confidentiality at the payload ([[mudra]] seal, veil), one post-quantum key exchange per pair for the wire itself | the wire has nothing to authenticate: the data does that. it only needs to be opaque to a watcher between two neurons |

and one addition the internet never had: a reason to forward. a forwarder emits a signed receipt for every chunk it carries, and receipts are paid in [[focus]]. caching and forwarding are not charity; they are the mining of the network layer.

---

## how it works, in one page

two packet kinds. an interest names what is wanted: a particle, a byte range, a hop budget, the best distance seen so far, the nodes visited. data answers it: a chunk and its proof path in the [[hemera]] tree. a signal is a third, carrying a cyberlink frame; a place frame carries a timing challenge; a receipt carries a forwarder's signature. all of them are [[tade]] frames the size of a datagram. there is no connection, no stream, no acknowledgement.

a request is the first packet. a neuron that wants a particle sends an interest toward whoever is likeliest to hold it — the neuron whose book references it, or the nearest locus that answered before. any node on the way that holds the range answers; the interest stops there. the answer is verified at the chunk, where it lands, on the accelerator that will read it. latency is the distance to the nearest copy.

forwarding is geometry. a node holds the loci of the neurons it follows and nothing else. an interest moves to the neighbour whose locus is closest to the target's; at a local minimum it falls back to gravity-pressure — the direction of more focus — and stops after 2·log₂N hops. no float enters the decision; comparisons are fixed point. a sybil that lies about its locus is caught by place frames: a challenge nobody can answer faster than light, with both signatures on the measured round trip.

the pair channel is one exchange. two neurons that talk often agree one shared secret through a post-quantum key encapsulation and encrypt every datagram after that with an authenticated cipher, rekeying by counter. no certificate, no handshake state machine, no key levels. the channel protects against a watcher; it grants nothing, because transport authentication grants nothing anywhere in cyber.

custody is how the dark is crossed. an interest a forwarder accepts is held until a path confirms delivery; data waits for the path. a path that has gone quiet is dark, not dead. this is what the internet's transports cannot do and what light-minutes require: between planets nothing is promised, so nothing times out, and a cache en route is the point rather than a trick.

---

## what it gives

- zero round trips before the first useful byte, for anything public.
- every fetch from the nearest copy, from several sources at once, verified chunk by chunk.
- no head-of-line blocking, because there is no line.
- no routing protocol, no convergence time, no table that grows with the network: a coordinate and a comparison.
- a network that works across light-minutes with the same code it runs across a room.
- post-quantum by construction: hashes and one lattice exchange, no curves anywhere on the wire.
- an economy on the wire: proven latency prices relays, proven forwarding earns focus, and the wire's honesty is measured the way the graph's is.

---

## what it does not pretend

it runs over the internet first. in that era it rides UDP, and the one thing the old world still forces — reaching a peer behind NAT — is done by the QUIC-era module, [[radio]], kept transmit-only so it can be lifted out later. leaving IP physically needs links we own, and that is a later chapter.

its rate control is a hypothesis. pressure as flow control is specified as a routing fallback and not yet as a law that behaves on a shared link next to someone else's TCP. that measurement comes before the old transport is removed.

its keystone is not built. the locus — a proven coordinate per neuron — is a specification. without it greedy forwarding is flooding. place frames are the measurement; locus is the number; everything above waits on them.

---

## the lineage, named

this is named-data networking with three things it never had: a routing metric that does not need a name table (the locus), an incentive to carry and cache (receipts in focus), and a name space nobody owns (the cybergraph). it is bittorrent's reliability model with proofs instead of trust. it is wireguard's idea of a channel with a post-quantum exchange. it is the delay-tolerant bundle model with a convergence layer of its own. none of the parts are new. the decision that lets them fit — a particle is its own authority, a neuron is its own address, the graph is the route — is.

see [[soft3-radio]] for the module and the order of work · `soft3/specs/routing.md` for the forwarding rule · `mudra/specs/place.md` for the timing proof · `foculus/specs/gossip.md` for the signal path · `cyber/litepaper.md` for the money the wire carries
