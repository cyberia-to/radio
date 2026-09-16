# Transport and neuron authority

Radio retains the selected iroh endpoint/session/content profiles. An endpoint
public key identifies transport; it is not automatically a native NeuronId or
the identity of every robot/prog using that endpoint. Several subjects may share
one device, and one subject may use several endpoints under explicit bindings.

An application dialect carries subject domain, destination network, prog/task
references where needed, exact payload and current authority evidence. The
receiving application verifies that statement under the network/profile it
expects. Transport authentication, a discovery entry and possession of a content
CID establish none of those application permissions. Device/worker replacement
must respect the current writer generation; gossip/CRDT convergence does not
fence an old signer or authorize replay of an unknown external effect.

The current signed native client uses the versioned soft3 HTTP adapter and its
exact receipt/idempotency contract. A future radio adapter must carry the same
subject/context semantics and declare its own negotiated dialect before writes.
This migration does not rename upstream iroh/CID fields or change hash/wire
profiles. A record called a storage cell, a table cell or std::cell remains so.
See [consumer contracts](../../soft3/specs/identity-consumers.md).
