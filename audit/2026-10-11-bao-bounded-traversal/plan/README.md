# Checked traversal PLAN evidence

Research and proposed tests only, on actual Radio parent
`a96d86e28d384cdf656aadc4282c78c0c170c102` (PR38). Production is unchanged.
The [PLAN](../../../.claude/tasks/bao-bounded-traversal/plan.md) specifies
one admitted byte range, one emitted geometric item per pending next, fixed
53-frame storage and a no_std boundary. Empty queries establish no authentication.
Proof parsing, particle/root association and legacy consumer migration remain open.

The [execution record](../../../.claude/tasks/bao-bounded-traversal/execution.md)
describes six current-parent commands: two offline lock resolutions, debug/release
legacy geometry probes, and two compile failures for the future public API.
The last two fail with E0432 and execute no test body. The legacy probe catches
panics and exits 0; its exit status establishes no correctness verdict.
All raw streams, exact arguments/environment, 26 source files, 27 primary inputs,
two frozen prospective witnesses (9 named tests) and 11 integration records are
retained. The witness files are external until PLAN approval. None is a new
candidate, repository, product or rung pass.

The readable PLAN v3 has 53 sections / 245109 bytes, SHA256
`de51738909d904d29d5a927f8b8e32ac0a2716081344f5d2fa645983fbec0510`.
The local verifier and independent root replay passed; fresh Grok PLAN review
was pending when this supplement froze. No approval or implementation is inferred.
Earlier unsubmitted oversize packets and the incomplete /tmp versus /private/tmp
wrapper attempt remain evidence, with no successful gate attributed to them.

From the repository root:

```text
nu audit/2026-10-11-bao-bounded-traversal/plan/verify.nu audit/2026-10-11-bao-bounded-traversal/plan
```

Nushell, Git and tar suffice; no checkout, Rust compilation or network is needed.
The verifier checks all object hashes, Git blob identities, PLAN reconstruction,
source/witness/command bindings, raw observations and integration receipts. It
first verifies the unchanged original dacd research capsule in the parent
directory. That historical evidence is kept separate rather than nested here;
its source epoch and independent u64 remainder check remain explicit. This is
evidence replay, not command re-execution or remote Git authenticity verification.

`evidence-index.json` maps logical paths to regular `objects/<sha256>` entries
in `evidence.tar.gz`. `capsule.json` pins sizes, counts and identities. Complete
omitted-support bodies remain retained; no omitted body is claimed reviewer-read.
Compiled targets are excluded. The original historical audit files are unchanged.
