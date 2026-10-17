# Finite acceptance map

All assertions are source-bound; expected roots, offsets, schedules and tree shape
precede the implementation. The initial 17 materialized seed carriers total 107086
bytes. Sixteen are valid finite carriers; the last is a synthetic maximum-depth
prefix, not a witnessed complete huge file. Malformed runtime variants are explicit
mutations in the full test source, not separately materialized in that seed count.

- `proof.rs`: literal schedules, whole-group coordinates, request intersection,
  pointer identity, two independent cursors, terminal output, external quotas,
  total exhaustion, cancellation, interleaved jobs, view/cursor retention and Debug.
- `proof_failures.rs`: geometry/error precedence, all canonical-word positions,
  short headers, every truncated prefix of selected carriers, parent/leaf errors,
  strict suffix rejection, terminal stickiness, grouped ROOT and absolute counters,
  all BlockSize logs, deepest finite prefix and largest-width setup, exact Display.
- `proof_allocation.rs`: observer positive control, successful verification/output,
  terminal polls and cancellation; EOF failure and constructor geometry failure.
  Other error branches are verified functionally, without an allocator observation
  claim. Fixture allocation and destruction happen outside the observed interval.
- `seals/src/bin/*`: positive runtime control plus private fields E0451, private
  constructor E0624, raw conversion E0277, DeserializeOwned and Deserialize<'static>
  E0277, proof drop E0505, proof mutation E0502 and immutable leaf mutation E0594.
  Exact compiler classes are asserted; generic compile failure alone is insufficient.
- `interleaved-oracle/`: independently assembled four-leaf carrier from committed
  kernels, never a traversal/encoder/verifier. Its parent pair after two payloads
  exercises resumed frontier state and replay offsets. Original adapter manifest's
  73 output actions includes its planned copy work; Radio emits six iterator items.

Negative compiler API absence on b933 is recorded separately from actual legacy
carrier runtime observations on a96d. Original tests-first and intermediate source
freezes are preserved. The final tests-only interleaved witness has its own source
bridge and focused debug/release results; earlier broad counts keep their 17-test
source epoch and are not relabeled as runs of the expanded corpus.
