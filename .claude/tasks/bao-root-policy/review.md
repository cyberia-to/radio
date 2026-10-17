# Review and merge decision

Serves Kadek foundation row 4. Exact parent is
`258724bd8ab797ad8d2ef43c6a4a2e07f1fc9e24`; final source is the eleven-file
[freeze](../../../audit/2026-10-10-bao-root-policy/source-freeze.json), SHA256
`9ce51f8d84e5f6e9f601f5979cb36d99b65af5966300ec646c952fdbf3d0b886`.
The draft-stage wording in the frozen research/plan is historical.

Fresh different-vendor Opus PLAN v3 and CODE reviews both returned APPROVE.
Their complete verdicts and source-pack inventories are retained in the
[audit](../../../audit/2026-10-10-bao-root-policy/README.md). Root independently
verified every packed artifact/source hash and unchanged Git pin, read the
production diff and tests, and verified the archived raw gate streams.

CODE's witness-count finding is resolved by a source-exact annotation: the
parent witness contained six default tests; the final source adds one non-root
control and rewrites one assertion equivalently. That extra test is not claimed
as an executed parent pass or a failure-first witness. The annotation retains
both source hashes and the exact diff. No tested source changed after approval.

The audit explicitly carries CODE's two validation limits: the unfiltered native
library suite was not rerun after its prior failed/hanging run, so an unreviewed
affected-length literal remains a risk; baseline Clippy errors prevent a complete
all-target lint certificate for the added tests. Cosmetic doc/module placement
and fixture-literal comments were not used to expand the frozen patch.

This correction changes existing keys for the affected complete-file lengths.
The audit gives the exact interval and independent old/new literals, requires
reconstruction of dependent records from complete bodies, and describes rollback
limits. No alias, live deployment migration, version, pin or release is included.

Owner authorization to implement, review, fix and merge covers this ordinary
source correction. The PR is a `decision`: required broad gates are still red,
and the source commit is `wip:` with the first actual error. Selected tests and
API gates pass as recorded; neither radio nor Kadek phase/rung closure follows.
MemStore pair width, empty-root identity, persisted checksums, bounded proofs and
authenticated particle/root/length binding remain distinct follow-up work.
