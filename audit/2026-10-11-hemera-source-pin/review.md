# Root disposition

Accepted for ordinary source merge under the owner's existing review/fix/merge
instruction. This is a decision/wip change with a major source-identity floor;
no version bump or release is authorized or claimed by this disposition.

Input parent: Radio a11d342594949d4ea542b26366f71d56ef21662d; Hemera
d5f0a09539360934fb32db9b2e15a91995607db6. Approved production patch SHA256:
90f284eb4083b1312334dc1eb641fe8e73cf074cd676c4ba66396e035cd41042.
Fresh Grok CODE v2 approved at 2026-10-11T21:37:19Z without blockers.
[Raw verdict](code-review.txt), [invocation](code-review-invocation.json),
[completion](code-review-completion.json). Both approved PLANs remain in the
capsule; the original task files retain their historical pre-review wording.

Root read every changed production line, both policy/implementation verdicts,
direct consumer/source contracts and the decisive gate/probe evidence. Independent
`ruby /tmp/radio-hemera-pin-code-v2/verify.rb` replay verified the current source,
complete normalized metadata parity and all 96 command records/192 streams;
[receipt](root-code-replay.json), [result](root-code-verification.json).
Independent portable `nu --no-config-file .../verify.nu ...` replay also passed;
[exact command](root-portable-replay.json), [result](root-portable-replay.stdout).
Neither replay reruns Cargo gates. Current source remained unchanged afterward.

All reviewer advice is retained: the Cargo rev/lock supplies the exact revision;
deny's URL entry permits the repository, not a revision. The Hash path/Git split
sets a major compatibility floor. The soft3 metadata failure is an external
prerequisite, not a candidate integration test. Fresh docs exit zero with warnings.
The original two tag exports are input-deviant; only corrected runs use the
verified tag input. These boundaries are explicit in [the audit](README.md).

Required broad reds and unexecuted ring/platform obligations stay open. The
source commit therefore uses wip and quotes the paired all-feature E0599 error;
the PR carries decision. No allowance or source change suppresses unrelated
dependency/license/advisory failures. Bounded BAO verification and authenticated
particle/root association are still subsequent work, so no Kadek phase closes.
