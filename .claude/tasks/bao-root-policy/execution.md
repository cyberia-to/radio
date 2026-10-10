# Execution notes

Approved plan v3 remains frozen. Fresh Opus source-only PLAN review:
`/tmp/kadek-bao-root-policy-plan-v3-review.txt`, explicit APPROVE, session99218
exit0 (root receipt). Implementation starts from radio258724bd with exact
Hemera23f3bbcf; no commit or release is part of this handoff.

- Preserve the bounded source scan and review receipts in the final audit.
- Any additional hardcoded affected-length literal requiring change is reported
  before editing; a separate defect returns to planning, not silent scope growth.
- Collection HashSeq bodies have32*(1+children) bytes:128..2047 children place
  that body in log4's affected4097..65536 interval even if every child is small.
  Metadata above4096 bytes can independently change its key. Rebuild references.
- Consolidation preserves sync's semantics while swapping its prior
  `(backend,start_chunk,data,is_root)` order to the canonical helper order.
- New files use repository import grouping; baseline-wide formatting stays out.
- Discovered-from root-policy: existing mem.rs::import_bao Parent handling copies
  a32-byte hash into pair[..64], and print_outboard uses old128/64 strides. This
  separate width defect is recorded for follow-up, never repaired in this unit.
- Installed pinned tools and actual parent receipts supersede the review's
  historical unavailable-tool note. Gate results belong in the audit/receipts;
  source-only PLAN approval does not claim tests passed or row4 closure.
