# Hosted checks after source push

Source head `4da5651316382b3d5a58766074a42fa132f60330`, PR36. The workflow snapshot
was read with `gh api repos/cyberia-to/radio/actions/runs/38162657596/jobs`.
Selected complete logs and exact retrieval receipts are in hosted-checks.tar.gz;
hosted-checks.json binds their bytes. No hosted green matrix is claimed.

[Clippy job114538638257](https://github.com/cyberia-to/radio/actions/runs/38162657596/job/114538638257)
fails before compiling the source: Cargo cannot read sibling
`/home/runner/work/radio/hemera/rs/Cargo.toml`. Semver, docs, MSRV, wasm and
format jobs report the same absent sibling path; dependency policy uses the
corresponding `/github/hemera/rs/Cargo.toml` path. This checkout failure is distinct
from the local current-parent lint/compiler/docs results retained in the capsule.
The command `git diff --exit-code bc8b6331 HEAD -- .github Cargo.toml Cargo.lock
iroh-relay/Cargo.toml` at the source head exits0: those build inputs are unchanged.

[Codespell job114538638272](https://github.com/cyberia-to/radio/actions/runs/38162657596/job/114538638272)
exits65 with findings in existing files, including old audit logs. Searching its
complete diagnostic lines for this task/audit and the five changed source paths
finds no matches. This is a named-path observation, not a parent codespell rerun.
Self-hosted platform test jobs are queued in the captured list. The earlier PR
run was superseded by the labeled-event run; its cancellation proves nothing.

The ordinary source repair retains wip/decision accounting and the owner's
existing merge authorization. No CI settings, spending, labels that skip tests,
source, dependency, version or release input is changed to make this snapshot
look green. This note and its evidence are the only follow-up to the reviewed
source commit; subsequent head checks have their own status.
