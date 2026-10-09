# PR32 remote check snapshot

Observed at `2026-10-09T23:52:59Z`, head
`3c291e511cb1c5457a5bd1945c45681f263bd064`, source commit
`62e7f53f237ceaf0f5037a396e79ff70f2c735cd`, parent
`764d732ac38fb9116c4cf525a6d1bb463d409a06`.

- [CI run 38006379058](https://github.com/cyberia-to/radio/actions/runs/38006379058):
  8 completed failures, 17 queued jobs; workflow status `queued`, no conclusion.
- [Docs Preview 38006378962](https://github.com/cyberia-to/radio/actions/runs/38006378962):
  completed, `failure`; deployment and comment steps skipped.

`ci-final.json` / `docs-final.json` preserve exact API status and step results.
`classification.json` maps every job to its status, reason, URL and available log.
No job was cancelled, restarted or modified while collecting this evidence.

## Completed failures

Seven CI jobs (MSRV, wasm, cargo-deny, fmt, semver, Clippy, docs) and Docs Preview
fail because `cyber-hemera` is a sibling path dependency whose manifest is absent:
`/home/runner/work/radio/hemera/rs/Cargo.toml`, or `/github/hemera/rs/Cargo.toml`
inside cargo-deny's container. These are manifest-loading/setup failures, before
the changed exporter can compile or its tests run. Cargo-make's fmt wrapper exits
105 after metadata failure; codespell exits65; normal Cargo setup failures exit101.
The full completed-job logs are retained as `job-<id>.log`.

The relevant workflows and manifests are byte-unchanged versus the parent.
`iroh-relay/Cargo.toml:93` still declares
`hemera = { package = "cyber-hemera", version = "0.3", path = "../../hemera/rs" }`;
the observed workflows check out radio alone. This identifies an unchanged
dependency setup gap, not a test of the corrected exporter.

Codespell reports 68 findings in 16 paths. `codespell-file-comparison.json`
records exact before/after Git blobs: all 16 are identical to the parent, none is
a touched file. This includes the older traversal receipt's copied diagnostic
text. No changed Rust source or new exporter receipt path appears in this run's
codespell output. The raw log retains the actual diagnostics.

## Incomplete coverage

All 17 queued jobs request self-hosted runners in the pinned workflows: ordinary
test matrices, minimal crates, cross/Android builds and Netsim. They have no
executed steps in the snapshot. Runner availability is not inferred from this
queue; these jobs have neither passed nor failed. The CI run is incomplete.

The failure classification does not turn red jobs green or replace local gates.
It finds no executed changed-code failure in the completed remote jobs because
the source checks were blocked by setup, while the spelling findings are in
unchanged files. Later runs at another head are separate evidence and cannot
retroactively change these conclusions.

`commands.json` pins the read-only collection and comparison commands; successful
log/API retrieval has exit0 and is separate from the job conclusions above.
