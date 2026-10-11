# Hosted evidence disposition

Root read the [completed-job supplement](hosted/README.md), its derivation,
job summaries and verifier, then independently replayed
`nu --no-config-file audit/2026-10-11-hemera-source-pin/hosted/verify.nu audit/2026-10-11-hemera-source-pin/hosted`.
[Exact command and revision](root-hosted-replay.json),
[result](root-hosted-replay.stdout). The replay passed saved-evidence integrity
and attribution checks; it did not rerun hosted gates.

The observed checkout is the recorded synthetic merge of source
`d90a784fa6a7f410492cc6c6d5242527e221c399` onto
`a11d342594949d4ea542b26366f71d56ef21662d`, with the same tree as that source.
All production files remain at the approved source revision. This addition
contains evidence and disposition only, after the fresh CODE approval.

The introduced spelling findings concern literal paths in the evidence index;
they remain red and the original names remain intact. The other completed failures
retain their exact source/toolchain/prerequisite limits, including the unresolved
rustdoc cause. No parent run, full API pass, platform pass or green hosted CI is
inferred from unchanged source identities. Queued jobs provide no result.

Accept this ordinary source merge under the owner's existing review/fix/merge
instruction with the existing decision label and wip status. The major source
identity floor and all red/unexecuted rung, platform and release obligations
remain open. No gate setting, source policy, version, release pin or tag changes.
