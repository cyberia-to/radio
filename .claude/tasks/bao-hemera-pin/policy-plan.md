# Hemera source-policy amendment

Serves: the approved Hemera source pin · Radio/soft3 · Kadek foundation row 4
prerequisite. Source parent remains Radio a11d3425; the ten manifest/lock files
retain their current frozen bytes and Hemera d5f0a095. Fresh PLAN review is
required before editing the additional production file, deny.toml.

The actual current candidate `34-deny` and unchanged parent `34-deny-parent`
both exit13. The candidate introduces a source-not-allowed diagnostic for
Hemera's Git repository; this is a new failure, not inherited policy debt.
Current deny.toml lists only the existing Quinn source. No source policy has
been edited yet. Exact paired commands, environments and unmodified streams
are retained in the amendment pack.

The proposed complete production extension is one line inside sources.allow-git:

```toml
  "https://github.com/cyberia-to/hemera",
```

The installed binary reports cargo-deny0.18.9. Its released annotated tag peels
to 8d76e7e991107da82c4a59cdc362a2739539f55d; exact primary source and docs are
frozen from that revision. Config allow_git is a list of strings and marks
entries exact; the matcher compares host and normalized path. A repository's
`.git` suffix and trailing slash are normalized. The matcher does not enforce
the revision query, scheme, port or fragment. Therefore this entry authorizes
that repository, not a revision. The existing immutable Cargo rev and exact
lock source continue to select d5f0a095. Adding a rev query to the allowlist
would not strengthen that contract. required-git-spec is a global minimum
specifier class, not a per-repository revision constraint; changing it would
also affect unrelated existing sources and is outside this amendment.

Primary implementation: [configuration](https://github.com/EmbarkStudios/cargo-deny/blob/8d76e7e991107da82c4a59cdc362a2739539f55d/src/sources/cfg.rs),
[source check](https://github.com/EmbarkStudios/cargo-deny/blob/8d76e7e991107da82c4a59cdc362a2739539f55d/src/sources.rs),
[URL matching and normalization](https://github.com/EmbarkStudios/cargo-deny/blob/8d76e7e991107da82c4a59cdc362a2739539f55d/src/lib.rs).

1. Review the original approved PLAN/verdict, frozen ten-file delta, complete
   current deny.toml, primary matching implementation and paired new-red evidence
   → verify: approval applies to adding only this repository allowlist entry.
2. After approval add that one line, retaining every other policy byte
   → verify: only the eleventh file is added to the production scope; lock,
   manifests, Rust source, tool version and exact Hemera revision are unchanged.
3. Repeat the same candidate full cargo-deny command, locked/offline, with the
   same cached advisory inputs. Also run its sources-only check with warnings
   denied → verify: the Hemera source-not-allowed block disappears, the source is
   actually encountered, and unrelated source/license/advisory failures remain
   visible. Compare diagnostic categories and source identities with the retained
   pre-amendment candidate; do not infer a clean full policy gate from one repair.
4. Freeze the eleven-file final delta and fresh CODE pack → verify: prior
   non-policy gates retain identical manifest/lock/Rust inputs; any later source
   edit requires its relevant checks. Root owns CODE review and decision/wip
   disposition, commit and ordinary merge. No tag, bump, release or publication.

Failure checks: a broad organization/wildcard exception is forbidden; the exact
repository entry must be encountered; revision enforcement stays in Cargo rather
than falsely attributed to the allowlist; a new failure stays new until paired
evidence explains it; existing unrelated reds stay reported. Ring1/ring2 remain
unverified and the intentional path/Git Hash major floor is unchanged. This
amendment neither changes Hemera's license nor treats its existing license-field
diagnostics as solved. Rollback reverts the one allowlist line together with the
dependency pin through ordinary history.
