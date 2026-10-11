# Pin the shared Hemera dependency

Serves: owner's Kadek phase-1 closure · Radio/soft3 · consumable dependency
prerequisite for bounded BAO verification, foundation row 4. Stage: draft.
Source parent Radio a11d342594949d4ea542b26366f71d56ef21662d; Hemera source
d5f0a09539360934fb32db9b2e15a91995607db6. Implementation awaits fresh
different-vendor PLAN approval. Root owns final CODE disposition/commit/merge.

## Contract and files

Every current root-workspace path-Hemera consumer resolves the same immutable
Git package. Existing std/serde behavior and all Rust source bytes remain the
same as the pinned Radio/Hemera baseline. A checkout without a sibling Hemera
directory can resolve its owning workspace. Root Cargo.lock preserves all other
dependency sources, versions and checksums. The separate FFI workspace and the
two existing registry0.1 declarations are unchanged, including their limitations.

Production files, exactly:

- Cargo.toml and Cargo.lock.
- cyber-bao/Cargo.toml; iroh-blobs/Cargo.toml; iroh-docs/Cargo.toml;
  iroh-gossip/Cargo.toml; iroh-relay/Cargo.toml; iroh-willow/Cargo.toml;
  particle/Cargo.toml; radio-cli/Cargo.toml.

Root declaration:

```toml
[workspace.dependencies]
hemera = { package = "cyber-hemera", git = "https://github.com/cyberia-to/hemera", rev = "d5f0a09539360934fb32db9b2e15a91995607db6", default-features = false }
```

Seven inheritors use `hemera = { workspace = true, features = ["std"] }`.
iroh-blobs uses `features = ["std", "serde"]`. Existing cyber-bao serde
forwarding stays as-is. No reducer, no_std module gating, Hash API, source code,
test source, specification, component version or release pin changes in this unit.
Research/PLAN/execution/review and a compact audit are the only additional files.

## Steps and checks

1. Freeze actual parent, rules, registry, full ten production inputs, all
   owning/direct-consumer manifests and relevant concrete Hash consumers.
   Preserve the published-package comparison and successful exact Git resolution
   receipt. Export parent Radio and Hemera from named Git objects, excluding only
   tracked nettools/target with an explicit inventory; never build the original
   shared trees. Export a separate unchanged Radio baseline without the sibling
   Hemera directory → verify: ordinary locked Cargo metadata fails at the missing
   Hemera manifest before the fix; retain full exact command/raw error. This is
   the failure-first source-delivery witness, not a codec/hash failure.

2. After PLAN approval, apply the ten manifest/lock edits above. Resolve without
   an adjacent Hemera directory, using installed Rustup1.95 and the committed
   lock. Permit only the necessary lock update, then use --locked --offline for
   subsequent gates → verify: metadata succeeds; one Git cyber-hemera0.3.1 ID
   reaches all eight inheritors; the expected std/serde edges exist; registry0.1.2
   stays distinct; no source requires the adjacent sibling. Every downloaded Git
   package file matches the exact Hemera commit, not merely its version string.

3. Compare baseline and candidate metadata under default, no-default and all
   features, including each owning manifest as needed to avoid feature unification
   masking a missing std edge → verify: map the single 0.3.1 path ID to the new
   exact Git ID, and compare the graph/features. The only intentional feature
   marker removal is default, whose pinned expansion is exactly std. Preserve
   cfg-relevant std/serde. Freeze all non-Hemera package IDs, sources, versions and
   checksums. Record any Cargo-generated lock difference precisely; unexplained
   unrelated changes block implementation completion.

4. Run the real existing independent BAO/consumer checks on exact candidate
   sources: `cargo test -p cyber-bao --all-features --locked --offline` and
   `cargo test -p cyber-bao --release --all-features --locked --offline`;
   owning iroh-blobs lib tests with filters root_policy, export_pairs, parent_pairs
   and empty_root (`cargo test --manifest-path iroh-blobs/Cargo.toml --lib
   --locked --offline <filter>`); checks/tests for actual particle, radio-cli,
   iroh-docs and radio-integration-tests package IDs found by metadata. Compiler
   checks cover all eight inheritors and native transitive consumers → verify:
   canonical/old-root literal distinction, existing real Hash exchange and store
   controls remain correct. Use exact same commands on the pinned path-Hemera
   parent for any failure; preserve unknown/different causes. Do not write a
   duplicate algorithm or a mock to replace a real consumer.

5. Run scoped strict Clippy and documentation, current-parent and last-tag
   semver checks with separate fresh helper targets/locks, then repository gates
   from the pinned workflow below → verify: exact current Rust sources are
   unchanged; candidate and parent source/command identities are retained; all
   required reds remain red. API diagnostic compares default and nondefault
   owner surfaces; source identity escaping in public Hash conversions is an
   explicit compatibility boundary even if rustdoc comparison reports green.
   Never turn an inconclusive tool result into a pass. Add a small compile probe
   of the existing public Hash exchange using a separately declared path Hemera:
   unchanged parent must compile, candidate must expose the intentional distinct
   Git/path type mismatch. This is a compatibility witness, not an algorithm
   test or a reason to change sibling manifests. A newly failing real dependent
   remains introduced unless the exact parent reproduces the same failure.

6. Freeze the dependency delta and bounded CODE input with complete changed
   manifests/lock, direct consumer contracts, source/feature comparison, ordinary
   witness and final outputs. Obtain fresh different-vendor CODE review; retain
   unedited verdict and invocation. Assemble lossless compact audit and Nu
   verifier → verify: exact command/source reconstruction, no dirty input or
   unexplained lock change. Root handles any decision/wip accounting and ordinary
   PR merge. No source mutation after freeze without new review disposition.

## Repository/rung gate staging

Use explicit installed toolchain paths and record actual cargo/rustc/rustdoc
versions, environment, cwd, complete output and exit. Native stable1.95,
MSRV1.89 and workflow nightly2025-10-09 are the planned installed tools;
verify availability before use. At most two Cargo jobs, incremental disabled,
owned targets only. No toolchain install, runner fleet, paid job or broad process
kill is authorized by this plan.

Named repository controls: workspace default test compilation/runtime;
all/default/no-default nextest compilation/runtime and feature/doctest loops
from tests.yaml; format-check from Makefile.toml; strict workspace Clippy feature
matrix; MSRV `cargo +1.89 check --workspace --all-targets`; private nightly docs;
deny and semver. Use the pinned nextest0.9.80 and committed timeout configuration
when available. Start each stage with its prerequisite; a compilation failure
blocks its dependent runtime and is recorded as such. Existing source/runtime
failures get identical exact-parent counterparts; only failed runtime cases need
repeat, with the narrower comparison disclosed. Prior PR36 outputs are history,
not this candidate's gate results. Full native runs remain bounded by the
committed timeout policy. Formatter/source fixes are outside this unit.

Platform matrices (Linux/FreeBSD/Android/Wasm/Windows), minimal-versions and
netsim remain named obligations; local unexecuted checks are unverified rather
than omitted or inferred from compilation on macOS. Existing hosted codespell
and other-source errors remain visible. Do not install Python or change its
tooling as part of this manifest task. Stage storage and clean only owned,
completed target caches; keep all raw receipts before cleanup.

Radio is part_of=soft3 at fresh registry44824e6, so ring1 must include exact committed
soft3 product/direct-dependent closure, specification and kelvin gates. Inventory
and run feasible prerequisites in isolation; retain concrete missing/blocked
prerequisites, then classify dependent product gates unverified. Do not replace
them with the absence of Cargo consumers. Public dependency source/type identity
sets a major compatibility floor for path-Hash consumers; ring2 obligations remain open
unless actually run. Current soft3 has no direct Radio Cargo edge; its inspected
path cybergraph/foculus closure uses path Hemera and upstream iroh, while Cyb's
separate facade declares registry cyber-radio/Hemera and exchanges byte arrays.
That measured source boundary is not a product pass or universal downstream
absence claim. Preserve full manifests/callers, registry-only obligations and
cached/unavailable inventory limitations separately. Existing phase1 Radio and
Hemera release pins remain untouched and their drift remains visible. This unit
makes no bump, release, tag or crates.io delivery.

## Five failure questions

1. Does source pinning silently downgrade Hemera? Exact current Git source,
   file-byte verification and independent existing root literals expose it.
2. Do path and Git Hash types split across crates? Eight unified IDs and actual
   public consumer compilation expose it; separate registry/FFI boundaries stay
   visible rather than silently migrated.
3. Does std disappear in a isolated consumer or serde drift under unification?
   Per-manifest metadata/feature comparisons and default/none/all compilation
   expose it; explicit inherited std keeps the present behavior.
4. Does a general lock refresh move unrelated dependencies? Exact package/source/
   checksum diff and locked offline repeats fail unless the sole intended Hemera
   source migration is the complete change.
5. Do historical green results or source-only metadata hide actual product reds?
   Current candidate/parent receipts, named blocked prerequisites and separate
   ring status prevent that claim; fresh CODE approval alone is not a gate pass.

Rollback is an ordinary revert of this dependency unit, restoring the previous
sibling-path requirement. It changes no stored keys or payloads. The subsequent
bounded-reducer PLAN depends on this unit's reviewed source boundary; it must
retain canonical root/non-root semantics, fixed frontier, charge-before-work,
and independent partition/boundary oracles. Warm anchor and cold association
authority remain open after both units.
