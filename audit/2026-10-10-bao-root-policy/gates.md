# Actual source-overlay gate receipts

Snapshot generated 2026-10-10 01:43:39 UTC. Local implementation, no source commit/release/rung claim. Exact source freeze /tmp/kadek-bao-root-policy-source-v4.json; radio parent258724bd, Hemera23f3bbcf. Version history: original candidate gates use frozen v2; v3 repeats targeted debug/release after two test cleanups. Named tools after overlay-v4 use final v4 (one blank-line removal only, no Rust token change). Production is identical in every candidate snapshot. All commands below have completed; planned gates without a receipt are unexecuted at this snapshot. Native tools now installed: nextest0.9.80, make0.37.24, deny0.18.9, CI nightly2025-10-09. Their exact parent receipts remain /tmp/radio-gate-tools/parent-installed-gates.json. No obsolete missing-tool result is promoted to current evidence.

## candidate-bao-all

Command: `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo test -p cyber-bao --all-features --locked --offline`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/candidate/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **0**. Receipt SHA256 `02433ef675acf093851ddb6ef8b987575c7b8e14058d004df9dec76e6bfa8bcd`.

- test result: ok. 71 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.35s
- test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.17s
- test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.07s
- test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

## candidate-bao-clippy

Command: `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo clippy --manifest-path cyber-bao/Cargo.toml --all-targets --all-features --locked --offline -- -D warnings`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/candidate/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **101**. Receipt SHA256 `17784ec8d1a237cf0b8f46fc6b520f186a6848fcc61476eb5ef466602c52f398`.

- error: using `clone` on type `Hash` which implements the `Copy` trait
- error: using `clone` on type `Hash` which implements the `Copy` trait
- error: using `clone` on type `Hash` which implements the `Copy` trait
- error: using `clone` on type `Hash` which implements the `Copy` trait
- error: this function has too many arguments (9/7)
- error: large size difference between variants
- error: using `clone` on type `Hash` which implements the `Copy` trait
- error: using `clone` on type `Hash` which implements the `Copy` trait
- error: using `clone` on type `Hash` which implements the `Copy` trait
- error: this `if` statement can be collapsed
- error: this `if` statement can be collapsed
- error: could not compile `cyber-bao` (lib) due to 11 previous errors
- warning: build failed, waiting for other jobs to finish...

## candidate-bao-default

Command: `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo test -p cyber-bao --locked --offline`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/candidate/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **0**. Receipt SHA256 `8fc1f556202ff6552f8ce6bc398e54513feead40c6232b71b050be2f15b5335b`.

- test result: ok. 69 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.19s
- test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.38s
- test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.08s
- test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

## candidate-bao-doc

Command: `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo doc --manifest-path cyber-bao/Cargo.toml --all-features --no-deps --locked --offline`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/candidate/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **0**. Receipt SHA256 `5c3d53da4c23ec589b89f1c242fa625530508119f89e2bb970852986f928142c`.


## candidate-bao-release-all

Command: `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo test -p cyber-bao --release --all-features --locked --offline`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/candidate/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **0**. Receipt SHA256 `9137bf5bdf05f2f05e40ebd9bc083c246ba81c167a3386b8985d8195fd828dab`.

- test result: ok. 71 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
- test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.15s
- test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
- test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

## candidate-clean-completed-before-semver

Command: `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo clean --target-dir /tmp/radio-bao-root-policy.rPXzYh/targets/candidate`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/candidate/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **0**. Receipt SHA256 `ca6148317a22e847254d707a58ba45bf9d888e0d95cbdc16f4cd399b0bf38ead`.


## candidate-clean-completed-nightly

Command: `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo clean --target-dir /tmp/radio-bao-root-policy.rPXzYh/targets/candidate-nightly-docs`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/candidate/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=``; RUSTDOCFLAGS=``. Exit **0**. Receipt SHA256 `0356445e8c587b6055ce0144e113eb3d6030fac0b69d5fa999be10b7e6f72c10`.


## candidate-clean-completed-parent-nightly

Command: `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo clean --target-dir /tmp/radio-bao-root-policy.rPXzYh/targets/parent-nightly-docs`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/candidate/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=``; RUSTDOCFLAGS=``. Exit **0**. Receipt SHA256 `b5e64096d2cf1b58ec8d3d784a9c85827513e5b971be4d72f1f18562666040ed`.


## candidate-clean-completed-release

Command: `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo clean --release --target-dir /tmp/radio-bao-root-policy.rPXzYh/targets/candidate`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/candidate/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=``; RUSTDOCFLAGS=``. Exit **0**. Receipt SHA256 `9f80169a89d0ca62423dc5e4dbe054d5d17173f8dd5b0af7e4fdfece6b0b3194`.


## candidate-consumers-no-run

Command: `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo test -p particle -p radio-cli -p radio-integration-tests --all-features --no-run --locked --offline`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/candidate/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **101**. Receipt SHA256 `8a61e478ab8665dec8bd0381d880a0c9f8a73fc450a12e367ff3733653c6c903`.

- error[E0053]: method `find_providers` has an incompatible type for trait
- error[E0308]: mismatched types
- error[E0308]: mismatched types
- error[E0271]: type mismatch resolving `<Vec<PublicKey> as IntoIterator>::Item == PublicKey`
- error[E0308]: mismatched types
- error[E0308]: mismatched types
- error[E0308]: mismatched types
- error[E0308]: mismatched types
- error[E0308]: mismatched types
- error: could not compile `iroh-docs` (lib) due to 9 previous errors
- warning: cyber-radio-relay@0.1.0: not within a suitable 'git' worktree!
- warning: cyber-radio-relay@0.1.0: VERGEN_GIT_SHA set to default
- warning: build failed, waiting for other jobs to finish...

## candidate-format

Command: `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo fmt --all -- --check`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/candidate/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **1**. Receipt SHA256 `46ceee3c6be32deef54eb9a4600955bc3afac677d96c379a6d02f84d592d45cc`.


## candidate-metadata

Command: `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo metadata --format-version 1 --locked --offline`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/candidate/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **0**. Receipt SHA256 `e418c89dad6c4abbf7fcfc4da33bafb22622d74aa6679fe8f429210ada2b2ae0`.


## candidate-msrv-bao-check

Command: `/Users/master/.rustup/toolchains/1.89.0-aarch64-apple-darwin/bin/cargo check -p cyber-bao --all-targets --all-features --locked --offline`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/candidate/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.89.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.89.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **0**. Receipt SHA256 `4e08725e6ff240ab5ba6774bee1eeda69a147a0a0701ea7684f672916f0a3904`.


## candidate-msrv-bao-root

Command: `/Users/master/.rustup/toolchains/1.89.0-aarch64-apple-darwin/bin/cargo test -p cyber-bao --test root_policy --all-features --locked --offline`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/candidate/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.89.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.89.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **0**. Receipt SHA256 `578a1f96890c6f52cd2af1db225b0e37d0d309daa7f8470665854dc5a712a19f`.

- test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.61s

## candidate-msrv-native-export

Command: `/Users/master/.rustup/toolchains/1.89.0-aarch64-apple-darwin/bin/cargo test --manifest-path iroh-blobs/Cargo.toml --lib export_pairs --locked --offline`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/candidate/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.89.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.89.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **0**. Receipt SHA256 `f549495e36d97f254a018ea3d00f8cfe041c4193db8e116da8ad8511def3063c`.

- test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured; 101 filtered out; finished in 0.57s
- warning: cyber-radio-relay@0.1.0: not within a suitable 'git' worktree!
- warning: cyber-radio-relay@0.1.0: VERGEN_GIT_SHA set to default

## candidate-msrv-native-root

Command: `/Users/master/.rustup/toolchains/1.89.0-aarch64-apple-darwin/bin/cargo test --manifest-path iroh-blobs/Cargo.toml --lib root_policy --locked --offline`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/candidate/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.89.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.89.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **0**. Receipt SHA256 `5801a11b059385607cc6c601f42a592683c0e2461cc48c81ce843459223aba4b`.

- test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 110 filtered out; finished in 0.50s
- warning: cyber-radio-relay@0.1.0: not within a suitable 'git' worktree!
- warning: cyber-radio-relay@0.1.0: VERGEN_GIT_SHA set to default

## candidate-msrv-workspace-check

Command: `/Users/master/.rustup/toolchains/1.89.0-aarch64-apple-darwin/bin/cargo check --workspace --all-targets --locked --offline`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/candidate/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.89.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.89.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **101**. Receipt SHA256 `f5919c7f103a1993e7858959df25c5648c0ccfb5e511076a57aab48ca2bf441f`.

- error[E0053]: method `find_providers` has an incompatible type for trait
- error[E0308]: mismatched types
- error[E0308]: mismatched types
- error[E0271]: type mismatch resolving `<Vec<PublicKey> as IntoIterator>::Item == PublicKey`
- error[E0308]: mismatched types
- error[E0308]: mismatched types
- error[E0308]: mismatched types
- error[E0308]: mismatched types
- error[E0308]: mismatched types
- error: could not compile `iroh-docs` (lib) due to 9 previous errors
- warning: cyber-radio-relay@0.1.0: not within a suitable 'git' worktree!
- warning: cyber-radio-relay@0.1.0: VERGEN_GIT_SHA set to default
- warning: build failed, waiting for other jobs to finish...

## candidate-named-clippy-all

Command: `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo clippy --workspace --all-features --all-targets --lib --bins --tests --benches --examples --locked --offline`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/candidate/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **101**. Receipt SHA256 `cce77b10a4190189f3222867f28fcbd460ce1bdb3eb9f899739ff7b461ec1f17`.

- error: using `clone` on type `Hash` which implements the `Copy` trait
- error: using `clone` on type `Hash` which implements the `Copy` trait
- error: using `clone` on type `Hash` which implements the `Copy` trait
- error: using `clone` on type `Hash` which implements the `Copy` trait
- error: this function has too many arguments (9/7)
- error: large size difference between variants
- error: using `clone` on type `Hash` which implements the `Copy` trait
- error: using `clone` on type `Hash` which implements the `Copy` trait
- error: using `clone` on type `Hash` which implements the `Copy` trait
- error: this `if` statement can be collapsed
- error: this `if` statement can be collapsed
- error: could not compile `cyber-bao` (lib) due to 11 previous errors
- error: consider using `sort_by_key`
- error: could not compile `cyber-radio` (lib) due to 1 previous error
- warning: cyber-radio-relay@0.1.0: not within a suitable 'git' worktree!
- warning: cyber-radio-relay@0.1.0: VERGEN_GIT_SHA set to default
- warning: build failed, waiting for other jobs to finish...

## candidate-named-clippy-default

Command: `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo clippy --workspace --all-targets --lib --bins --tests --benches --examples --locked --offline`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/candidate/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **101**. Receipt SHA256 `f8c80890ce6e78efbbed0ed3fb361464290af8576ec089128eee4db137ea2ea1`.

- error: using `clone` on type `Hash` which implements the `Copy` trait
- error: using `clone` on type `Hash` which implements the `Copy` trait
- error: using `clone` on type `Hash` which implements the `Copy` trait
- error: using `clone` on type `Hash` which implements the `Copy` trait
- error: this function has too many arguments (9/7)
- error: large size difference between variants
- error: using `clone` on type `Hash` which implements the `Copy` trait
- error: using `clone` on type `Hash` which implements the `Copy` trait
- error: using `clone` on type `Hash` which implements the `Copy` trait
- error: this `if` statement can be collapsed
- error: this `if` statement can be collapsed
- error: could not compile `cyber-bao` (lib) due to 11 previous errors
- warning: cyber-radio-relay@0.1.0: not within a suitable 'git' worktree!
- warning: cyber-radio-relay@0.1.0: VERGEN_GIT_SHA set to default
- warning: build failed, waiting for other jobs to finish...

## candidate-named-clippy-none

Command: `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo clippy --workspace --no-default-features --all-targets --lib --bins --tests --benches --examples --locked --offline`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/candidate/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **101**. Receipt SHA256 `f3e07218fa260e4811bb462cb39439fceee39f34fd5f2ae3e314ecc4a735792f`.

- error: using `clone` on type `Hash` which implements the `Copy` trait
- error: using `clone` on type `Hash` which implements the `Copy` trait
- error: using `clone` on type `Hash` which implements the `Copy` trait
- error: using `clone` on type `Hash` which implements the `Copy` trait
- error: this function has too many arguments (9/7)
- error: large size difference between variants
- error: using `clone` on type `Hash` which implements the `Copy` trait
- error: using `clone` on type `Hash` which implements the `Copy` trait
- error: using `clone` on type `Hash` which implements the `Copy` trait
- error: this `if` statement can be collapsed
- error: this `if` statement can be collapsed
- error: could not compile `cyber-bao` (lib) due to 11 previous errors
- warning: cyber-radio-relay@0.1.0: not within a suitable 'git' worktree!
- warning: cyber-radio-relay@0.1.0: VERGEN_GIT_SHA set to default
- warning: build failed, waiting for other jobs to finish...

## candidate-named-deny

Command: `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo deny --workspace --all-features --locked check --disable-fetch -Dwarnings`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/candidate/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **13**. Receipt SHA256 `ca5788e1d1ed15c499ebc749cb7b6697724f7b395f7a1ee61751eac045a49bed`.

- error[source-not-allowed]: detected 'git' source not explicitly allowed
- error[no-license-field]: license expression was not specified in manifest for crate 'cyber-hemera = 0.3.1'
- error[gather-failure]:
- error[unlicensed]: a valid license expression could not be retrieved for the crate
- error[unlicensed]: cyber-hemera = 0.3.1 is unlicensed
- error[source-not-allowed]: detected 'git' source not explicitly allowed
- error[source-not-allowed]: detected 'git' source not explicitly allowed
- error[source-not-allowed]: detected 'git' source not explicitly allowed
- error[unmatched-source]: allowed source was not encountered
- error[rejected]: failed to satisfy license requirements
- error[no-license-field]: license expression was not specified in manifest for crate 'radio-integration-tests = 0.1.0'
- error[unlicensed]: a valid license expression could not be retrieved for the crate
- error[unlicensed]: radio-integration-tests = 0.1.0 is unlicensed
- error[rejected]: failed to satisfy license requirements
- error[unsound]: Unsoundness in `Error::downcast_mut()`
- error[unmaintained]: core2 is unmaintained, all versions yanked
- error[vulnerability]: Invalid pointer dereference in `fmt::Pointer` impl for `Atomic` and `Shared` when the underlying pointer is invalid
- error[unsound]: `event-listener` allows `!Send` tags to cross thread boundaries via `StackSlot`
- error[vulnerability]: h2 unbounded empty DATA frames
- error[vulnerability]: NSEC3 closest-encloser proof validation enters unbounded loop on cross-zone responses
- error[vulnerability]: CPU exhaustion during message encoding due to O(n²) name compression
- error[unsound]: Potential use-after-free due to lack of panic safety in `LruCache::pop()`
- error[unmaintained]: proc-macro-error is unmaintained
- error[vulnerability]: Quadratic run time when checking a start tag for duplicate attribute names
- error[vulnerability]: Unbounded namespace-declaration allocation in `NsReader` enables memory-exhaustion denial of service
- error[unsound]: Rand is unsound with a custom logger using `rand::rng()`
- error[unsound]: Rand is unsound with a custom logger using `rand::rng()`
- error[vulnerability]: TLS 1.3 handshake messages incorrectly accepted across encryption level boundaries
- error[vulnerability]: CRLs not considered authoritative by Distribution Point due to faulty matching logic
- error[vulnerability]: Name constraints for URI names were incorrectly accepted
- error[vulnerability]: Name constraints were accepted for certificates asserting a wildcard name
- error[vulnerability]: Reachable panic in certificate revocation list parsing
- error[yanked]: detected yanked crate (try `cargo update -p core2`)
- error[yanked]: detected yanked crate (try `cargo update -p crypto-common`)
- error[yanked]: detected yanked crate (try `cargo update -p spin`)
- error[yanked]: detected yanked crate (try `cargo update -p spin`)

## candidate-named-format

Command: `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo make --disable-check-for-updates format-check`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/candidate/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **105**. Receipt SHA256 `68d67065af462be9c5f0c7d7516d5e5308543ffbd7a3f15cb906e8911ce6272d`.


## candidate-named-nextest-all

Command: `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo nextest run --workspace --all-features --lib --bins --tests --no-run --locked --offline`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/candidate/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **101**. Receipt SHA256 `1712b41916113ac70f044e288ef36fd95d78bbdcd2d5bbadeb2d892cc22fecd8`.

- error[E0053]: method `find_providers` has an incompatible type for trait
- error[E0308]: mismatched types
- error[E0308]: mismatched types
- error[E0271]: type mismatch resolving `<Vec<PublicKey> as IntoIterator>::Item == PublicKey`
- error[E0308]: mismatched types
- error[E0308]: mismatched types
- error[E0308]: mismatched types
- error[E0308]: mismatched types
- error[E0308]: mismatched types
- error: could not compile `iroh-docs` (lib) due to 9 previous errors
- error: command `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo test --no-run --message-format json-render-diagnostics --workspace --lib --bins --tests --all-features --locked --offline` exited with code 101
- warning: cyber-radio-relay@0.1.0: not within a suitable 'git' worktree!
- warning: cyber-radio-relay@0.1.0: VERGEN_GIT_SHA set to default
- warning: iroh-dns-server@0.96.1: not within a suitable 'git' worktree!
- warning: iroh-dns-server@0.96.1: VERGEN_GIT_SHA set to default
- warning: build failed, waiting for other jobs to finish...

## candidate-named-nightly-docs

Command: `/Users/master/.rustup/toolchains/nightly-2025-10-09-aarch64-apple-darwin/bin/cargo doc --workspace --all-features --no-deps --document-private-items --locked --offline`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/candidate/radio`. RUSTC=`/Users/master/.rustup/toolchains/nightly-2025-10-09-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/nightly-2025-10-09-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`--cfg docsrs`. Exit **101**. Receipt SHA256 `9d5cf4381020e9276d272709e8c1c2cc97afb078e989145519036e6d1e8dab03`.

- error[E0053]: method `find_providers` has an incompatible type for trait
- error[E0308]: mismatched types
- error[E0308]: mismatched types
- error[E0271]: type mismatch resolving `<Vec<PublicKey> as IntoIterator>::Item == PublicKey`
- error[E0308]: mismatched types
- error[E0308]: mismatched types
- error[E0308]: mismatched types
- error[E0308]: mismatched types
- error[E0308]: mismatched types
- error[E0433]: failed to resolve: use of unresolved module or unlinked crate `radio`
- error[E0432]: unresolved import `radio`
- error[E0433]: failed to resolve: could not find `radio` in the list of imported crates
- error[E0433]: failed to resolve: could not find `radio` in the list of imported crates
- error: could not document `iroh-bench`
- error: could not compile `iroh-docs` (lib) due to 9 previous errors
- warning: output filename collision.
- warning: cyber-radio-relay@0.1.0: not within a suitable 'git' worktree!
- warning: cyber-radio-relay@0.1.0: VERGEN_GIT_SHA set to default
- warning: iroh-dns-server@0.96.1: not within a suitable 'git' worktree!
- warning: iroh-dns-server@0.96.1: VERGEN_GIT_SHA set to default
- warning: build failed, waiting for other jobs to finish...

## candidate-native-clippy

Command: `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo clippy --manifest-path iroh-blobs/Cargo.toml --all-targets --all-features --locked --offline -- -D warnings`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/candidate/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **101**. Receipt SHA256 `eb67329a8cc86129e66011d42cb691153bd7eee41e8d698d3a0db61683f56e1e`.

- error: using `clone` on type `Hash` which implements the `Copy` trait
- error: using `clone` on type `Hash` which implements the `Copy` trait
- error: using `clone` on type `Hash` which implements the `Copy` trait
- error: using `clone` on type `Hash` which implements the `Copy` trait
- error: this function has too many arguments (9/7)
- error: large size difference between variants
- error: using `clone` on type `Hash` which implements the `Copy` trait
- error: using `clone` on type `Hash` which implements the `Copy` trait
- error: using `clone` on type `Hash` which implements the `Copy` trait
- error: this `if` statement can be collapsed
- error: this `if` statement can be collapsed
- error: could not compile `cyber-bao` (lib) due to 11 previous errors
- error: consider using `sort_by_key`
- error: could not compile `cyber-radio` (lib) due to 1 previous error
- warning: cyber-radio-relay@0.1.0: not within a suitable 'git' worktree!
- warning: cyber-radio-relay@0.1.0: VERGEN_GIT_SHA set to default
- warning: build failed, waiting for other jobs to finish...

## candidate-native-doc

Command: `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo doc --manifest-path iroh-blobs/Cargo.toml --all-features --no-deps --locked --offline`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/candidate/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **0**. Receipt SHA256 `e455634a4e5790f763ab392e287cb2fef07d1af7267032926051aa06694088fd`.

- warning: cyber-radio-relay@0.1.0: not within a suitable 'git' worktree!
- warning: cyber-radio-relay@0.1.0: VERGEN_GIT_SHA set to default

## candidate-native-export-all

Command: `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo test --manifest-path iroh-blobs/Cargo.toml --lib export_pairs --all-features --locked --offline`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/candidate/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **0**. Receipt SHA256 `83b9c5fd280e7ba71844b07b3e4b9e7e5406a0b883dbe1f3f9c4155500a86ba5`.

- test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured; 101 filtered out; finished in 0.54s
- warning: cyber-radio-relay@0.1.0: not within a suitable 'git' worktree!
- warning: cyber-radio-relay@0.1.0: VERGEN_GIT_SHA set to default

## candidate-native-export-default

Command: `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo test --manifest-path iroh-blobs/Cargo.toml --lib export_pairs --locked --offline`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/candidate/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **0**. Receipt SHA256 `e96b340e9191c760d41008ba45afad30ca7fc9e6da2d18beca65d44267ca4767`.

- test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured; 101 filtered out; finished in 0.51s
- warning: cyber-radio-relay@0.1.0: not within a suitable 'git' worktree!
- warning: cyber-radio-relay@0.1.0: VERGEN_GIT_SHA set to default

## candidate-native-export-release-all

Command: `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo test --manifest-path iroh-blobs/Cargo.toml --lib export_pairs --release --all-features --locked --offline`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/candidate/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **0**. Receipt SHA256 `c48d8a263a58b0195428fdb73cb85f06cf0c70dee65f5065c1dcf70ff722bbbd`.

- test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured; 101 filtered out; finished in 0.22s
- warning: cyber-radio-relay@0.1.0: not within a suitable 'git' worktree!
- warning: cyber-radio-relay@0.1.0: VERGEN_GIT_SHA set to default

## candidate-native-root-policy-all

Command: `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo test --manifest-path iroh-blobs/Cargo.toml --lib root_policy --all-features --locked --offline`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/candidate/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **0**. Receipt SHA256 `48b2aa9c6847e081d8f6d0e8057bccc3b4df63c015521541fe63437b64acd88a`.

- test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 110 filtered out; finished in 0.40s
- warning: cyber-radio-relay@0.1.0: not within a suitable 'git' worktree!
- warning: cyber-radio-relay@0.1.0: VERGEN_GIT_SHA set to default

## candidate-native-root-policy-default

Command: `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo test --manifest-path iroh-blobs/Cargo.toml --lib root_policy --locked --offline`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/candidate/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **0**. Receipt SHA256 `4f5ebbab5074db8ce3c72536dbe9fb51ce493be74b70171cc42280ab1df67823`.

- test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 110 filtered out; finished in 0.46s
- warning: cyber-radio-relay@0.1.0: not within a suitable 'git' worktree!
- warning: cyber-radio-relay@0.1.0: VERGEN_GIT_SHA set to default

## candidate-native-root-release-all

Command: `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo test --manifest-path iroh-blobs/Cargo.toml --lib root_policy --release --all-features --locked --offline`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/candidate/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **0**. Receipt SHA256 `9e4aaf0f5ab3ccca97a061e288a4bf3850cdf48570aefa5cdaeed17ab396e4fa`.

- test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 110 filtered out; finished in 0.26s
- warning: cyber-radio-relay@0.1.0: not within a suitable 'git' worktree!
- warning: cyber-radio-relay@0.1.0: VERGEN_GIT_SHA set to default

## candidate-right-fixture

Command: `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo test --manifest-path iroh-blobs/Cargo.toml --lib api::blobs::export_pairs::readonly_store_right_block --all-features --locked --offline -- --exact`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/candidate/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **0**. Receipt SHA256 `d31764b3d5736713171f77df8bad98b1679a161451241deab8aff50a181868e8`.

- test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 114 filtered out; finished in 0.50s
- warning: cyber-radio-relay@0.1.0: not within a suitable 'git' worktree!
- warning: cyber-radio-relay@0.1.0: VERGEN_GIT_SHA set to default

## candidate-root-policy-all

Command: `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo test -p cyber-bao --test root_policy --all-features --locked --offline`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/candidate/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **0**. Receipt SHA256 `870423a6f2461624eac48ef8b4e9b0ec5e2a631d108274348aa64ba4bf8ae816`.

- test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.56s

## candidate-root-policy-default

Command: `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo test -p cyber-bao --test root_policy --locked --offline`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/candidate/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **0**. Receipt SHA256 `2f555d7eee9e7232e866ab77f89cb878df8c846c68f917e0f1c4688dd643aff4`.

- test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.93s

## candidate-semver-parent-cyber-bao

Command: `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo semver-checks check-release --manifest-path cyber-bao/Cargo.toml --baseline-root /tmp/radio-bao-root-policy.rPXzYh/semver/parent/radio/cyber-bao --verbose`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/semver/current/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **0**. Receipt SHA256 `053268eb72597aa5e8e00b03489115272ae19affb2af0718c8d3d0d0a9867e42`.

- Checked [   0.047s] 202 checks: 202 pass, 58 skip
- Summary no semver update required

## candidate-semver-parent-iroh-blobs

Command: `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo semver-checks check-release --manifest-path iroh-blobs/Cargo.toml --baseline-root /tmp/radio-bao-root-policy.rPXzYh/semver/parent/radio/iroh-blobs --verbose`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/semver/current/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **0**. Receipt SHA256 `2633ef2f31c2f96917d4d29afca03ea01ac5ce0ea7df0ca4265f438fa79ce1b5`.

- Checked [   0.066s] 202 checks: 202 pass, 58 skip
- Summary no semver update required
- warning: cyber-radio-relay@0.1.0: not within a suitable 'git' worktree!
- warning: cyber-radio-relay@0.1.0: VERGEN_GIT_SHA set to default
- warning: cyber-radio-relay@0.1.0: not within a suitable 'git' worktree!
- warning: cyber-radio-relay@0.1.0: VERGEN_GIT_SHA set to default

## candidate-semver-tag-cyber-bao

Command: `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo semver-checks check-release --manifest-path cyber-bao/Cargo.toml --baseline-root /tmp/radio-bao-root-policy.rPXzYh/semver/tag/radio/cyber-bao --verbose`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/semver/current/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **0**. Receipt SHA256 `68b210315a2704eb5d79368edcce966a69e31f5ea2485fdb6d393a4ad9b62619`.

- Checked [   0.045s] 202 checks: 202 pass, 58 skip
- Summary no semver update required

## candidate-semver-tag-iroh-blobs

Command: `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo semver-checks check-release --manifest-path iroh-blobs/Cargo.toml --baseline-root /tmp/radio-bao-root-policy.rPXzYh/semver/tag/radio/iroh-blobs --verbose`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/semver/current/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **0**. Receipt SHA256 `0286e1a4314404a782511a09a4cdfd9032507e29f87c529aa18eb51b723f7956`.

- Checked [   0.028s] 202 checks: 202 pass, 58 skip
- Summary no semver update required
- warning: cyber-radio-relay@0.1.0: not within a suitable 'git' worktree!
- warning: cyber-radio-relay@0.1.0: VERGEN_GIT_SHA set to default
- warning: cyber-radio-relay@0.1.0: not within a suitable 'git' worktree!
- warning: cyber-radio-relay@0.1.0: VERGEN_GIT_SHA set to default

## candidate-v3-bao-all

Command: `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo test -p cyber-bao --all-features --locked --offline`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/candidate/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **0**. Receipt SHA256 `4eacda7dbf46705f75af38cd69ab8aa7be82626429133f95c140fe4c09a1c84f`.

- test result: ok. 71 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.43s
- test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.45s
- test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.17s
- test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

## candidate-v3-bao-release-all

Command: `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo test -p cyber-bao --release --all-features --locked --offline`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/candidate/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **0**. Receipt SHA256 `1422569854e182a04be5f70e17d6acf228c2103bd283fbc656d942a0458d177b`.

- test result: ok. 71 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.04s
- test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.20s
- test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
- test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

## candidate-v3-native-export-all

Command: `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo test --manifest-path iroh-blobs/Cargo.toml --lib export_pairs --all-features --locked --offline`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/candidate/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **0**. Receipt SHA256 `12ce8f6d8c769969e0feb9d3e043f37e1e516ac0fb1f46623d483bcac4a37b7b`.

- test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured; 101 filtered out; finished in 0.61s
- warning: cyber-radio-relay@0.1.0: not within a suitable 'git' worktree!
- warning: cyber-radio-relay@0.1.0: VERGEN_GIT_SHA set to default

## candidate-v3-native-export-release-all

Command: `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo test --manifest-path iroh-blobs/Cargo.toml --lib export_pairs --release --all-features --locked --offline`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/candidate/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **0**. Receipt SHA256 `ec799b34887703897a289b1ee0b798b66f089865005fbbbbb0781b04c47db9d4`.

- test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured; 101 filtered out; finished in 0.18s
- warning: cyber-radio-relay@0.1.0: not within a suitable 'git' worktree!
- warning: cyber-radio-relay@0.1.0: VERGEN_GIT_SHA set to default

## candidate-v3-native-root-all

Command: `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo test --manifest-path iroh-blobs/Cargo.toml --lib root_policy --all-features --locked --offline`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/candidate/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **0**. Receipt SHA256 `d80e3979b3dc012c16b4f5729dd16eb039d58f95fdded9ca600be5ad6911767d`.

- test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 110 filtered out; finished in 0.91s
- warning: cyber-radio-relay@0.1.0: not within a suitable 'git' worktree!
- warning: cyber-radio-relay@0.1.0: VERGEN_GIT_SHA set to default

## candidate-v3-native-root-release-all

Command: `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo test --manifest-path iroh-blobs/Cargo.toml --lib root_policy --release --all-features --locked --offline`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/candidate/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **0**. Receipt SHA256 `8e5d826b71f9e6f658ee93f69d755c8dbf6dfd30919488f67e3e3a29697d2077`.

- test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 110 filtered out; finished in 0.19s
- warning: cyber-radio-relay@0.1.0: not within a suitable 'git' worktree!
- warning: cyber-radio-relay@0.1.0: VERGEN_GIT_SHA set to default

## candidate-workspace-no-run

Command: `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo test --workspace --no-run --locked --offline`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/candidate/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **101**. Receipt SHA256 `2dfcc4b483e971a7b14ab5611e639f338a026c59ec92e74add06c4423252c8fb`.

- error[E0053]: method `find_providers` has an incompatible type for trait
- error[E0308]: mismatched types
- error[E0308]: mismatched types
- error[E0271]: type mismatch resolving `<Vec<PublicKey> as IntoIterator>::Item == PublicKey`
- error[E0308]: mismatched types
- error[E0308]: mismatched types
- error[E0308]: mismatched types
- error[E0308]: mismatched types
- error[E0308]: mismatched types
- error: could not compile `iroh-docs` (lib) due to 9 previous errors
- warning: output filename collision at /tmp/radio-bao-root-policy.rPXzYh/targets/candidate/debug/examples/transfer
- warning: output filename collision at /tmp/radio-bao-root-policy.rPXzYh/targets/candidate/debug/examples/transfer.dSYM
- warning: cyber-radio-relay@0.1.0: not within a suitable 'git' worktree!
- warning: cyber-radio-relay@0.1.0: VERGEN_GIT_SHA set to default
- warning: build failed, waiting for other jobs to finish...

## witness-clean-completed-for-candidate

Command: `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo clean --target-dir /tmp/radio-bao-root-policy.rPXzYh/targets/witness`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/witness/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **0**. Receipt SHA256 `ddfae53e407c9c73f86597ddf564ba9ad77b7cc6174b4dfcb0d326b3c524b183`.


## witness-extract-hemera

Command: `tar -xf /tmp/radio-bao-root-policy.rPXzYh/archives/hemera.tar -C /tmp/radio-bao-root-policy.rPXzYh/witness/hemera`

Cwd: `/Users/master/cyber`. RUSTC=``; RUSTDOC=``; RUSTFLAGS=``; RUSTDOCFLAGS=``. Exit **0**. Receipt SHA256 `42a2ae898807f5deca5f06e1314bb98aea4a699479f85383738a34694f5ccd6b`.


## witness-extract-radio

Command: `tar -xf /tmp/radio-bao-root-policy.rPXzYh/archives/radio.tar -C /tmp/radio-bao-root-policy.rPXzYh/witness/radio`

Cwd: `/Users/master/cyber`. RUSTC=``; RUSTDOC=``; RUSTFLAGS=``; RUSTDOCFLAGS=``. Exit **0**. Receipt SHA256 `4b9bae67d1614ac83d0f2d1f935dac69809a2a76a50b13c087a03d31e40d7d2e`.


## witness-root-policy-default

Command: `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo test -p cyber-bao --test root_policy --locked --offline`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/witness/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **101**. Receipt SHA256 `f79780a67ea87931631b1839588cef5e6e18b04e02c17b85835531813d35ac0d`.

- test result: FAILED. 1 passed; 5 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.04s
- error: test failed, to rerun pass `-p cyber-bao --test root_policy`

## witness-root-policy-stores

Command: `/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo test --manifest-path iroh-blobs/Cargo.toml --lib root_policy_ --locked --offline`

Cwd: `/tmp/radio-bao-root-policy.rPXzYh/witness/radio`. RUSTC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`; RUSTDOC=`/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustdoc`; RUSTFLAGS=`-Dwarnings`; RUSTDOCFLAGS=`-Dwarnings`. Exit **101**. Receipt SHA256 `98ecf84e4c7ad24dd32ac160db142426ed6cc0bf617b9af06c28f8377afa0562`.

- test result: FAILED. 0 passed; 3 failed; 0 ignored; 0 measured; 110 filtered out; finished in 0.30s
- error: test failed, to rerun pass `--lib`
- warning: cyber-radio-relay@0.1.0: not within a suitable 'git' worktree!
- warning: cyber-radio-relay@0.1.0: VERGEN_GIT_SHA set to default

Independent right-only fixture was re-emitted and checksum-checked by candidate-fixture.nu / candidate-right-fixture.json; it remains source-pinned: 131072-byte D, log4, canonical root9ccd2809b2bcca875ee39f2c034c80969c176a5510a66d638b2c88c3cd7c7f0f; proof65608 bytes SHA256108022aa95ee61a1058d6d4bb53979a95bc46de114b036fcc6620fbd65648a51. Existing exporter harness compares exact bytes and parser progress; support.rs literal/tree assembly was not replaced by the implementation under test. New memory-store tests independently assert list/import key2abf65dd…0190, fixed_chunk_root, Hash::new and literal LE64(8192)||D, both memory stores and FsStore inline/non-inline.

Compatibility: affected old keys/tickets remain old bytes and corrected proof verification rejects them; whole-body rebuild/reindex/reimport and references are required, no alias. HashSeq payload32*(1+children) means128..2047children are in affected log4 interval. Hash::EMPTY and mem.rs import_bao Parent32-to64 copy remain distinct existing defects. Neither bounded verification nor particle-to-root authority is implemented.

Paired diagnostic comparison (error header, file, quoted Rust lines; only line numbers stripped; compiler summaries excluded, full raw retained):

- bao-clippy: 13→11; added 0, removed 2.
- native-clippy: 14→12; added 0, removed 2.
- workspace: 9→9; added 0, removed 0.
- consumers: 9→9; added 0, removed 0.
- msrv-workspace: 9→9; added 0, removed 0.
- named-nextest: 9→9; added 0, removed 0.
- named-nightly-docs: 27→13; added 0, removed 14.

Owning Clippy remains blocked by baseline dependency diagnostics and does not certify all tests lint-clean. Workspace tests are unexecuted after compilation failure. Complete error descriptions and source identity comparison are retained in /tmp/kadek-bao-root-policy-diagnostic-comparison.json.

Additional exact comparisons: formatter340→340 per-file +/- hunks with no additions/removals; cargo-deny36→36 indexed findings with no added/removed headers/advisory/package evidence, exact unchanged lock/config and advisory DB7eebec69. Deny exit13 is a process bitmask, not a finding count. Named nightly docs: parent9 iroh-docs +18 iroh-bench compiler diagnostics; candidate9+4 iroh-bench rustdoc diagnostics, all candidate source diagnostics in parent set. This is a smaller observed failure surface, not full diagnostic parity; untouched bench/docs source bytes and full raw logs are retained. Named workspace Clippy variants expose subsets of the package baseline diagnostic set, not newly executed identical parent command receipts.

Semver0.51.0: both crates, exact parent and last tag v0.1.0, each202 checks pass/58 skip and no source-API update required. These are fresh scratch resolutions (e.g. bytes1.12.1, tokio1.53.2), not the committed-lock gate graph and not behavioral/content-identity compatibility. Separate source locks stayed unchanged. Final generated scratch manifests/locks retained under scaffold/semver-scratch-receipts/tag; the tool overwrites the same per-crate placeholder manifest when switching baseline, so these are final tag snapshots, not claimed per-stage snapshots. Radio tag uses explicitly pinned current Hemera23f3bbcf for its unversioned path; this is not a historical release closure.

Integrity: candidate-source-integrity.json checks all989 parent source files against991 candidate files; only the11 frozen whitelist paths differ, Hemera is byte-identical, lock SHA295b21c8… unchanged, git diff --check exit0. New test files268/46 lines. Source v4 is final; no commits/push/review launched by this agent.
