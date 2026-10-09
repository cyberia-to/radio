# Replays immutable source inputs into fresh temporary workspaces; no repo writes.
def checked [action: closure] {
    let r = (do $action | complete)
    if $r.exit_code != 0 { error make {msg: $"exit ($r.exit_code)\n($r.stderr)\n($r.stdout)"} }
    $r
}

def record [run: path, name: string, command: string, action: closure] {
    let started = (date now)
    let r = (do $action | complete)
    let stem = ($run | path join logs $name)
    $r.stdout | save $"($stem).stdout"
    $r.stderr | save $"($stem).stderr"
    {command: $command, cwd: $env.PWD, started: $started, ended: (date now), exit: $r.exit_code}
        | to json | save $"($stem).json"
    print $"($name): exit ($r.exit_code)"
    $r
}

def prepare-crate [repo: path, revision: string, dir: path, receipt: path] {
    mkdir $dir
    let archive = $"($dir).tar"
    checked { ^git -C $repo archive --format=tar --output $archive $revision cyber-bao } | ignore
    checked { ^tar -xf $archive -C $dir } | ignore
    cp ($receipt | path join Cargo.toml) ($dir | path join Cargo.toml)
    cp ($receipt | path join Cargo.lock) ($dir | path join Cargo.lock)
    mkdir ($dir | path join src)
    cp ($receipt | path join probe.rs) ($dir | path join src main.rs)
    let manifest = ($dir | path join cyber-bao Cargo.toml)
    let original = (open --raw $manifest)
    if not ($original | str contains 'path = "../../hemera/rs"') {
        error make {msg: 'unexpected cyber-bao Hemera declaration'}
    }
    $original | str replace 'path = "../../hemera/rs"' 'version = "=0.3.1"' | save --force $manifest
}

def main [
    --implementation-revision: string # Required: actual committed source revision.
    --radio-repo: path = "~/cyber/radio"
    --hemera-repo: path = "~/cyber/hemera"
    --fetch # Fetch pinned dependencies when caches are incomplete; never regenerate locks.
    --full-workspace # Also export exact-source Hemera and run the broader native gates.
] {
    if $implementation_revision == null {
        error make {msg: '--implementation-revision must name the actual committed implementation'}
    }
    let receipt = $env.FILE_PWD
    let repo = ($radio_repo | path expand)
    let hemera = ($hemera_repo | path expand)
    let base = 'db1d62e2cd1e4b2f309fa19bcc158bd29b44753d'
    let hemera_rev = '23f3bbcff910ea6d504ceb505680a539260869da'
    let implementation = ((checked { ^git -C $repo rev-parse $"($implementation_revision)^{commit}" }).stdout | str trim)
    let run = ((checked { ^mktemp -d /tmp/radio-slice-replay.XXXXXX }).stdout | str trim)
    mkdir ($run | path join logs)
    print $"logs and exported inputs: ($run)"
    checked { ^git -C $repo merge-base --is-ancestor $base $implementation } | ignore
    {radio_base: $base, implementation: $implementation, hemera_source: $hemera_rev,
        hemera_registry: '=0.3.1', checksum: 'ebcf7ffcd69170adde7e792826d7cececda962ea220b9834c6535bbc71e5a6df'}
        | to json | save ($run | path join sources.json)
    (checked { ^rustc -Vv }).stdout | save ($run | path join rustc.txt)
    (checked { ^cargo -Vv }).stdout | save ($run | path join cargo.txt)
    let baseline = ($run | path join baseline)
    let candidate = ($run | path join candidate)
    prepare-crate $repo $base $baseline $receipt
    prepare-crate $repo $implementation $candidate $receipt
    for source in (open ($receipt | path join SOURCE-FREEZE.json)) {
        let actual = ((checked { ^git hash-object ($candidate | path join $source.path) }).stdout | str trim)
        if $actual != $source.blob { error make {msg: $"reviewed source mismatch: ($source.path)"} }
    }
    let original = ((checked { ^git -C $repo ls-tree -r $base cyber-bao }).stdout
        | lines | parse -r '^(?P<mode>\d+) (?P<type>\w+) (?P<blob>[0-9a-f]+)\t(?P<path>.+)$'
        | where {|p| $p.path | str ends-with '.rs' })
    if ($original | length) != 15 { error make {msg: 'unexpected original Rust inventory'} }
    for source in $original {
        let actual = ((checked { ^git hash-object ($baseline | path join $source.path) }).stdout | str trim)
        if $actual != $source.blob { error make {msg: $"baseline source mismatch: ($source.path)"} }
    }
    cd $baseline
    if $fetch { checked { ^cargo fetch --locked } | ignore }
    let probe = (with-env {RUSTFLAGS: '', RUSTDOCFLAGS: ''} {
        record $run historical-probe 'cargo run --offline --locked --bin kadek-bao-source-repro' {
            ^cargo run --offline --locked --bin kadek-bao-source-repro
        }
    })
    if $probe.exit_code != 0 { error make {msg: 'historical probe failed; see logs'} }
    checked { ^diff -u ($receipt | path join expected-probe.stdout) ($run | path join logs historical-probe.stdout) } | ignore
    (checked { ^shasum -a 256 -c ($receipt | path join FIXTURE-SHA256SUMS) }).stdout | save ($run | path join fixture-check.txt)
    with-env {RUSTFLAGS: '-Dwarnings'} {
        record $run pristine-clippy 'RUSTFLAGS=-Dwarnings cargo clippy -p cyber-bao --all-features --all-targets --offline --locked -- -D warnings' {
            ^cargo clippy -p cyber-bao --all-features --all-targets --offline --locked -- -D warnings
        } | ignore
    }
    # Copy only the independently constructed new regression onto unchanged production.
    mkdir ($baseline | path join cyber-bao tests)
    cp ($candidate | path join cyber-bao tests slice_traversal.rs) ($baseline | path join cyber-bao tests slice_traversal.rs)
    for profile in [debug release] {
        let args = if $profile == 'release' { ['--release'] } else { [] }
        let r = (with-env {RUSTFLAGS: '', RUSTDOCFLAGS: ''} {
            record $run $"red-($profile)" $"cargo test -p cyber-bao --test slice_traversal literal_right_subtree_is_authenticated ($args | str join ' ') --offline --locked" {
                ^cargo test -p cyber-bao --test slice_traversal literal_right_subtree_is_authenticated ...$args --offline --locked
            }
        })
        if $r.exit_code != 101 or not ($r.stdout | str contains 'independently constructed valid proof must decode: Truncated') {
            error make {msg: $"red-($profile) did not reproduce the expected assertion; see logs"}
        }
    }
    cd $candidate
    if $fetch { checked { ^cargo fetch --locked } | ignore }
    with-env {RUSTFLAGS: '-Dwarnings', RUSTDOCFLAGS: '-Dwarnings'} {
        for args in ([
            [test -p cyber-bao --offline --locked],
            [test -p cyber-bao --all-features --offline --locked],
            [test -p cyber-bao --all-features --release --offline --locked],
            [check -p cyber-bao --all-targets --no-default-features --offline --locked],
            [clippy -p cyber-bao --all-targets --offline --locked -- -D warnings],
            [clippy -p cyber-bao --all-targets --no-default-features --offline --locked -- -D warnings],
            [clippy -p cyber-bao --all-targets --all-features --offline --locked -- -D warnings],
            [doc -p cyber-bao --all-features --no-deps --offline --locked],
            [semver-checks check-release -p cyber-bao --baseline-root ../baseline],
        ] | enumerate) {
            record $run $"candidate-($args.index)" $"RUSTFLAGS=-Dwarnings RUSTDOCFLAGS=-Dwarnings cargo ($args.item | str join ' ')" {
                ^cargo ...$args.item
            } | ignore
        }
        record $run msrv 'RUSTFLAGS=-Dwarnings rustup run 1.89.0 cargo check -p cyber-bao --all-features --all-targets --offline --locked' {
            ^rustup run 1.89.0 cargo check -p cyber-bao --all-features --all-targets --offline --locked
        } | ignore
    }
    if $full_workspace {
        let full = ($run | path join full)
        mkdir ($full | path join radio) ($full | path join hemera)
        let top = ((checked { ^git -C $repo ls-tree --name-only $implementation }).stdout | lines | where {|p| $p != 'nettools' })
        let net = ((checked { ^git -C $repo ls-tree --name-only $"($implementation):nettools" }).stdout | lines | where {|p| $p != 'target' } | each {|p| $"nettools/($p)" })
        checked { ^git -C $repo archive --format=tar --output ($run | path join radio-full.tar) $implementation ...($top | append $net) } | ignore
        checked { ^tar -xf ($run | path join radio-full.tar) -C ($full | path join radio) } | ignore
        checked { ^git -C $hemera archive --format=tar --output ($run | path join hemera.tar) $hemera_rev } | ignore
        checked { ^tar -xf ($run | path join hemera.tar) -C ($full | path join hemera) } | ignore
        cd ($full | path join radio)
        if $fetch { checked { ^cargo fetch --locked } | ignore }
        let metadata = (record $run full-metadata 'cargo metadata --format-version 1 --all-features --offline --locked' {
            ^cargo metadata --format-version 1 --all-features --offline --locked
        })
        if $metadata.exit_code != 0 { error make {msg: 'full metadata prerequisite failed; see logs'} }
        let local = ($metadata.stdout | from json | get packages | where source == null | select name version manifest_path)
        let isolated = ($full | path expand)
        if ($local | any {|p| not ($p.manifest_path | str starts-with $isolated) }) {
            error make {msg: 'local dependency escapes isolated source root'}
        }
        $local | to json | save ($run | path join full-local-packages.json)
        with-env {RUSTFLAGS: '-Dwarnings', RUSTDOCFLAGS: '-Dwarnings'} {
            for args in ([
                [test -p cyber-bao --all-features --offline --locked],
                [check --workspace --all-features --all-targets --offline --locked],
                [test --workspace --lib --bins --tests --offline --locked],
                [make format-check], [nextest run --workspace --lib --bins --tests --offline --locked],
                [deny -D warnings check],
            ] | enumerate) {
                record $run $"full-($args.index)" $"RUSTFLAGS=-Dwarnings RUSTDOCFLAGS=-Dwarnings cargo ($args.item | str join ' ')" { ^cargo ...$args.item } | ignore
            }
        }
        record $run format-expanded 'rustup run nightly-2025-11-26 cargo fmt --all --check -- --config unstable_features=true --config imports_granularity=Crate,group_imports=StdExternalCrate,reorder_imports=true,format_code_in_doc_comments=true' {
            ^rustup run nightly-2025-11-26 cargo fmt --all --check -- --config unstable_features=true --config imports_granularity=Crate,group_imports=StdExternalCrate,reorder_imports=true,format_code_in_doc_comments=true
        } | ignore
    }
    let outcomes = (glob ($run | path join logs '*.json') | each {|p| open $p | insert name ($p | path parse | get stem) })
    $outcomes | to json | save ($run | path join outcomes.json)
    let failed = ($outcomes | where {|r| $r.exit != 0 and not ($r.name | str starts-with 'red-') and $r.name != 'pristine-clippy' })
    print ($outcomes | select name exit command)
    print $"Evidence retained at ($run). Expected red tests are not product passes; no upstream/row-4 closure follows."
    if not ($failed | is-empty) { exit 1 }
}
