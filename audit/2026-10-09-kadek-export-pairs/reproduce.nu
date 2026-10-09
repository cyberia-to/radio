# Full exact source archives; working-tree files are never dependency inputs.
def checked [action: closure] {
    let r = (do $action | complete)
    if $r.exit_code != 0 { error make {msg: $"exit ($r.exit_code)\n($r.stderr)\n($r.stdout)"} }
    $r.stdout
}

def record [run: path, name: string, args: list<string>] {
    let started = (date now)
    let program = ($args | first)
    let rest = ($args | skip 1)
    let r = (with-env {RUSTFLAGS: '-Dwarnings', RUSTDOCFLAGS: '-Dwarnings', RADIO_EXPORT_PAIRS_FIXTURE_DIR: $run} {
        run-external $program ...$rest | complete
    })
    let stem = ($run | path join logs $name)
    $r.stdout | save $"($stem).stdout"
    $r.stderr | save $"($stem).stderr"
    {command: $"RUSTFLAGS=-Dwarnings RUSTDOCFLAGS=-Dwarnings ($args | str join ' ')",
        cwd: $env.PWD, started: $started, ended: (date now), exit: $r.exit_code}
        | to json | save $"($stem).json"
    print $"($name): exit ($r.exit_code)"
    $r
}

def export-radio [repo: path, revision: string, archive: path, dir: path] {
    let top = (checked { ^git -C $repo ls-tree --name-only $revision } | lines | where $it != 'nettools')
    let net = (checked { ^git -C $repo ls-tree --name-only $"($revision):nettools" }
        | lines | where $it != 'target' | each { $"nettools/($in)" })
    checked { ^git -C $repo archive --format=tar --output $archive $revision ...($top | append $net) } | ignore
    mkdir $dir
    checked { ^tar -xf $archive -C $dir } | ignore
}

def verify-files [dir: path, freeze: path] {
    for source in (open $freeze) {
        let file = ($dir | path join $source.path)
        let actual = (checked { ^git hash-object $file } | str trim)
        if $actual != $source.blob or (open --raw $file | hash sha256) != $source.sha256 {
            error make {msg: $"reviewed source mismatch: ($source.path)"}
        }
    }
}

def finish [run: path] {
    let outcomes = (glob ($run | path join logs '*.json') | each {|p|
        open $p | insert name ($p | path parse | get stem)
    } | sort-by name)
    $outcomes | to json | save --force ($run | path join outcomes.json)
    print ($outcomes | select name exit)
    print $"Evidence retained at ($run); nonzero gates remain red."
    $outcomes
}

def main [
    --radio-repo: path = "~/cyber/radio"
    --hemera-repo: path = "~/cyber/hemera"
    --implementation-revision: string = "62e7f53f237ceaf0f5037a396e79ff70f2c735cd" # Override must match the frozen source.
    --fetch # Fetch locked identities if caches are incomplete; never regenerate a lock.
    --prepare-only # Verify archives, source freezes, locks and metadata without compiling.
    --api-smoke # Extra base-vs-candidate API smoke; tool uses an unlocked scratch resolution.
] {
    let receipt = $env.FILE_PWD
    let repo = ($radio_repo | path expand)
    let hemera = ($hemera_repo | path expand)
    let base = '764d732ac38fb9116c4cf525a6d1bb463d409a06'
    let tag = 'f2b1298daa9f635c821d53996c4d1dc4f1042b3d'
    let hemera_rev = '23f3bbcff910ea6d504ceb505680a539260869da'
    let lock = '8ea933dfbb9aec54002213be4883b9829112b7c4'
    let run = (checked { ^mktemp -d /tmp/radio-export-pairs-replay.XXXXXX } | str trim)
    mkdir ($run | path join logs)
    print $"Exported inputs and logs: ($run)"
    cd $receipt
    checked { ^shasum -a 256 -c SHA256SUMS } | save ($run | path join receipt-check.txt)
    checked { ^rustc -Vv } | save ($run | path join rustc.txt)
    checked { ^cargo -Vv } | save ($run | path join cargo.txt)
    checked { ^git -C $hemera archive --format=tar --output ($run | path join hemera.tar) $hemera_rev } | ignore
    let implementation = (checked { ^git -C $repo rev-parse $"($implementation_revision)^{commit}" } | str trim)
    checked { ^git -C $repo merge-base --is-ancestor $base $implementation } | ignore
    {radio_base: $base, candidate_archive: $implementation,
        candidate_overlay: null,
        hemera: $hemera_rev, tag: $tag} | to json | save ($run | path join sources.json)
    for item in [{scope: baseline, rev: $base} {scope: candidate, rev: $implementation} {scope: tag, rev: $tag}] {
        let root = ($run | path join $item.scope)
        export-radio $repo $item.rev ($run | path join $"($item.scope)-radio.tar") ($root | path join radio)
        mkdir ($root | path join hemera)
        checked { ^tar -xf ($run | path join hemera.tar) -C ($root | path join hemera) } | ignore
    }
    let inputs = (open ($receipt | path join source-inputs.json))
    for item in [{file: baseline-radio.tar, sha: $inputs.radio_archive_sha256}
        {file: hemera.tar, sha: $inputs.hemera_archive_sha256}] {
        if (open --raw ($run | path join $item.file) | hash sha256) != $item.sha {
            error make {msg: $"archive mismatch: ($item.file)"}
        }
    }
    checked { ^shasum -a 256 ...(glob ($run | path join '*.tar')) }
        | save ($run | path join archive-sha256.txt)
    let candidate = ($run | path join candidate radio)
    let baseline = ($run | path join baseline radio)
    checked { ^git -C $baseline apply --check ($receipt | path join source.patch) } | ignore
    verify-files $candidate ($receipt | path join SOURCE-FREEZE.json)
    mkdir ($baseline | path join iroh-blobs src api blobs export_pairs)
    for path in ['iroh-blobs/src/api/blobs/export_pairs.rs' 'iroh-blobs/src/api/blobs/export_pairs/support.rs'] {
        cp ($candidate | path join $path) ($baseline | path join $path)
    }
    checked { ^git -C $baseline apply ($receipt | path join red-module.patch) ($receipt | path join red-test-imports.patch) } | ignore
    verify-files $baseline ($receipt | path join red-source-freeze.json)
    for scope in [baseline candidate tag] {
        let root = ($run | path join $scope)
        cd ($root | path join radio)
        let expected = if $scope == 'tag' { 'e10b128ee7148d7273756ae6e4d1ef06c4ff1ff1' } else { $lock }
        if (checked { ^git hash-object Cargo.lock } | str trim) != $expected {
            error make {msg: $"($scope) committed lock mismatch"}
        }
        if $fetch { record $run $"($scope)-fetch" [cargo fetch --locked] | ignore }
        let meta = (record $run $"($scope)-metadata" [cargo metadata --format-version 1 --all-features --offline --locked])
        if $meta.exit_code != 0 {
            if $scope != 'tag' { finish $run | ignore; error make {msg: 'metadata prerequisite failed; see logs'} }
        } else {
            let local = ($meta.stdout | from json | get packages | where source == null | select name version manifest_path)
            let prefix = $"($root | path expand)/"
            if ($local | any {|p| not ($p.manifest_path | path expand | str starts-with $prefix) }) {
                error make {msg: $"($scope) local dependency escaped isolated source root"}
            }
            $local | to json | save ($run | path join $"($scope)-local-packages.json")
        }
    }
    if $prepare_only { finish $run | ignore; return }
    cd $baseline
    for item in [{name: red-debug, extra: []} {name: red-release, extra: [--release]}] {
        let args = ([cargo test --manifest-path iroh-blobs/Cargo.toml --lib export_pairs]
            | append $item.extra | append [--offline --locked])
        let r = (record $run $item.name $args)
        let panic = 'copy_from_slice: source slice length (32) does not match destination slice length (64)'
        if $r.exit_code != 101 or not ($r.stdout | str contains $panic) or not ($r.stdout | str contains '3 passed; 8 failed') {
            finish $run | ignore
            error make {msg: $"($item.name) did not reproduce the actual expected panic"}
        }
    }
    for scope in [baseline candidate] {
        cd ($run | path join $scope radio)
        for item in [{name: clippy, extra: []} {name: clippy-primary, extra: [--no-deps]}] {
            record $run $"($scope)-($item.name)" ([cargo clippy --manifest-path iroh-blobs/Cargo.toml --all-features --all-targets]
                | append $item.extra | append [--offline --locked -- -D warnings]) | ignore
        }
    }
    cd $candidate
    for item in [{name: debug, extra: []} {name: release, extra: [--release]}
        {name: none, extra: [--no-default-features]} {name: all, extra: [--all-features]}] {
        let r = (record $run $"focused-($item.name)" ([cargo test --manifest-path iroh-blobs/Cargo.toml --lib export_pairs]
            | append $item.extra | append [--offline --locked]))
        if $r.exit_code != 0 or not ($r.stdout | str contains '11 passed; 0 failed') {
            finish $run | ignore
            error make {msg: $"focused-($item.name) failed; see logs"}
        }
    }
    for file in [right-proof.bin right-root.txt] {
        checked { ^cmp ($receipt | path join $file) ($run | path join $file) } | ignore
    }
    record $run docs [cargo doc --manifest-path iroh-blobs/Cargo.toml --all-features --no-deps --offline --locked] | ignore
    record $run msrv-lib-tests [rustup run 1.89.0 cargo check --manifest-path iroh-blobs/Cargo.toml --lib --tests --all-features --offline --locked] | ignore
    record $run msrv-all-targets [rustup run 1.89.0 cargo check --manifest-path iroh-blobs/Cargo.toml --all-targets --all-features --offline --locked] | ignore
    if $api_smoke {
        let parent = ($run | path join parent)
        export-radio $repo $base ($run | path join parent-radio.tar) ($parent | path join radio)
        mkdir ($parent | path join hemera)
        checked { ^tar -xf ($run | path join hemera.tar) -C ($parent | path join hemera) } | ignore
        print 'API smoke uses tool-generated scratch resolution, not the source Cargo.lock or tag.'
        record $run api-smoke [cargo semver-checks check-release --manifest-path iroh-blobs/Cargo.toml --baseline-root ($parent | path join radio iroh-blobs) --verbose] | ignore
    }
    for scope in ([baseline candidate tag] | append (if $api_smoke { [parent] } else { [] })) {
        let expected = if $scope == 'tag' { 'e10b128ee7148d7273756ae6e4d1ef06c4ff1ff1' } else { $lock }
        let path = ($run | path join $scope radio Cargo.lock)
        if (checked { ^git hash-object $path } | str trim) != $expected { error make {msg: $"($scope) lock changed"} }
    }
    verify-files $candidate ($receipt | path join SOURCE-FREEZE.json)
    verify-files $baseline ($receipt | path join red-source-freeze.json)
    let outcomes = (finish $run)
    let failed = ($outcomes | where {|r| $r.exit != 0 and not ($r.name | str starts-with 'red-') })
    print 'Broad unfinished suites are historical evidence only; this script does not launch them.'
    if not ($failed | is-empty) { exit 1 }
}
