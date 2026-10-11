def ensure [ok: bool, message: string] {
    if not $ok { error make {msg: $message} }
}

def payload [c: record, name: string] {
    let found = ($c.lookup | get -o $name)
    ensure ($found != null) $'missing logical payload: ($name)'
    let row = ($found | first)
    open --raw ($c.root | path join objects $row.sha256) | into binary
}

def json [c: record, name: string] { payload $c $name | decode utf-8 | from json }
def text [c: record, name: string] { payload $c $name | decode utf-8 }

def same [c: record, name: string, digest: string] {
    ensure ((payload $c $name | hash sha256) == $digest) $'payload hash differs: ($name)'
}

def sized [c: record, name: string, row: record] {
    let body = (payload $c $name)
    ensure (($body | bytes length) == $row.bytes and ($body | hash sha256) == $row.sha256) $'payload identity differs: ($name)'
}

def git-blob [c: record, name: string, oid: string] {
    let body = (payload $c $name)
    let header = ($"blob ($body | bytes length)(char --integer 0)" | encode utf-8)
    let result = ([$header $body] | bytes collect | ^shasum -a 1 | complete)
    ensure ($result.exit_code == 0 and ($result.stdout | split row ' ' | first) == $oid) $'Git blob differs: ($name)'
}

def offset-pack [c: record, prefix: string] {
    let pack = (json $c $'($prefix)/pack.json')
    let review = (payload $c $'($prefix)/review.txt')
    sized $c $'($prefix)/review.txt' $pack.review
    for row in $pack.support { sized $c $'($prefix)/($row.path)' $row }
    for row in $pack.sections {
        let part = ($review | bytes at ($row.offset)..<($row.offset + $row.bytes))
        ensure ($part == (payload $c $'($prefix)/($row.path)')) $'inline section differs: ($prefix)/($row.path)'
    }
    $pack
}

def metadata [c: record, prefix: string] {
    let source = 'git+https://github.com/cyberia-to/hemera?rev=d5f0a09539360934fb32db9b2e15a91995607db6'
    for pair in [[default '02'] [none '03'] [all '04']] {
        let variant = $pair.0
        let parent = (json $c $'($prefix)/plan-v1/research/baseline-($variant).stdout')
        let candidate = (json $c $'($prefix)/execution/logs/($pair.1)-metadata-($variant).stdout')
        ensure ($candidate == (json $c $'($prefix)/execution/logs/44-final-metadata-($variant).stdout')) 'final full metadata bridge differs'
        let ph = ($parent.packages | where name == cyber-hemera and version == '0.3.1' | first)
        let ch = ($candidate.packages | where name == cyber-hemera and version == '0.3.1' | first)
        ensure ($ch.source == $'($source)#d5f0a09539360934fb32db9b2e15a91995607db6') 'Hemera source differs'
        mut normalized = ($candidate | to json -r)
        for pair in [[$ch.id $ph.id] [($ch.manifest_path | path dirname) ($ph.manifest_path | path dirname)] [$candidate.workspace_root $parent.workspace_root]] {
            $normalized = ($normalized | str replace --all $pair.0 $pair.1)
        }
        let value = ($normalized | from json)
        let owners = ($value.packages | where {|p| $p.dependencies | any {|d| $d.name == cyber-hemera and $d.source == $source}})
        ensure (($owners | length) == 8) 'direct owner count differs'
        for package in $owners {
            let dep = ($package.dependencies | where name == cyber-hemera and source == $source | first)
            let want = if $package.name == iroh-blobs { [std serde] } else { [std] }
            ensure ($dep.features == $want and not $dep.uses_default_features and $dep.req == '*' and ($dep | get -o path) == null) $'direct features differ: ($package.name)'
        }
        let packages = ($value.packages | each {|p|
            let old = ($parent.packages | where id == $p.id | first)
            mut out = ($p | update dependencies {|row| $row.dependencies | each {|d|
                if $d.name == cyber-hemera and $d.source == $source {
                    $old.dependencies | where name == cyber-hemera | where {|x| ($x | get -o path) != null} | first
                } else { $d }
            }})
            if $p.id == $ph.id { $out = ($out | update source null) }
            $out
        })
        let nodes = ($value.resolve.nodes | each {|n|
            if $n.id == $ph.id {
                ensure ($n.features == [serde std]) 'unified feature set differs'
                $n | update features [default serde std]
            } else { $n }
        })
        ensure (($packages | sort-by id) == ($parent.packages | sort-by id)) $'complete package parity differs: ($variant)'
        ensure (($nodes | sort-by id) == ($parent.resolve.nodes | sort-by id)) $'complete node parity differs: ($variant)'
    }
}

def main [audit: path = '.'] {
    let audit = ($audit | path expand)
    for row in (open --raw ($audit | path join SHA256SUMS) | lines | parse '{sha256}  {path}') {
        ensure ((open --raw ($audit | path join $row.path) | hash sha256) == $row.sha256) $'outer checksum differs: ($row.path)'
    }
    let index = (open ($audit | path join evidence-index.json))
    ensure (($index.path | uniq | length) == ($index | length)) 'duplicate logical path'
    ensure (not ($index.path | any {|p| $p =~ '(^/|(^|/)\.\.(/|$))'})) 'unsafe logical path'
    let objects = ($index.sha256 | uniq | sort)
    ensure (not ($objects | any {|h| not ($h =~ '^[0-9a-f]{64}$')})) 'invalid object name'
    let archive = ($audit | path join evidence.tar.gz)
    let listed = (^tar -tzf $archive | complete)
    ensure ($listed.exit_code == 0 and ($listed.stdout | lines | sort) == ($objects | each {|h| $'objects/($h)'})) 'archive inventory differs'
    let types = (^tar -tvzf $archive | complete)
    ensure ($types.exit_code == 0 and not ($types.stdout | lines | any {|s| not ($s | str starts-with '-')})) 'archive contains nonregular entries'
    let made = (^mktemp -d /tmp/radio-hemera-audit.XXXXXX | complete)
    ensure ($made.exit_code == 0) $made.stderr
    let dest = ($made.stdout | str trim)
    try {
        let extracted = (^tar -xzf $archive -C $dest | complete)
        ensure ($extracted.exit_code == 0) $extracted.stderr
        for digest in $objects {
            let file = ($dest | path join objects $digest)
            ensure (($file | path type) == file and (open --raw $file | hash sha256) == $digest) $'object differs: ($digest)'
            let size = (ls $file | get 0.size | into int)
            ensure (not ($index | where sha256 == $digest | any {|r| $r.bytes != $size})) 'object size differs'
        }
        let c = {root: $dest, lookup: ($index | group-by path)}
        let v1 = (offset-pack $c code-v1)
        let v2 = (offset-pack $c code-v2)
        ensure ($v1.review.sha256 == '0309d0d63b012474f222a4da5a6ef3bff1fce9612011b93bd5fa0b6be7d77c71' and $v2.review.sha256 == 'ac39bbd31dc6c4e34dea84ae3094f23abc46f95522a544844b375b6efa7768cf' and $v2.review.bytes < 500000) 'CODE identities differ'
        let prefix = 'code-v2'
        let original = (json $c $'($prefix)/plan-v1/pack-inputs.json')
        mut rebuilt = $"Radio shared Hemera pin PLAN v1 — exact full sections\n"
        for row in $original.sections {
            sized $c $'($prefix)/plan-v1/($row.path)' $row
            let body = (text $c $'($prefix)/plan-v1/($row.path)')
            $rebuilt += $"\n=== FILE ($row.path) | bytes=($row.bytes) | sha256=($row.sha256) ===\n($body)\n=== END FILE ($row.path) ===\n"
        }
        ensure ($rebuilt == (text $c $'($prefix)/plan-v1/review.txt') and ($rebuilt | hash sha256) == $original.review_sha256) 'original PLAN reconstruction differs'
        for row in (json $c $'($prefix)/plan-v1/omissions.json' | get files) { sized $c $'($prefix)/plan-v1/($row.path)' $row }
        let amendment = (offset-pack $c $'($prefix)/policy-plan-v1')
        same $c $'($prefix)/plan-v1/raw-review.txt' '3f83390de606e26240e1da678c3df9bbdf2f486e35f43e5ac898fefa2542a741'
        same $c $'($prefix)/policy-plan-v1/raw-review.txt' 'd0d5b4e1497c66c2f908e7890ff54b4fb6e9c4503dc0c293447ba4426ee91b3a'
        let freeze = (json $c $'($prefix)/execution/final/source-freeze.json')
        ensure ($freeze.parent == 'a11d342594949d4ea542b26366f71d56ef21662d' and $freeze.hemera == 'd5f0a09539360934fb32db9b2e15a91995607db6' and ($freeze.files | length) == 11) 'source freeze identity differs'
        for row in $freeze.files {
            sized $c $'($prefix)/execution/final/source/($row.path)' $row
            same $c $'($prefix)/execution/final/parent/($row.path)' $row.parent_sha256
            git-blob $c $'($prefix)/execution/final/parent/($row.path)' $row.parent_git_oid
        }
        same $c $'($prefix)/execution/final/source.patch' $freeze.patch_sha256
        let parent = (json $c $'($prefix)/execution/parent-freeze.json')
        ensure (($freeze.unchanged_rust | length) == 511) 'unchanged Rust count differs'
        for row in $freeze.unchanged_rust {
            sized $c $'($prefix)/execution/final/unchanged-rust/($row.path)' $row
            git-blob $c $'($prefix)/execution/final/unchanged-rust/($row.path)' $row.oid
            ensure (($parent.tree | where path == $row.path | select mode kind oid | first) == ($row | select mode kind oid)) 'Rust tree identity differs'
        }
        let rust_hash = ($parent.rust | each {|r| [$r.path $r.sha256]} | to json -r | hash sha256)
        let early = (json $c $'($prefix)/policy-plan-v1/ten-file-freeze.json' | get files | each {|r| [$r.path $r.sha256]})
        let base = ($parent.ten_files | each {|p| [$p (payload $c $'($prefix)/execution/parent/($p)' | hash sha256)]})
        let final = ($parent.ten_files | each {|p| [$p (payload $c $'($prefix)/execution/final/source/($p)' | hash sha256)]})
        let summary = (json $c $'($prefix)/execution/gate-summary.json')
        ensure (($summary.records | length) == 96) 'record count differs'
        for row in $summary.records {
            let label = $row.label
            let name = $'($prefix)/execution/logs/($label)'
            same $c $'($name).json' $row.record_sha256
            let record = (json $c $'($name).json')
            ensure ($record.exit == $row.exit and $record.argv == $row.argv) 'outcome/command differs'
            for stream in [stdout stderr] { same $c $'($name).($stream)' ($record | get $'($stream)_sha256') }
            for snapshot in [$record.source_before $record.source_after] {
                ensure ($snapshot.rust_files == 511 and $snapshot.rust_sha256 == $rust_hash) 'Rust command epoch differs'
            }
            let runner = ($record | get -o runner_sha256)
            if $runner != null { same $c $'($prefix)/execution/runners/($runner).rb' $runner } else { ensure ($label == '01-unlocked-online-resolve') 'unexpected unbound runner' }
            let expected = if $record.kind == parent { $base } else if $label =~ '^(44|45)-' { $final } else { $early }
            if $label == '01-unlocked-online-resolve' {
                let before = ($early | each {|r| if $r.0 == Cargo.lock { $base | where {|b| $b.0 == Cargo.lock} | first } else { $r }})
                ensure ($record.source_before.files == $before and $record.source_after.files == $early) 'unlocked resolve epoch differs'
            } else { ensure ($record.source_before.files == $expected and $record.source_after.files == $expected) $'source epoch differs: ($label)' }
        }
        metadata $c $prefix
        let before_lock = (text $c $'($prefix)/execution/final/parent/Cargo.lock')
        let after_lock = (text $c $'($prefix)/execution/final/source/Cargo.lock')
        let source_line = $"source = \"git+https://github.com/cyberia-to/hemera?rev=d5f0a09539360934fb32db9b2e15a91995607db6#d5f0a09539360934fb32db9b2e15a91995607db6\"\n"
        ensure (($after_lock | str replace $source_line '') == $before_lock) 'lock delta exceeds one source line'
        for path in [iroh-gossip iroh-willow] {
            let a = (text $c $'($prefix)/execution/final-bridge/($path)_Cargo.toml.before')
            let b = (text $c $'($prefix)/execution/final-bridge/($path)_Cargo.toml.after')
            ensure ($b == ($a + (char newline)) and ($a | from toml) == ($b | from toml)) 'EOF-only bridge differs'
        }
        for row in (json $c $'($prefix)/plan-v1/source-freeze.json' | get files) { git-blob $c $'($prefix)/plan-v1/($row.snapshot)' $row.git_oid }
        for row in (json $c $'($prefix)/cached-manifests.json') { git-blob $c $'($prefix)/($row.path)' $row.git_oid }
        let tag = (json $c $'($prefix)/execution/api/inputs.json')
        let correction = (json $c $'($prefix)/execution/api/tag-correction.json')
        ensure ($tag.revision == 'f2b1298daa9f635c821d53996c4d1dc4f1042b3d' and ($tag.files | length) == 854 and ($correction.deviations.path | sort) == [quinn/LICENSE-APACHE quinn/LICENSE-MIT]) 'tag epoch identity differs'
        ensure (($correction.before_actual | length) == 854 and ($correction.before_actual.path | uniq | length) == 854) 'historical full tag inventory differs'
        let corrected = (json $c $'($prefix)/execution/api/corrected-mode-verification.json')
        ensure ($corrected.exact and $corrected.entries == 854 and $corrected.records == ($tag.files | each {|r| [$r.path $r.mode $r.sha256]})) 'corrected mode/body observation differs'
        for row in $tag.files {
            sized $c $'($prefix)/execution/api/last-tag/radio/($row.path)' $row
            git-blob $c $'($prefix)/execution/api/last-tag/radio/($row.path)' $row.oid
        }
        for row in $correction.before_actual {
            let wanted = ($tag.files | where path == $row.path | first)
            ensure ($row.mode == $wanted.mode) 'historical tag mode differs'
            if $row.path in $correction.deviations.path {
                sized $c $'($prefix)/execution/api/tag-run-deviation/($row.path)' $row
            } else { ensure ($row.git_oid == $wanted.oid) 'unexpected historical tag difference' }
        }
        for name in [LICENSE-APACHE LICENSE-MIT] {
            ensure ((text $c $'($prefix)/execution/api/last-tag/radio/quinn/quinn-proto/($name)') == $'../($name)') 'literal symlink Git body differs'
        }
        for label in [40-api-last-tag-default 40-api-last-tag-none 45-api-last-tag-default 45-api-last-tag-none] {
            let record = (json $c $'($prefix)/execution/logs/($label).json')
            let raw = (text $c $'($prefix)/execution/logs/($label).stderr')
            ensure ($record.exit == 101 and ($raw | str contains 'core2')) $'API blocked result differs: ($label)'
        }
        ensure ((json $c $'($prefix)/execution/logs/9-probe-parent-check.json').exit == 0 and (json $c $'($prefix)/execution/logs/11-probe-candidate-check.json').exit == 101 and ((text $c $'($prefix)/execution/logs/11-probe-candidate-check.stderr') | str contains 'E0308')) 'major Hash source boundary differs'
        let comparison = (json $c $'($prefix)/execution/policy/comparison.json')
        let heading = "error[source-not-allowed]: detected 'git' source not explicitly allowed"
        ensure (($comparison.before_full.diagnostic_headings | get $heading) == 5 and ($comparison.after_full.diagnostic_headings | get $heading) == 4) 'source denial count differs'
        ensure (($comparison.before_full.diagnostic_headings | reject $heading) == ($comparison.after_full.diagnostic_headings | reject $heading)) 'other diagnostic counts differ'
        let adv_before = (json $c $'($prefix)/execution/policy/advisory-before.json')
        let adv_after = (json $c $'($prefix)/execution/policy/advisory-after.json')
        ensure (($adv_before | select argv exit stdout stderr) == ($adv_after | select argv exit stdout stderr)) 'advisory snapshots differ'
        for label in [41-deny-after-policy 42-deny-sources-after-policy] {
            let record = (json $c $'($prefix)/execution/logs/($label).json')
            ensure ('--locked' in $record.argv and '--offline' in $record.argv) 'deny scope differs'
        }
        let product = (json $c $'($prefix)/execution/logs/38-soft3-metadata.json')
        ensure ($product.exit == 101 and ((text $c $'($prefix)/execution/logs/38-soft3-metadata.stderr') | str contains 'local-storage')) 'product prerequisite red differs'
        {status: pass, logical_files: ($index | length), objects: ($objects | length),
         code_sections: [($v1.sections | length) ($v2.sections | length)],
         original_plan_sections: ($original.sections | length), policy_plan_sections: ($amendment.sections | length),
         production_files: 11, unchanged_rust_git_blobs: 511, corrected_tag_git_blobs: 854,
         historical_tag_deviations: 2, records: 96, streams: 192, full_metadata_variants: 3,
         gates_rerun: false, live_git_required: false,
         scope: 'Saved evidence integrity and explicit historical epochs. API, repository and product gates retain their recorded red/unverified boundaries.'} | to json | print
    } catch {|err|
        rm -r $dest
        print --stderr $err.rendered
        error make {msg: $err.msg}
    }
    rm -r $dest
}
