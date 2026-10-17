def payload [index: list, root: path, name: string] {
    let rows = ($index | where path == $name)
    if ($rows | length) != 1 { error make {msg: $'missing payload ($name)'} }
    open --raw ($root | path join objects ($rows | first | get sha256))
}
def check [index: list, root: path, name: string, digest: string] {
    if (payload $index $root $name | hash sha256) != $digest { error make {msg: $'payload digest ($name)'} }
}
def main [audit: path = '.'] {
    let audit = ($audit | path expand)
    for row in (open --raw ($audit | path join SHA256SUMS) | lines | parse '{sha256}  {path}') {
        if (open --raw ($audit | path join $row.path) | hash sha256) != $row.sha256 { error make {msg: $'outer checksum ($row.path)'} }
    }
    let original = ($audit | path dirname)
    if (open --raw ($original | path join evidence.tar.gz) | hash sha256) != '23ab6b2d3ef3ed2b2019a96d307f5f9de28b741120c2741e851b2b52fcf57444' { error make {msg: 'original research archive changed'} }
    let original_result = (^nu ($original | path join verify.nu) $original | complete)
    if $original_result.exit_code != 0 { error make {msg: $original_result.stderr} }
    let old = ($original_result.stdout | from json)
    if not $old.pass or $old.revision != 'dacd030c9d6301b316a96b5bc6e4ea1e1cec79f1' { error make {msg: 'historical research epoch'} }
    let index = (open ($audit | path join evidence-index.json))
    let capsule = (open ($audit | path join capsule.json))
    if ($index | length) != $capsule.logical_payloads or ($index.path | uniq | length) != ($index | length) { error make {msg: 'logical inventory'} }
    if ($index.path | any {|p| $p =~ '(^/|(^|/)\.\.(/|$))'}) { error make {msg: 'unsafe logical path'} }
    let objects = ($index.sha256 | uniq | sort)
    if ($objects | length) != $capsule.unique_objects or ($objects | any {|s| not ($s =~ '^[0-9a-f]{64}$')}) { error make {msg: 'object inventory'} }
    let archive = ($audit | path join evidence.tar.gz)
    if (open --raw $archive | hash sha256) != $capsule.archive_sha256 or (open --raw ($audit | path join evidence-index.json) | hash sha256) != $capsule.index_sha256 { error make {msg: 'capsule identity'} }
    let listing = (^tar -tzf $archive | complete)
    let types = (^tar -tvzf $archive | complete)
    if $listing.exit_code != 0 or ($listing.stdout | lines | sort) != ($objects | each {|h| $'objects/($h)'}) or $types.exit_code != 0 or ($types.stdout | lines | any {|s| not ($s | str starts-with '-')}) { error make {msg: 'archive inventory/type'} }
    let made = (^mktemp -d /tmp/bao-traversal-plan.XXXXXX | complete)
    if $made.exit_code != 0 { error make {msg: $made.stderr} }
    let dest = ($made.stdout | str trim)
    try {
        let extracted = (^tar -xzf $archive -C $dest | complete)
        if $extracted.exit_code != 0 { error make {msg: $extracted.stderr} }
        for hash in $objects {
            let file = ($dest | path join objects $hash)
            if ($file | path type) != file or (open --raw $file | hash sha256) != $hash { error make {msg: 'object body'} }
            let bytes = (ls $file | get 0.size | into int)
            if ($index | where sha256 == $hash | any {|r| $r.bytes != $bytes}) { error make {msg: 'object size'} }
        }
        let rows = (payload $index $dest plan/index.json | from json)
        let build = (payload $index $dest plan/build.json | from json)
        check $index $dest plan/index.json $build.index_sha256
        let pieces = ($rows | each {|r|
            let body = (payload $index $dest $'plan/($r.retained_path)' | into string)
            if ($body | hash sha256) != $r.sha256 { error make {msg: 'PLAN section'} }
            $'===== ($r.name) =====(char nl)SOURCE ($r.source)(char nl)SHA256 ($r.sha256) BYTES ($r.bytes)(char nl)($body)(char nl)===== END ($r.name) =====(char nl)'
        })
        let rebuilt = ((payload $index $dest plan/intro.txt | into string) + ($pieces | str join (char nl)))
        if ($rebuilt | hash sha256) != $capsule.plan_sha256 or $build.sha256 != $capsule.plan_sha256 or ($rows | length) != $capsule.plan_sections { error make {msg: 'PLAN reconstruction'} }
        check $index $dest plan/sourcepack.txt $capsule.plan_sha256
        let source = (payload $index $dest evidence/source-freeze.json | from json)
        if $source.revision != $capsule.parent or ($source.files | length) != $capsule.current_sources { error make {msg: 'current source inventory'} }
        for row in $source.files {
            let body = (payload $index $dest $'evidence/source/($row.path)' | into binary)
            let oid = ($body | ^git hash-object --stdin | complete)
            if ($body | hash sha256) != $row.sha256 or $oid.exit_code != 0 or ($oid.stdout | str trim) != $row.git_oid { error make {msg: 'current source blob'} }
        }
        let primary = (payload $index $dest evidence/primary-freeze.json | from json)
        if ($primary.files | length) != $capsule.primary_sources { error make {msg: 'primary inventory'} }
        for row in $primary.files {
            let body = (payload $index $dest $'evidence/primary/($row.repo)/($row.path)' | into binary)
            let oid = ($body | ^git hash-object --stdin | complete)
            if ($body | hash sha256) != $row.sha256 or $oid.exit_code != 0 or ($oid.stdout | str trim) != $row.git_oid { error make {msg: 'primary blob'} }
        }
        let freeze = (payload $index $dest evidence/witness-freeze.json | from json)
        if $freeze.parent != $capsule.parent or not $freeze.ordinary_tests_not_installed { error make {msg: 'witness provenance'} }
        for row in $freeze.files { check $index $dest $'evidence/($row.path)' $row.sha256 }
        let records = ($index | where {|r| $r.path =~ '^evidence/records/[^/]+/command\.json$'})
        if ($records | length) != $capsule.records { error make {msg: 'current record count'} }
        for row in $records {
            let r = (payload $index $dest $row.path | from json)
            if $r.revision != $capsule.parent or not $r.source_unchanged_after or not $r.inputs_unchanged_after { error make {msg: 'current record epoch'} }
            check $index $dest evidence/source-freeze.json $r.source_freeze_sha256
            check $index $dest evidence/witness-freeze.json $r.witness_freeze_sha256
            for input in $r.inputs { check $index $dest $'evidence/($input.path)' $input.sha256 }
            let stem = ($row.path | path dirname)
            for stream in [stdout stderr] { check $index $dest $'($stem)/($stream)' ($r | get $'($stream)_sha256') }
            if ($stem | str contains 'probe-') and not ($stem | str ends-with resolve) {
                let raw = (payload $index $dest $'($stem)/stderr' | into string)
                if $r.exit != 101 or not ($raw | str contains 'error[E0432]: unresolved import `cyber_bao::traversal`') { error make {msg: 'API absence observation'} }
            } else if $r.exit != 0 { error make {msg: 'research command status'} }
        }
        for mode in [debug release] {
            let output = (payload $index $dest $'evidence/records/geometry-($mode)/stdout' | into string)
            if not ($output | str contains 'postorder leaves=4096 total_items=8191 constructor_calls=12 constructor_requested_bytes=393120 first_next_calls=0 first_next_requested_bytes=0') { error make {msg: 'eager constructor observation'} }
            let expected = if $mode == debug { 'u64max_last_group: panicked' } else { 'Leaf { start_chunk: 4503599627370495, size: 4096, is_root: false }' }
            if not ($output | str contains $expected) { error make {msg: 'maximum geometry observation'} }
        }
        let old_index = (open ($original | path join evidence-index.json))
        let old_probe = ($old_index | where path == probe/src/main.rs | first)
        check $index $dest evidence/geometry/src/main.rs $old_probe.sha256
        let bridge = ($index | where {|r| $r.path =~ '^bridge/[^/]+\.json$'})
        if ($bridge | length) != $capsule.bridge_records { error make {msg: 'bridge count'} }
        for row in $bridge {
            let r = (payload $index $dest $row.path | from json)
            if $r.exit != 0 { error make {msg: 'bridge failure'} }
            let stem = ($row.path | str replace --regex '\.json$' '')
            for stream in [stdout stderr] { check $index $dest $'($stem).($stream)' ($r | get $'($stream)_sha256') }
        }
        if (payload $index $dest bridge/09-parent-after.stdout | into string | str trim) != $capsule.parent { error make {msg: 'integrated parent'} }
        for name in [03-tracked-before 06-protected-delta 11-source-tree-delta] {
            if (payload $index $dest $'bridge/($name).stdout' | into binary | bytes length) != 0 { error make {msg: 'protected bridge delta'} }
        }
        rm -r $dest
        print ({status: PASS, current_records: $capsule.records, current_streams: $capsule.streams, bridge_records: $capsule.bridge_records, bridge_streams: $capsule.bridge_streams, historical_records: $old.records, historical_streams: $old.raw_streams, source_entries: ($capsule.current_sources + $capsule.primary_sources + $old.source_files), plan_sections: $capsule.plan_sections, payloads: $capsule.logical_payloads, objects: $capsule.unique_objects} | to json --raw)
    } catch {|err|
        rm -r $dest
        error make {msg: $err.msg}
    }
}
