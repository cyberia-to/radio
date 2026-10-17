def payload [index: list, root: path, name: string] {
    let rows = ($index | where path == $name)
    if ($rows | length) != 1 { error make {msg: $'missing payload: ($name)'} }
    open --raw ($root | path join objects ($rows | first | get sha256))
}
def check [index: list, root: path, name: string, digest: string] {
    if (payload $index $root $name | hash sha256) != $digest { error make {msg: $'digest mismatch: ($name)'} }
}
def main [audit: path = '.'] {
    let audit = ($audit | path expand)
    for row in (open --raw ($audit | path join SHA256SUMS) | lines | parse '{sha256}  {path}') {
        if (open --raw ($audit | path join $row.path) | hash sha256) != $row.sha256 { error make {msg: $'outer checksum: ($row.path)'} }
    }
    let index = (open ($audit | path join evidence-index.json))
    let capsule = (open ($audit | path join capsule.json))
    if ($index.path | uniq | length) != ($index | length) or ($index | length) != $capsule.logical_payloads { error make {msg: 'payload inventory'} }
    if ($index.path | any {|p| $p =~ '(^/|(^|/)\.\.(/|$))'}) { error make {msg: 'unsafe logical path'} }
    let objects = ($index.sha256 | uniq | sort)
    if ($objects | length) != $capsule.unique_objects or ($objects | any {|s| not ($s =~ '^[0-9a-f]{64}$')}) { error make {msg: 'object inventory'} }
    let archive = ($audit | path join evidence.tar.gz)
    if (open --raw $archive | hash sha256) != $capsule.archive_sha256 or (open --raw ($audit | path join evidence-index.json) | hash sha256) != $capsule.index_sha256 { error make {msg: 'capsule binding'} }
    let listed = (^tar -tzf $archive | complete)
    if $listed.exit_code != 0 or ($listed.stdout | lines | sort) != ($objects | each {|s| $'objects/($s)'}) { error make {msg: 'archive inventory'} }
    let types = (^tar -tvzf $archive | complete)
    if $types.exit_code != 0 or ($types.stdout | lines | any {|s| not ($s | str starts-with '-')}) { error make {msg: 'archive contains non-regular entry'} }
    let created = (^mktemp -d /tmp/bao-reducer-evidence.XXXXXX | complete)
    if $created.exit_code != 0 { error make {msg: $created.stderr} }
    let dest = ($created.stdout | str trim)
    try {
        let unpack = (^tar -xzf $archive -C $dest | complete)
        if $unpack.exit_code != 0 { error make {msg: $unpack.stderr} }
        for hash in $objects {
            let file = ($dest | path join objects $hash)
            if ($file | path type) != file or (open --raw $file | hash sha256) != $hash { error make {msg: $'object body: ($hash)'} }
            let size = (ls $file | get 0.size | into int)
            if ($index | where sha256 == $hash | any {|r| $r.bytes != $size}) { error make {msg: 'object size'} }
        }
        for kind in [plan code] {
            let rows = (payload $index $dest $'($kind)/index.json' | from json)
            let build = (payload $index $dest $'($kind)/build.json' | from json)
            check $index $dest $'($kind)/index.json' $build.index_sha256
            let pieces = ($rows | each {|r|
                let body = (payload $index $dest $'($kind)/($r.retained_path)' | into string)
                if ($body | hash sha256) != $r.sha256 { error make {msg: 'review section'} }
                $'===== ($r.name) =====(char nl)SOURCE ($r.source)(char nl)SHA256 ($r.sha256) BYTES ($r.bytes)(char nl)($body)(char nl)===== END ($r.name) =====(char nl)'
            })
            let rebuilt = ((payload $index $dest $'($kind)/intro.txt' | into string) + ($pieces | str join (char nl)))
            if ($rebuilt | hash sha256) != $build.sha256 { error make {msg: 'review reconstruction'} }
            check $index $dest $'($kind)/sourcepack.txt' $build.sha256
        }
        check $index $dest plan/review.txt '63c4a0496c9a0893fdc5ebbb7c62a4619db9550af14a26f7e1e52744ff12add3'
        let records = ($index | where {|r| $r.path =~ '^execution/logs/[^/]+\.json$'})
        if ($records | length) != $capsule.records or $capsule.streams != (2 * $capsule.records) { error make {msg: 'receipt count'} }
        for row in $records {
            let r = (payload $index $dest $row.path | from json)
            if $r.source_before != $r.source_after { error make {msg: 'source changed during gate'} }
            let stem = ($row.path | str replace --regex '\.json$' '')
            for stream in [stdout stderr] { check $index $dest $'($stem).($stream)' ($r | get $'($stream)_sha256') }
            check $index $dest $'execution/runners/($r.runner_sha256).rb' $r.runner_sha256
            let source = (payload $index $dest $'execution/sources/($r.source_before.sha256).json' | from json)
            if $source.sha256 != $r.source_before.sha256 or ($source.files | length) != $r.source_before.count { error make {msg: 'source snapshot binding'} }
        }
        let sources = ($index | where {|r| $r.path =~ '^execution/sources/[0-9a-f]+\.json$'})
        for row in $sources {
            let source = (payload $index $dest $row.path | from json)
            if ($source.files | to json --raw | hash sha256) != $source.sha256 { error make {msg: 'source manifest digest'} }
            for pair in $source.files { check $index $dest $'execution/sources/($source.sha256)/($pair.0)' $pair.1 }
        }
        let freeze = (payload $index $dest execution/parent-freeze.json | from json)
        if $freeze.parent.head != $capsule.parent { error make {msg: 'parent identity'} }
        for pair in $freeze.files {
            let name = ($pair.0 | path basename)
            check $index $dest $'execution/frozen-tests/($name)' $pair.1
        }
        for feature in [default all none] {
            for mode in [debug release] {
                let label = $'23b-final-($feature)-($mode)'
                let record = (payload $index $dest $'execution/logs/($label).json' | from json)
                let output = (payload $index $dest $'execution/logs/($label).stdout' | into string)
                let count = ($output | lines | parse --regex '^test result: ok\. (?<passed>\d+) passed' | get passed | into int | math sum)
                let expected = if $feature == default { 92 } else if $feature == all { 95 } else { 21 }
                if $record.exit != 0 or $count != $expected { error make {msg: 'finite matrix outcome'} }
            }
        }
        for label in [01-parent-missing-api-debug 02-parent-missing-api-release] {
            let record = (payload $index $dest $'execution/logs/($label).json' | from json)
            let error = (payload $index $dest $'execution/logs/($label).stderr' | into string)
            if $record.exit != 101 or not ($error | str contains 'error[E0432]') { error make {msg: 'parent API absence'} }
        }
        let thumb = (payload $index $dest execution/logs/14c-candidate-isolated-thumb.json | from json)
        let graph = (payload $index $dest execution/logs/15b-candidate-isolated-graph.stdout | into string)
        if $thumb.exit != 0 or ($graph | str contains 'feature "std"') { error make {msg: 'isolated embedded record'} }
        print ({status: PASS, records: $capsule.records, streams: $capsule.streams, source_snapshots: ($sources | length), code_sections: $capsule.code_sections, logical_payloads: $capsule.logical_payloads, objects: $capsule.unique_objects} | to json --raw)
        rm -rf $dest
    } catch {|error|
        rm -rf $dest
        error make {msg: $'portable replay failed: ($error.msg)'}
    }
}
