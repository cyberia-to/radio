def body [index: list, root: path, name: string] {
    let rows = ($index | where path == $name)
    if ($rows | length) != 1 { error make {msg: $'missing payload ($name)'} }
    open --raw ($root | path join objects ($rows | first | get sha256))
}
def check [index: list, root: path, name: string, digest: string] {
    if (body $index $root $name | hash sha256) != $digest { error make {msg: $'payload digest ($name)'} }
}
def main [audit: path = '.'] {
    let audit = ($audit | path expand)
    for row in (open --raw ($audit | path join SHA256SUMS) | lines | parse '{sha256}  {path}') {
        if (open --raw ($audit | path join $row.path) | hash sha256) != $row.sha256 { error make {msg: $'outer checksum ($row.path)'} }
    }
    let plan = ($audit | path dirname | path join plan)
    let capsule = (open ($audit | path join capsule.json))
    if (open --raw ($plan | path join evidence.tar.gz) | hash sha256) != $capsule.plan_archive_sha256 { error make {msg: 'PLAN capsule changed'} }
    let previous = (^nu ($plan | path join verify.nu) $plan | complete)
    if $previous.exit_code != 0 or ($previous.stdout | from json | get status) != PASS { error make {msg: 'historical PLAN/research replay'} }
    let index = (open ($audit | path join evidence-index.json))
    if ($index | length) != $capsule.logical_payloads or ($index.path | uniq | length) != ($index | length) { error make {msg: 'logical inventory'} }
    if ($index.path | any {|p| $p =~ '(^/|(^|/)\.\.(/|$))'}) { error make {msg: 'unsafe logical path'} }
    let objects = ($index.sha256 | uniq | sort)
    if ($objects | length) != $capsule.unique_objects or ($objects | any {|s| not ($s =~ '^[0-9a-f]{64}$')}) { error make {msg: 'object inventory'} }
    let archive = ($audit | path join evidence.tar.gz)
    if (open --raw $archive | hash sha256) != $capsule.archive_sha256 or (open --raw ($audit | path join evidence-index.json) | hash sha256) != $capsule.index_sha256 { error make {msg: 'capsule identity'} }
    let listing = (^tar -tzf $archive | complete)
    let types = (^tar -tvzf $archive | complete)
    if $listing.exit_code != 0 or ($listing.stdout | lines | sort) != ($objects | each {|h| $'objects/($h)'}) or $types.exit_code != 0 or ($types.stdout | lines | any {|s| not ($s | str starts-with '-')}) { error make {msg: 'archive inventory/type'} }
    let made = (^mktemp -d /tmp/bao-traversal-code.XXXXXX | complete)
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
        let rows = (body $index $dest code/index.json | from json)
        let build = (body $index $dest code/build.json | from json)
        check $index $dest code/index.json $build.index_sha256
        let pieces = ($rows | each {|r|
            let value = (body $index $dest $'code/($r.retained_path)' | into string)
            if ($value | hash sha256) != $r.sha256 { error make {msg: 'CODE section'} }
            $'===== ($r.name) =====(char nl)SOURCE ($r.source)(char nl)SHA256 ($r.sha256) BYTES ($r.bytes)(char nl)($value)(char nl)===== END ($r.name) =====(char nl)'
        })
        let rebuilt = ((body $index $dest code/intro.txt | into string) + ($pieces | str join (char nl)))
        if ($rebuilt | hash sha256) != $capsule.code_sha256 or $build.sha256 != $capsule.code_sha256 or ($rows | length) != $capsule.code_sections { error make {msg: 'CODE reconstruction'} }
        check $index $dest code/sourcepack.txt $capsule.code_sha256
        let records = ($index | where {|r| $r.path =~ '^execution/logs/[^/]+\.json$'})
        if ($records | length) != $capsule.records { error make {msg: 'gate record count'} }
        mut sources = []
        for row in $records {
            let r = (body $index $dest $row.path | from json)
            if $r.source_before != $r.source_after or $r.source_before.head != $capsule.parent { error make {msg: 'gate epoch/drift'} }
            let stem = ($row.path | str replace --regex '\.json$' '')
            for stream in [stdout stderr] { check $index $dest $'($stem).($stream)' ($r | get $'($stream)_sha256') }
            check $index $dest $'execution/runners/($r.runner_sha256).rb' $r.runner_sha256
            if ($r | columns | any {|c| $c == supplemental_inputs}) {
                for input in $r.supplemental_inputs { check $index $dest $'execution/($input.0)' $input.1 }
            }
            $sources = ($sources | append $r.source_before.sha256 | uniq)
        }
        for hash in $sources {
            let manifest = (body $index $dest $'execution/sources/($hash).json' | from json)
            if $manifest.head != $capsule.parent or ($manifest.files | to json --raw | hash sha256) != $hash { error make {msg: 'source manifest'} }
            for row in $manifest.files { check $index $dest $'execution/sources/($hash)/($row.0)' $row.1 }
        }
        let current = (body $index $dest $'execution/sources/($capsule.source_sha256).json' | from json)
        if ($current.files | length) != $capsule.current_sources { error make {msg: 'final source count'} }
        let extra = (body $index $dest execution/primary-extra.json | from json)
        let primary = (body $index $dest $'execution/primary/hemera/($extra.path)' | into binary)
        let oid = ($primary | ^git hash-object --stdin | complete)
        if $oid.exit_code != 0 or ($oid.stdout | str trim) != $extra.git_blob or ($primary | hash sha256) != $extra.sha256 { error make {msg: 'pinned Hemera source'} }
        check $index $dest plan-review/stdout.txt c810226e7b5865b57b3d0bf0b5f7d916b3b0fb6fb620298a0daa0723fb77ade1
        for name in [01-parent-ordinary-debug 02-parent-ordinary-release] {
            let r = (body $index $dest $'execution/logs/($name).json' | from json)
            if $r.exit != 101 or not (body $index $dest $'execution/logs/($name).stderr' | into string | str contains 'error[E0432]: unresolved import `cyber_bao::traversal`') { error make {msg: 'ordinary parent negative'} }
        }
        for name in [12b-isolated-thumb-link-bound 22-parent-thumb-link-control] {
            let r = (body $index $dest $'execution/logs/($name).json' | from json)
            if $r.exit != 101 or not (body $index $dest $'execution/logs/($name).stderr' | into string | str contains 'no global memory allocator found') { error make {msg: 'final-link boundary'} }
        }
for name in [03c-final-default-debug 04c-final-default-release 05c-final-all-debug 06c-final-all-release 07c-final-none-debug 08c-final-none-release 19c-final-owning-format 19d-final-new-workflow-format 21c-final-none-clippy 25b-candidate-nextest-default 26b-candidate-nextest-none 40-api-parent-default 40-api-parent-none 40-api-last-tag-default] {
    let r = (body $index $dest $'execution/logs/($name).json' | from json)
    if $r.exit != 0 { error make {msg: $'expected green outcome ($name)'} }
}
for name in [27b-candidate-nextest-all 28b-parent-nextest-all] {
    let r = (body $index $dest $'execution/logs/($name).json' | from json)
    if $r.exit != 101 or not (body $index $dest $'execution/logs/($name).stderr' | into string | str contains 'error[E0599]') { error make {msg: 'all-feature compile boundary'} }
}
let last_none = (body $index $dest execution/logs/40-api-last-tag-none.json | from json)
if $last_none.exit != 100 { error make {msg: 'last-tag no-default major floor'} }
for row in ($rows | where {|r| $r.name | str starts-with 'candidate/'}) {
    let path = ($row.name | str replace 'candidate/' '')
    check $index $dest $'execution/sources/($capsule.source_sha256)/($path)' $row.sha256
}
        let api = (body $index $dest execution/api/inputs.json | from json)
        let api_receipt = (body $index $dest execution/api/input-verification.json | from json)
        check $index $dest execution/api/inputs.json $api_receipt.input_manifest_sha256
        if ($api.files | length) != $api_receipt.git_blobs { error make {msg: 'API inventory receipt'} }
        rm -r $dest
        print ({status: PASS, records: $capsule.records, streams: $capsule.streams, current_sources: $capsule.current_sources, source_snapshots: ($sources | length), code_sections: $capsule.code_sections, payloads: $capsule.logical_payloads, objects: $capsule.unique_objects, api_inventory: ($api.files | length), api_archive_bodies_replayed: false} | to json --raw)
    } catch {|err|
        rm -r $dest
        error make {msg: $err.msg}
    }
}
