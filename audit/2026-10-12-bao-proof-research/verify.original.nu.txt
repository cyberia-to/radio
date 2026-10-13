use std/assert

def check-file [root: string, row: record] {
  let path = ($root | path join $row.path)
  assert equal (open --raw $path | hash sha256) $row.sha256
  assert equal (ls $path | get size | first | into int) $row.bytes
}

def git-bytes [repo: string, revision: string, path: string, temp: string] {
  ^git -C $repo cat-file blob $'($revision):($path)' out> $temp
  assert equal $env.LAST_EXIT_CODE 0
  open --raw $temp | into binary
}

def main [--repo: string, --siblings: string, --live] {
  let root = $env.FILE_PWD
  let own = if $repo == null { $root | path dirname | path dirname } else { $repo }
  let parent = if $siblings == null { $own | path dirname } else { $siblings }
  let repos = {radio: $own, hemera: ($parent | path join hemera),
    kadek: ($parent | path join kadek), soft3: ($parent | path join soft3)}
  let files = (open ($root | path join files.json))
  for f in $files { check-file $root $f }
  let initial = (open ($root | path join inputs.json))
  for f in $initial.probe_inputs { check-file $root $f }
  for f in (open ($root | path join primary-inputs.json) | get files) { check-file $root $f }
  let support = (open ($root | path join support-inputs.json))
  let bridge = (open ($root | path join merged-bridge.json))
  let temp = (^mktemp /tmp/radio-proof-replay.XXXXXX | str trim)
  let git_inputs = ($initial.git_inputs | append $support | append $bridge.merged_inputs)
  for f in $git_inputs {
    let bytes = (git-bytes ($repos | get $f.repository) $f.revision $f.path $temp)
    assert equal ($bytes | hash sha256) $f.sha256
    assert equal ($bytes | bytes length) $f.bytes
    if $f.local? != null { assert equal (open --raw ($root | path join $f.local) | into binary) $bytes }
  }
  for f in $bridge.comparison {
    let old = (git-bytes $own $bridge.parent $f.path $temp)
    let new = (git-bytes $own $bridge.current $f.path $temp)
    assert equal ($old | hash sha256) $f.parent_sha256
    assert equal ($new | hash sha256) $f.sha256
    assert equal (($old | hash sha256) == ($new | hash sha256)) $f.unchanged
  }
  assert equal (open --raw ($root | path join prerequisite/traversal.rs)) (open --raw ($root | path join merged-prerequisite/traversal.rs))
  for e in (open ($root | path join excerpts.json)) {
    let bytes = (git-bytes ($repos | get $e.repository) $e.revision $e.source $temp)
    assert equal ($bytes | hash sha256) $e.source_sha256
    let lines = ($bytes | decode utf-8 | split row "\n")
    let text = (($lines | skip ($e.first - 1) | take ($e.last - $e.first + 1) | str join "\n") + "\n")
    assert equal ($text | hash sha256) $e.sha256
  }
  let runner = (open --raw ($root | path join records/capture.rb) | hash sha256)
  let raw = (glob ($root | path join 'records/*.json'))
  for path in $raw {
    let record = (open $path)
    assert equal $record.runner_sha256 $runner
    let base = ($path | str replace --regex '\.json$' '')
    for stream in [stdout stderr] {
      let body = (open --raw $'($base).($stream)' | into binary)
      assert equal ($body | hash sha256) ($record | get $stream | get sha256)
      assert equal ($body | bytes length) ($record | get $stream | get bytes)
    }
  }
  assert equal (open --raw ($root | path join records/initial-debug.stdout)) (open --raw ($root | path join records/legacy-release.stdout))
  assert equal (open --raw ($root | path join records/primary-debug.stdout)) (open --raw ($root | path join records/primary-release.stdout))
  let fixtures = (open ($root | path join fixtures.json))
  for f in $fixtures { check-file $root $f }
  for f in (open ($root | path join task-inputs.json)) {
    check-file $root {path: $f.local, sha256: $f.sha256, bytes: $f.bytes}
    if $live { check-file $own $f }
  }
  if $live {
    assert equal (^git -C $own rev-parse HEAD | str trim) $bridge.current
    assert equal (^git -C $own diff --name-only | str trim) ''
  }
  rm $temp
  {status: pass, files: ($files | length), git_input_records: ($git_inputs | length),
    bridge_comparisons: ($bridge.comparison | length), primary_excerpts: 13,
    raw_receipts: ($raw | length), fixtures: ($fixtures | length),
    production_implemented: false, cargo_rerun: false, historical_inventory_archive_replayed: false} | to json
}
