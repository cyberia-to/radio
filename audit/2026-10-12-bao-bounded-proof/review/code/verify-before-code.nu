use std/assert

def check [root: string, path: string, bytes: int, digest: string] {
  let data = (open --raw ($root | path join $path) | into binary)
  assert equal ($data | bytes length) $bytes
  assert equal ($data | hash sha256) $digest
}

def main [--repo: string, --live] {
  let root = $env.FILE_PWD
  let own = if $repo == null { $root | path dirname | path dirname } else { $repo }
  let all = (open ($root | path join files.json))
  for f in $all { check $root $f.path $f.bytes $f.sha256 }
  let ready = (open ($root | path join source-complete.json))
  let freezes = [tests-first.json source-freeze.json source-final.json source-ready.json source-complete.json]
  mut candidates = []
  for p in $freezes {
    let freeze = (open ($root | path join $p))
    for f in $freeze.files {
      check $root $f.local $f.bytes $f.sha256
      $candidates = ($candidates | append $f)
    }
  }
  for f in (open ($root | path join fixtures-first.json) | get files) {
    check $root $f.path $f.bytes $f.sha256
  }
  for p in [seals-first.json seals-final-inputs.json] {
    for f in (open ($root | path join $p)) { check $root $f.path $f.bytes $f.sha256 }
  }
  let temp = (^mktemp /tmp/radio-proof-execution-replay.XXXXXX | str trim)
  mut original_count = 0
  mut candidate_count = 0
  let epochs = (glob ($root | path join 'epochs/*.json'))
  for p in $epochs {
    let epoch = (open $p)
    assert equal $epoch.head $ready.parent
    assert equal ($epoch.files | to json --raw | hash sha256) ($p | path parse | get stem)
    for row in $epoch.files {
      let path = ($row | get 0)
      let size = ($row | get 1)
      let digest = ($row | get 2)
      let local = ($candidates | where {|f| $f.path == $path and $f.sha256 == $digest })
      if ($local | is-not-empty) {
        assert equal ($local | first | get bytes) $size
        $candidate_count += 1
      } else {
        ^git -C $own cat-file blob $'($epoch.head):($path)' out> $temp
        assert equal $env.LAST_EXIT_CODE 0
        let data = (open --raw $temp | into binary)
        assert equal ($data | bytes length) $size
        assert equal ($data | hash sha256) $digest
        $original_count += 1
      }
    }
  }
  let runner = (open --raw ($root | path join records/capture.rb) | hash sha256)
  let raw = (glob ($root | path join 'records/*.json'))
  for p in $raw {
    let r = (open $p)
    assert equal $r.runner_sha256 $runner
    let stem = ($p | str replace --regex '\.json$' '')
    for stream in [stdout stderr] {
      let data = (open --raw $'($stem).($stream)' | into binary)
      assert equal ($data | bytes length) ($r | get $stream | get bytes)
      assert equal ($data | hash sha256) ($r | get $stream | get sha256)
    }
  }
  let bindings = (glob ($root | path join 'bindings/*.json'))
  let gate_runners = ([records/final-gates.rb records/radio-bao-proof-final-gates-v2.rb] | each {|p| open --raw ($root | path join $p) | hash sha256 })
  for p in $bindings {
    let b = (open $p)
    assert equal $b.source_before $b.source_after
    assert ($b.runner_sha256 in $gate_runners)
    assert equal (open --raw ($root | path join records $'($b.name).json') | hash sha256) $b.record_sha256
    assert ( ($root | path join epochs $'($b.source_before).json') | path exists )
  }
  let ledger = (open ($root | path join gate-ledger.json))
  for row in $ledger {
    let record = (open ($root | path join $row.record))
    assert equal (open --raw ($root | path join $row.record) | hash sha256) $row.record_sha256
    assert equal $record.exit_code $row.exit
    assert equal $record.argv $row.argv
    assert equal $record.revision $row.revision
    assert equal $record.stdout $row.stdout
    assert equal $record.stderr $row.stderr
    if $row.epoch != null {
      assert equal (open ($root | path join bindings $'($row.name).json') | get source_before) $row.epoch
    }
  }
  for row in (open ($root | path join review-gates.json)) {
    assert equal $row ($ledger | where name == $row.name | first)
  }
  let pairs = ((open ($root | path join comparisons.json)) | append (open ($root | path join additional-comparisons.json)))
  for pair in $pairs {
    assert ($pair.candidate in ($ledger | get name))
    assert ($pair.parent in ($ledger | get name))
  }
  let previous = (open ($root | path join source-ready.json))
  let changed = ($ready.files | where {|f| $f.sha256 != ($previous.files | where path == $f.path | first | get sha256) } | get path)
  assert equal $changed ['cyber-bao/tests/proof.rs']
  for row in (open ($root | path join seals-final-results.json)) {
    let record = (open ($root | path join records $'seal-($row.bin)-final.json'))
    assert equal $record.exit_code 101
    assert equal $row.actual [$row.expected]
    let stderr = (open --raw ($root | path join records $'seal-($row.bin)-final.stderr'))
    let codes = ($stderr | parse --regex 'error\[(E\d+)\]' | get capture0 | uniq)
    assert equal $codes [$row.expected]
  }
  assert equal (open ($root | path join records/seal-control-final.json) | get exit_code) 0
  for f in (open ($root | path join interleaved-oracle.json) | get files) {
    check $root $f.path $f.bytes $f.sha256
  }
  let review = (open ($root | path join plan-review/invocation.json))
  let completion = (open ($root | path join plan-review/completion.json))
  assert equal (open --raw ($root | path join plan-review/launcher.rb) | hash sha256) $review.launcher_sha256
  assert equal (open --raw ($root | path join plan-input/context.txt) | hash sha256) $review.input_sha256
  assert equal (open --raw ($root | path join plan-review/stdout.json) | hash sha256) $completion.stdout_sha256
  assert equal (open --raw ($root | path join plan-review/stderr.txt) | hash sha256) $completion.stderr_sha256
  assert equal (open ($root | path join plan-review/stdout.json) | get result) (open --raw ($root | path join plan-review/result.md))
  for pack in [plan-input code-input] {
    let manifest = (open ($root | path join $pack manifest.json))
    check $root ($pack | path join context.txt) $manifest.context_bytes $manifest.context_sha256
  }
  let first = (open ($root | path join records/parent-absence.json))
  assert equal $first.revision $ready.parent
  assert equal $first.exit_code 101
  assert (open --raw ($root | path join records/parent-absence.stderr) | str contains 'error[E0432]')
  for f in $ready.files {
    if $live { check $own $f.path $f.bytes $f.sha256 }
    if ($f.path | str starts-with 'cyber-bao/src/') {
      if $f.path == 'cyber-bao/src/lib.rs' {
        ^git -C $own cat-file blob $'($ready.parent):($f.path)' out> $temp
        assert equal $env.LAST_EXIT_CODE 0
        let old = (open --raw $temp)
        let new = (open --raw ($root | path join $f.local))
        assert equal ($new | str replace "pub mod proof;\n" '') $old
      }
    }
  }
  if $live { assert equal (^git -C $own rev-parse HEAD | str trim) $ready.parent }
  rm $temp
  {status: pass, files: ($all | length), source_epochs: ($epochs | length),
    original_git_source_records: $original_count, candidate_source_records: $candidate_count,
    raw_records: ($raw | length), gate_bindings: ($bindings | length),
    counterpart_mappings: ($pairs | length),
    initial_seed_fixtures: 17, supplemental_interleaved_carriers: 1,
    cargo_rerun: false, hemera_recomputed: false,
    requires_exact_parent_git_objects: true} | to json
}
