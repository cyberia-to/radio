use std/assert

def check [root: string, f: record] {
  let b = (open --raw ($root | path join $f.path) | into binary)
  assert equal ($b | bytes length) $f.bytes
  assert equal ($b | hash sha256) $f.sha256
}
def pointer [p: string] {
  $p | split row '/' | skip 1 | each {|x| if ($x =~ '^[0-9]+$') { $x | into int } else { $x } } | into cell-path
}
def main [--repo: string, --live] {
  assert ($repo != null) 'Pass --repo containing the exact historical Radio Git objects'
  let root = $env.FILE_PWD
  let files = (open ($root | path join files.json))
  for f in $files { check $root $f }
  let base = 'ce0fb312faa8770e80efe9afa864106ae6b51552'
  let tmp = (^mktemp -d /tmp/radio-packaging-verify.XXXXXX | str trim)
  let blob = ($tmp | path join blob)
  let sources = (open ($root | path join inputs/source.json) | append (open ($root | path join inputs/v2-additional-source.json)))
  for f in $sources {
    ^git -C $repo cat-file blob $'($f.revision):($f.path)' out> $blob
    assert equal $env.LAST_EXIT_CODE 0
    let bytes = (open --raw $blob | into binary)
    assert equal ($bytes | bytes length) $f.bytes
    assert equal ($bytes | hash sha256) $f.sha256
    assert equal (open --raw ($root | path join $f.local) | into binary) $bytes
  }
  let renames = (open ($root | path join inputs/renames.json))
  assert equal ($renames | length) 7
  assert equal ($renames | get bytes | math sum) 2141
  let bindings = (open ($root | path join inputs/historical-index-bindings.json))
  for f in $bindings {
    ^git -C $repo cat-file blob $'($base):($f.index)' out> $blob
    assert equal $env.LAST_EXIT_CODE 0
    let text = (open --raw $blob)
    assert equal ($text | hash sha256) $f.index_sha256
    let entry = ($text | from json | get (pointer $f.pointer))
    assert equal $entry.bytes $f.bytes
    assert equal $entry.sha256 $f.sha256
    if $live { check $repo {path: $f.archived_path, bytes: $f.bytes, sha256: $f.sha256} }
  }
  # Bundle is an incremental local witness, not a release or default-branch commit.
  let bare = ($tmp | path join witness.git)
  ^git clone --bare --shared $repo $bare out+err> ($tmp | path join clone.log)
  assert equal $env.LAST_EXIT_CODE 0
  ^git --git-dir $bare fetch ($root | path join pair/candidate.bundle) refs/heads/packaging-witness out+err> ($tmp | path join fetch.log)
  assert equal $env.LAST_EXIT_CODE 0
  let snap = (open ($root | path join pair/snapshot.json))
  assert equal $snap.parent $base
  assert equal (^git --git-dir $bare rev-parse FETCH_HEAD | str trim) $snap.candidate
  assert equal (^git --git-dir $bare rev-parse $'($snap.candidate)^{tree}' | str trim) $snap.tree
  let delta = (^git --git-dir $bare diff-tree --no-commit-id --no-renames --name-only -r $base $snap.candidate | lines | sort)
  assert equal $delta ($snap.explicit_paths | get path | sort)
  assert equal $delta ($snap.changed_paths | sort)
  for f in ($snap.explicit_paths | where {|x| not ($x | get -o deleted | default false) }) {
    ^git --git-dir $bare cat-file blob $'($snap.candidate):($f.path)' out> $blob
    assert equal $env.LAST_EXIT_CODE 0
    let b = (open --raw $blob | into binary)
    assert equal ($b | bytes length) $f.bytes
    assert equal ($b | hash sha256) $f.sha256
  }
  let normal = {|rev| ^git --git-dir $bare ls-tree -r $rev | lines | where {|s| let p = ($s | split row "\t" | last); not (($p | str starts-with audit/) or ($p | str starts-with .claude/tasks/)) } }
  assert equal (do $normal $base) (do $normal $snap.candidate)
  assert equal (do $normal $base | length) $snap.unchanged_normal_paths
  let names = (^git --git-dir $bare ls-tree -r --name-only $snap.candidate audit | lines)
  assert ($names | where {|p| ($p | path basename) == Cargo.toml } | is-empty)
  let freeze = (open ($root | path join execution/source-freeze.json))
  for f in $freeze {
    ^git --git-dir $bare cat-file blob $'($snap.candidate):($f.path)' out> $blob
    assert equal $env.LAST_EXIT_CODE 0
    assert equal (open --raw $blob | hash sha256) $f.sha256
    if $live { check $repo $f }
  }
  # Raw stream hashes and actual statuses, including deliberate failures.
  let raw = (open ($root | path join raw-records.json))
  for f in $raw {
    let r = (open ($root | path join $f.path))
    assert equal $r.exit_code $f.exit_code
    for stream in [stdout stderr] {
      let s = ($r | get $stream)
      let b = (open --raw ($root | path join ($f.path | str replace '.json' $'.($stream)')) | into binary)
      assert equal ($b | bytes length) $s.bytes
      assert equal ($b | hash sha256) $s.sha256
    }
  }
  for arm in [parent candidate] {
    let before = (open ($root | path join pair $arm before.json))
    assert equal $before (open ($root | path join pair $arm after.json))
    for cmd in [lock metadata debug release] {
      let r = (open ($root | path join pair $arm $'($cmd).json'))
      assert equal $r.exit_code 0
      let err = (open --raw ($root | path join pair $arm $'($cmd).stderr'))
      if $arm == parent { assert ($err | str contains 'warning: skipping duplicate package') } else { assert (not ($err | str contains 'warning:')) }
    }
  }
  let result = (open ($root | path join pair/results.json))
  for arm in [parent candidate] { for mode in [debug release] {
    assert equal (open --raw ($root | path join pair $arm $'($mode).stdout') | hash sha256) $result.stdout_sha256
  } }
  assert equal $result.stdout_sha256 'ccb679634c8a07dc76b75445b6ac9f8372602e46bb4d85217a7634db6956ab99'
  let tuples = {|arm| open ($root | path join pair $arm sources.json) | select package relative bytes sha256 }
  assert equal (do $tuples parent) (do $tuples candidate)
  assert equal (do $tuples parent | length) 63
  let external = (open ($root | path join pair/external-manifest.json))
  assert equal ($external | select path bytes sha256 | uniq | length) 1
  check $root {path: pair/external.Cargo.toml.txt, bytes: ($external | first | get bytes), sha256: ($external | first | get sha256)}
  let comparison = (open ($root | path join pair/metadata-comparison.json))
  mut normalized = []
  for row in $comparison.arms {
    mut data = (open --raw ($root | path join pair $row.arm metadata.stdout) | from json)
    for s in $row.substitutions {
      let p = (pointer $s.pointer)
      assert equal ($data | get $p) $s.old
      if $s.kind == exact-identifier {
        assert equal ($row.exact_map | get $s.old) $s.new
      } else {
        assert equal $s.kind validated-path-boundary
        let admitted = ($row.path_prefix_map | transpose old new | where {|m| ($s.old == $m.old) or ($s.old | str starts-with ($m.old + '/')) })
        assert equal ($admitted | length) 1
        let m = ($admitted | first)
        assert equal $s.new ($m.new + ($s.old | str substring ($m.old | str length)..))
      }
      $data = ($data | update $p $s.new)
    }
    assert equal $data (open ($root | path join pair $row.arm metadata-normalized.json))
    $normalized = ($normalized | append [$data])
  }
  assert equal ($normalized | get 0) ($normalized | get 1)
  for name in [research proof] {
    assert equal (open --raw ($root | path join records $'($name)-before.stdout')) (open --raw ($root | path join records $'($name)-after-v2.stdout'))
    let live = (open ($root | path join records $'($name)-live-after-v2.json'))
    assert equal $live.exit_code 1
    let error = (open --raw ($root | path join records $'($name)-live-after-v2.stderr'))
    assert ($error | str contains 'Failed historical replay retained at /tmp/radio-audit-replay.')
    assert ($error | str contains $base)
    assert ($error | str contains b933829cbe273d2f31fe75ca83125f3ddd8917a2)
  }
  let controls = (open ($root | path join controls/staging-v2/results.json))
  assert equal ($controls.stages | get files_equal) [13 90 620]
  for x in $controls.failures { assert equal $x.before $x.after; assert equal $x.historical_invoked false; assert equal $x.status 1 }
  assert equal ($controls.default_cli | length) 3
  assert equal (open ($root | path join controls/child-exit-v1/result.json) | get status) 77
  if $live {
    let actual = (^git -C $repo diff --no-renames --name-only $base | lines | append (^git -C $repo ls-files --others --exclude-standard | lines) | uniq | sort)
    assert equal $actual (open ($root | path join final-paths.json) | sort)
    assert (glob ($repo | path join audit '**' Cargo.toml) | is-empty)
  }
  rm --recursive $tmp
  {status: pass, files: ($files | length), historical_git_inputs: ($sources | length), index_bindings: ($bindings | length),
   packaging_files: ($freeze | length), snapshot_paths: ($delta | length), raw_records: ($raw | length),
   source_tuples: 63, consumer_cases: 8, consumer_commands_per_arm: 4, requires_exact_git_objects: true,
   cargo_rerun: false, broader_gates_refreshed: false} | to json
}
