use std/assert

# Historical names exist only in this disposable copy, never in the Git source.
export def stage [root: path, entry: string, manifests: list<string>] {
  assert ($entry in [verify.nu reproduce.nu]) 'Unexpected replay entry'
  let archived_entry = ($entry | str replace '.nu' '.original.nu.txt')
  let originals = ($manifests | append $entry)
  let archives = ($manifests | each {|p| $p + '.txt' } | append $archived_entry)
  for p in $manifests {
    assert (not (($root | path join $p) | path exists)) $'Logical Cargo path already exists: ($p)'
  }
  let hashes = ($archives | each {|p| open --raw ($root | path join $p) | hash sha256 })
  let wrapper = (open --raw ($root | path join $entry) | hash sha256)
  let directory = (^mktemp -d /tmp/radio-audit-replay.XXXXXX | str trim)
  assert equal $env.LAST_EXIT_CODE 0
  let capsule = ($directory | path join capsule)
  try {
    cp --recursive $root $capsule
    assert equal (open --raw ($capsule | path join $entry) | hash sha256) $wrapper
    for row in ($archives | enumerate) {
      let source = ($capsule | path join $row.item)
      assert equal (open --raw $source | hash sha256) ($hashes | get $row.index)
      let logical = ($originals | get $row.index)
      if $logical != $entry {
        assert (not (($capsule | path join $logical) | path exists)) 'Staging collision'
      }
      mv --force $source ($capsule | path join $logical)
    }
  } catch {|failure|
    error make {msg: $'($failure.msg); failed staging retained at ($directory)'}
  }
  {directory: $directory, capsule: $capsule}
}

export def finish [staged: record, status: int] {
  if $status == 0 {
    rm --recursive $staged.directory
  } else {
    print --stderr $'Failed historical replay retained at ($staged.directory)'
  }
  exit $status
}
