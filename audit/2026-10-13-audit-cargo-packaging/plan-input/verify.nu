use std/assert

def check [root: string, f: record] {
  let data = (open --raw ($root | path join $f.path) | into binary)
  assert equal ($data | bytes length) $f.bytes
  assert equal ($data | hash sha256) $f.sha256
}

def main [--repo: string, --soft3: string, --live] {
  assert ($repo != null and $soft3 != null) 'Pass --repo and --soft3 containing the exact Git objects'
  let root = $env.FILE_PWD
  let files = (open ($root | path join files.json))
  for f in $files { check $root $f }
  let m = (open ($root | path join manifest.json))
  let context = (open --raw ($root | path join context.txt) | into binary)
  assert equal ($context | bytes length) $m.context_bytes
  assert equal ($context | hash sha256) $m.context_sha256
  let temp = (^mktemp /tmp/radio-audit-plan-replay.XXXXXX | str trim)
  mut rebuilt = ''
  mut git_count = 0
  mut index_count = 0
  mut excerpt_count = 0
  mut retained_count = 0
  for s in $m.sections {
    let end = ($s.offset + $s.bytes - 1)
    let body = if $s.bytes == 0 { '' } else { $context | bytes at $s.offset..$end | decode utf-8 }
    assert equal ($body | hash sha256) $s.sha256
    assert equal ($body | into binary | bytes length) $s.bytes
    $rebuilt += $s.header
    assert equal ($rebuilt | into binary | bytes length) $s.offset
    $rebuilt += $body
    $rebuilt += $s.footer
    assert equal (open --raw ($root | path join $s.local)) $body
    let b = $s.binding
    if $b.kind in [git index excerpt] {
      let source_repo = if $b.repository == radio { $repo } else { $soft3 }
      ^git -C $source_repo cat-file blob $'($b.revision):($b.path)' out> $temp
      assert equal $env.LAST_EXIT_CODE 0
      let source = (open --raw $temp)
      if $b.kind == git {
        assert equal $source $body
        $git_count += 1
      } else if $b.kind == index {
        assert equal ($source | hash sha256) $b.source_sha256
        assert equal ($source | into binary | bytes length) $b.source_bytes
        let selected = ($source | from json | where {|f| ($f.path | str ends-with 'Cargo.toml') or ($f.path | str ends-with 'verify.nu') })
        assert equal $selected ($body | from json)
        $index_count += 1
      } else {
        assert equal ($source | hash sha256) $b.sha256
        assert equal ($source | into binary | bytes length) $b.bytes
        let selected = (($source | split row "\n" | skip ($b.first - 1) | take ($b.last - $b.first + 1) | str join "\n") + "\n")
        assert equal $selected $body
        assert equal ($body | hash sha256) $b.excerpt_sha256
        $excerpt_count += 1
      }
    } else if $b.kind in [owned evidence] {
      if $live { assert equal (open --raw ($repo | path join $b.path)) $body }
      $retained_count += 1
    } else { assert equal $b.kind brief }
  }
  assert equal ($rebuilt | into binary) $context
  let sources = (open ($root | path join source-identities.json))
  for f in $sources {
    assert equal $f.revision $m.parent
    ^git -C $repo cat-file blob $'($f.revision):($f.path)' out> $temp
    assert equal $env.LAST_EXIT_CODE 0
    let source = (open --raw $temp | into binary)
    assert equal ($source | bytes length) $f.bytes
    assert equal ($source | hash sha256) $f.sha256
  }
  let evidence = {|label| let s = ($m.sections | where label == $label | first); open --raw ($root | path join $s.local) }
  let before = (do $evidence 'Packaging inputs/consumer-before.json' | from json)
  let after = (do $evidence 'Packaging inputs/consumer-after.json' | from json)
  assert equal ($before | reject at) ($after | reject at)
  assert equal ($before.source | length) 51
  assert equal ($before.inputs | length) 36
  let capture = (do $evidence 'Capture wrapper' | hash sha256)
  for name in [consumer-ce0-lock consumer-ce0-metadata research-before proof-before] {
    let record = (do $evidence $'records/($name).json' | from json)
    assert equal $record.exit_code 0
    assert equal $record.runner_sha256 $capture
    for stream in [stdout stderr] {
      let text = (do $evidence $'records/($name).($stream)')
      assert equal ($text | into binary | bytes length) ($record | get $stream | get bytes)
      assert equal ($text | hash sha256) ($record | get $stream | get sha256)
    }
  }
  for name in [consumer-ce0-lock consumer-ce0-metadata] {
    assert (do $evidence $'records/($name).stderr' | str contains 'warning: skipping duplicate package')
  }
  let renames = (do $evidence 'Packaging inputs/renames.json' | from json)
  assert equal ($renames | length) 7
  assert equal ($renames | get bytes | math sum) 2141
  for row in $renames { assert equal $row.archived ($row.logical + '.txt') }
  assert equal (do $evidence 'records/research-before.stdout' | from json | get status) pass
  assert equal (do $evidence 'records/proof-before.stdout' | from json | get status) pass
  rm $temp
  {status: pass, bytes: $m.context_bytes, sha256: $m.context_sha256, sections: ($m.sections | length),
   full_git_sections: $git_count, selected_index_sections: $index_count, primary_excerpts: $excerpt_count,
   retained_sections: $retained_count, source_identity_records: ($sources | length), archived_manifests: 7,
   raw_records: 4, production_changed: false} | to json
}
