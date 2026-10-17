use std/assert

def main [--repo: string, --live] {
  assert ($repo != null) 'Pass --repo containing the exact ce0 Git objects'
  let root = $env.FILE_PWD
  for f in (open ($root | path join files.json)) {
    let b = (open --raw ($root | path join $f.path) | into binary)
    assert equal ($b | bytes length) $f.bytes
    assert equal ($b | hash sha256) $f.sha256
  }
  let m = (open ($root | path join manifest.json))
  let context = (open --raw ($root | path join context.txt) | into binary)
  assert equal ($context | bytes length) $m.context_bytes
  assert equal ($context | hash sha256) $m.context_sha256
  let temp = (^mktemp /tmp/radio-packaging-code.XXXXXX | str trim)
  mut rebuilt = ''
  mut git_sections = 0
  mut owned_sections = 0
  for s in $m.sections {
    let body = if $s.bytes == 0 { '' } else { $context | bytes at $s.offset..($s.offset + $s.bytes - 1) | decode utf-8 }
    assert equal ($body | into binary | bytes length) $s.bytes
    assert equal ($body | hash sha256) $s.sha256
    assert equal (open --raw ($root | path join $s.local)) $body
    $rebuilt += $s.header
    assert equal ($rebuilt | into binary | bytes length) $s.offset
    $rebuilt += $body
    $rebuilt += $s.footer
    let b = $s.binding
    if $b.kind == git {
      ^git -C $repo cat-file blob $'($b.revision):($b.path)' out> $temp
      assert equal $env.LAST_EXIT_CODE 0
      assert equal (open --raw $temp) $body
      $git_sections += 1
    } else if $b.kind == owned {
      if $live { assert equal (open --raw ($repo | path join $b.path)) $body }
      $owned_sections += 1
    } else { assert equal $b.kind brief }
  }
  assert equal ($rebuilt | into binary) $context
  let freeze = (open ($root | path join source-freeze.json))
  for f in $freeze {
    let s = ($m.sections | where {|s| ($s.binding | get -o path) == $f.path } | first)
    assert equal $s.bytes $f.bytes
    assert equal $s.sha256 $f.sha256
    if ($f.path | str ends-with Cargo.toml.txt) or ($f.path | str ends-with .original.nu.txt) {
      let prior = if ($f.path | str ends-with Cargo.toml.txt) { $f.path | str replace '.toml.txt' '.toml' } else { $f.path | str replace '.original.nu.txt' '.nu' }
      ^git -C $repo cat-file blob $'($m.parent):($prior)' out> $temp
      assert equal $env.LAST_EXIT_CODE 0
      assert equal (open --raw $temp | hash sha256) $f.sha256
    }
  }
  rm $temp
  {status: pass, bytes: $m.context_bytes, sha256: $m.context_sha256, sections: ($m.sections | length),
    full_git_sections: $git_sections, owned_sections: $owned_sections,
    exact_packaging_files: ($freeze | length), cargo_rerun: false} | to json
}
