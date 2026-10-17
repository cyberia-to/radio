use std/assert

def main [--repo: string, --siblings: string, --live] {
  let root = $env.FILE_PWD
  let own = $repo
  let repos = {radio: $own, hemera: ($siblings | path join hemera),
    kadek: ($siblings | path join kadek), soft3: ($siblings | path join soft3)}
  let execution = ($own | path join audit/2026-10-12-bao-bounded-proof)
  let research = ($own | path join audit/2026-10-12-bao-proof-research)
  let m = (open ($root | path join manifest.json))
  let context = (open --raw ($root | path join context.txt) | into binary)
  assert equal ($context | hash sha256) $m.context_sha256
  assert equal ($context | bytes length) $m.context_bytes
  let temp = (^mktemp /tmp/radio-proof-code-replay.XXXXXX | str trim)
  mut rebuilt = ''
  mut git_count = 0
  mut excerpt_count = 0
  mut candidate_count = 0
  mut evidence_count = 0
  for s in $m.sections {
    let start = $s.offset
    let end = ($s.offset + $s.bytes - 1)
    let body = if $s.bytes == 0 { '' } else { $context | bytes at $start..$end | decode utf-8 }
    assert equal ($body | hash sha256) $s.sha256
    assert equal ($body | into binary | bytes length) $s.bytes
    $rebuilt += $s.header
    assert equal ($rebuilt | into binary | bytes length) $s.offset
    $rebuilt += $body
    $rebuilt += $s.footer
    let b = $s.binding
    if $b.kind in [git excerpt] {
      ^git -C ($repos | get $b.repository) cat-file blob $'($b.revision):($b.path)' out> $temp
      assert equal $env.LAST_EXIT_CODE 0
      let full = (open --raw $temp)
      if $b.kind == git {
        assert equal ($full | hash sha256) $s.sha256
        $git_count += 1
      } else {
        assert equal ($full | hash sha256) $b.source_sha256
        let selected = (($full | split row "\n" | skip ($b.first - 1) | take ($b.last - $b.first + 1) | str join "\n") + "\n")
        assert equal ($selected | hash sha256) $s.sha256
        $excerpt_count += 1
      }
    } else if $b.kind == candidate {
      assert equal (open --raw ($execution | path join $b.local) | hash sha256) $s.sha256
      if $live { assert equal (open --raw ($own | path join $b.path) | hash sha256) $s.sha256 }
      $candidate_count += 1
    } else {
      let source = match $b.kind { execution => $execution, research => $research, task => $own, _ => { error make {msg: 'unknown binding'} } }
      assert equal (open --raw ($source | path join $b.path) | hash sha256) $s.sha256
      $evidence_count += 1
    }
  }
  assert equal ($rebuilt | into binary) $context
  if $live { assert equal (^git -C $own rev-parse HEAD | str trim) $m.revision }
  rm $temp
  {status: pass, sections: ($m.sections | length), bytes: $m.context_bytes,
    sha256: $m.context_sha256, full_git_sources: $git_count, primary_excerpts: $excerpt_count,
    candidate_sources: $candidate_count, evidence_inputs: $evidence_count} | to json
}
