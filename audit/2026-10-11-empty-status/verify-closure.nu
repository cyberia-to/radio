# Read-only replay of live exported sources, raw receipts and counterpart identities.
# Unlike verify.nu, this auxiliary check needs the retained scaffold and local Git objects.
def checked [args: list<string>] {
 let r = (run-external ($args | first) ...($args | skip 1) | complete)
 if $r.exit_code != 0 { error make {msg: $'command failed: ($args | to nuon); ($r.stderr)'} }
 $r.stdout
}
def sha [p: path] { open --raw $p | hash sha256 }
def inventory [root: path] {
 checked [rg --files --hidden --no-ignore $root] | lines | sort | each {|p| {path: ($p | path relative-to $root), sha256: (sha $p)}} | sort-by path
}
def normalize [value: any] {
 $value | to json --raw | str replace --all '/candidate/' '/closure/' | str replace --all '/parent/' '/closure/' | str replace --all '/targets/candidate' '/targets/closure' | str replace --all '/targets/parent' '/targets/closure'
}
def main [--run: path = '/tmp/radio-empty-status.20261011-60036-oi3wr7', --radio-repo: path = '/Users/master/cyber/radio-kadek-empty-status', --hemera-repo: path = '/Users/master/cyber/hemera'] {
 let input = (open ($run | path join sources.json))
 let freeze = (open ($run | path join candidate-freeze.json))
 let witness = (open ($run | path join witness-overlay.json))
 let tag = (open ($run | path join tag-sources.json))
 let generated = (open ($run | path join generated-runtime-output.json))
 let tmp = (checked [mktemp -d /tmp/radio-source-replay.XXXXXX] | str trim)
 mkdir ($tmp | path join radio) ($tmp | path join hemera) ($tmp | path join tag)
 checked ([git -C $radio_repo archive --format=tar --output ($tmp | path join radio.tar) $input.radio] | append (open ($run | path join archives radio-pathspec.json))) | ignore
 checked [git -C $hemera_repo archive --format=tar --output ($tmp | path join hemera.tar) $input.hemera] | ignore
 checked [git -C $radio_repo archive --format=tar $tag.radio_revision --output ($tmp | path join tag-radio.tar) -- . ':(exclude)nettools/target'] | ignore
 for item in [{name: radio, digest: $input.archive_sha256.radio}, {name: hemera, digest: $input.archive_sha256.hemera}, {name: tag-radio, digest: $tag.radio_archive_sha256}] {
  if (sha ($tmp | path join $'($item.name).tar')) != $item.digest or (sha ($run | path join archives $'($item.name).tar')) != $item.digest { error make {msg: $'archive identity mismatch: ($item.name)'} }
 }
 checked [tar -xf ($tmp | path join radio.tar) -C ($tmp | path join radio)] | ignore
 checked [tar -xf ($tmp | path join hemera.tar) -C ($tmp | path join hemera)] | ignore
 checked [tar -xf ($tmp | path join tag-radio.tar) -C ($tmp | path join tag) --exclude=nettools/target] | ignore
 let base = (inventory ($tmp | path join radio))
 let hemera = (inventory ($tmp | path join hemera))
 let tagged = (inventory ($tmp | path join tag))
 let final = ($base | where {|r| $r.path not-in ($freeze.files | get path)} | append ($freeze.files | select path sha256) | sort-by path)
 let test_only = ($base | where {|r| $r.path not-in ($witness.files | get path)} | append ($witness.files | select path sha256) | sort-by path)
 let parent = ($base | append {path: $generated.path, sha256: $generated.sha256} | sort-by path)
 if (sha $generated.retained) != $generated.sha256 { error make {msg: 'generated seed mismatch'} }
 for scope in [{path: parent, expected: $parent}, {path: candidate, expected: $final}, {path: witness, expected: $test_only}, {path: tag, expected: $tagged}, {path: 'semver/current', expected: $final}, {path: 'semver/parent', expected: $base}, {path: 'semver/tag', expected: $tagged}] {
  if (inventory ($run | path join $scope.path radio)) != $scope.expected { error make {msg: $'complete source export mismatch: ($scope.path)/radio; temp retained at ($tmp)'} }
  if (inventory ($run | path join $scope.path hemera)) != $hemera { error make {msg: $'complete source export mismatch: ($scope.path)/hemera'} }
 }
 mut raw = 0
 for p in (glob ($run | path join logs '*.json')) {
  let r = (open $p)
  if ($r.stdout_sha256? | default null) != null {
   let stem = ($p | path parse | get stem)
   for stream in [stdout stderr] { if (sha ($run | path join logs $'($stem).($stream)')) != ($r | get $'($stream)_sha256') { error make {msg: $'raw mismatch: ($stem).($stream)'} } }
   $raw += 1
  }
 }
 let mapping = (open ($run | path join counterpart-ci-run-none.json))
 let c = (open ($run | path join logs $'candidate-($mapping.candidate).json'))
 let p = (open ($run | path join logs $'parent-($mapping.parent).json'))
 let cases = (open --raw ($run | path join logs $'candidate-($mapping.candidate).stderr') | lines | parse --regex '^\s*(?<status>FAIL|TIMEOUT)\s+\[[^\]]+\]\s+(?<binary>\S+)\s+(?<test>\S+)' | uniq)
 let filter = ($cases | each {|r| ['(binary_id(=' $r.binary ') and test(=' $r.test '))'] | str join} | str join ' or ')
 if $cases != $mapping.selected_cases or $c.argv != $mapping.candidate_argv or ($p.argv | skip 1) != $mapping.parent_cargo_args or $p.argv != ($c.argv | append [-E $filter]) or (normalize $p.environment) != (normalize $c.environment) { error make {msg: 'narrow runtime counterpart mapping mismatch'} }
 mut pairs = 0
 for r in (open ($run | path join paired-diagnostics.json) | get gates) {
  let cf = ($run | path join logs $'candidate-($r.name).json')
  let pf = ($run | path join logs $'parent-($r.parent_name).json')
  if (sha $cf) != $r.candidate_receipt_sha256 or (sha $pf) != $r.parent_receipt_sha256 { error make {msg: 'paired diagnostic receipt identity mismatch'} }
  if (open $cf).argv != (open $pf).argv { error make {msg: 'paired command mismatch'} }
  $pairs += 1
 }
 let native_c = (open ($run | path join logs candidate-native-nextest.json))
 let native_p = (open ($run | path join logs parent-native-nextest.json))
 if $native_c.argv != $native_p.argv or (normalize $native_c.environment) != (normalize $native_p.environment) { error make {msg: 'full native comparator identity mismatch'} }
 for pair in [[parent-native-clippy parent-native-clippy-after-sigkill] [candidate-semver-parent-iroh-blobs candidate-semver-parent-iroh-blobs-after-sigkill]] {
  let first = (open ($run | path join logs $'($pair.0).json'))
  let last = (open ($run | path join logs $'($pair.1).json'))
  if $first.argv != $last.argv or $first.environment != $last.environment or not (open --raw ($run | path join logs $'($pair.0).stderr') | str contains SIGKILL) { error make {msg: 'follow-up identity mismatch'} }
 }
 rm -r $tmp
 {radio: $input.radio, hemera: $input.hemera, archives_reproduced_from_git: 3, base_radio_files: ($base | length), hemera_files: ($hemera | length), final_radio_files: ($final | length), tag_radio_files: ($tagged | length), complete_export_pairs_checked: 7, source_freeze_sha256: (sha ($run | path join candidate-freeze.json)), command_records: $raw, raw_streams: ($raw * 2), paired_diagnostic_records_bound_to_raw: $pairs, narrowed_runtime_mapping_checked: true, full_native_comparator_checked: true, exact_sigkill_followups_checked: 2, generated_parent_seed_retained: true, note: 'Integrity and command/scope identities only. Diagnostic equality assertions are separately derived in paired-diagnostics.json; no red outcome becomes green.'} | to json
}
