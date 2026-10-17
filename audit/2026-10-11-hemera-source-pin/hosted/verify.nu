def require [ok: bool, msg: string] { if not $ok { error make {msg: $msg} } }
def raw [root: path, name: string] {
    let result = (^gzip -dc ($root | path join $name) | complete)
    require ($result.exit_code == 0) $'gzip failed: ($name)'
    $result.stdout
}
def main [root: path = '.'] {
    let root = ($root | path expand)
    for row in (open --raw ($root | path join SHA256SUMS) | lines | parse '{sha256}  {path}') {
        require ((open --raw ($root | path join $row.path) | hash sha256) == $row.sha256) $'checksum differs: ($row.path)'
    }
    mut retrievals = 0
    for file in (glob ($root | path join '*.json')) {
        let record = (open $file)
        if ($record | get -o stdout_gzip_sha256) == null { continue }
        let base = ($file | path basename | str replace --regex '\.json$' '')
        let content = (raw $root $'($base).stdout.gz')
        require (($content | hash sha256) == $record.stdout_sha256 and ($content | str length --utf-8-bytes) == $record.stdout_bytes and $record.exit == 0) $'retrieval differs: ($base)'
        require ((open --raw ($root | path join $'($base).stdout.gz') | hash sha256) == $record.stdout_gzip_sha256) 'gzip identity differs'
        require ((open --raw ($root | path join $'($base).stderr') | hash sha256) == $record.stderr_sha256) 'stderr differs'
        $retrievals += 1
    }
    require ($retrievals == 14) 'retrieval count differs'
    let original = (open ($root | path join codespell-original.json))
    let spell = (raw $root codespell-logs.stdout.gz)
    require (($spell | hash sha256) == $original.stdout.sha256 and ($spell | str length --utf-8-bytes) == $original.stdout.bytes and $original.exit_code == 0) 'original spelling receipt differs'
    let analysis = (raw $root analysis.json.gz | from json)
    require ($analysis.codespell.findings == 157 and $analysis.codespell.inherited == 139 and $analysis.codespell.introduced == 18) 'spelling counts differ'
    require (($analysis.codespell.records | where unchanged == true | length) == 139 and ($analysis.codespell.records | where unchanged == false | length) == 18) 'spelling classification differs'
    require (($analysis.format.identities | length) == 131 and $analysis.format.sections == 300 and ($analysis.format.identities | all {|r| $r.unchanged and $r.parent_entry == $r.head_entry})) 'format attribution differs'
    let head = 'd90a784fa6a7f410492cc6c6d5242527e221c399'
    let merge = (raw $root merge-commit.stdout.gz | from json)
    require ($merge.sha == '2d606fbc2638c52c9613ea7d712a6f35ee32a48c' and $merge.tree.sha == '0f77ec947fb72f1ea9c4df3dd82514aa03294fb6' and $merge.parents.sha == ['a11d342594949d4ea542b26366f71d56ef21662d' $head]) 'merge checkout differs'
    for name in [wasm semver fmt docs clippy deny codespell] {
        let metadata = (raw $root $'($name)-metadata.stdout.gz' | from json)
        require ($metadata.head_sha == $head and $metadata.run_id == 38177461896 and $metadata.conclusion == failure) 'hosted job identity differs'
        require ((raw $root $'($name)-logs.stdout.gz') | str contains $merge.sha) 'checkout log differs'
    }
    require ($analysis.direct_input_identities | all {|r| $r.unchanged and $r.parent_entry == $r.head_entry}) 'direct source identity differs'
    require $analysis.cfg_aliases_lock_entry.parent_equal 'macro dependency differs'
    {status: pass, retrievals: $retrievals, original_root_retrieval: 1, jobs: 7,
     format_sections: 300, format_unchanged_paths: 131, spelling: {total: 157, unchanged: 139, introduced: 18},
     gates_rerun: false, scope: 'Saved hosted evidence only; no green CI or hosted-parent run claimed.'} | to json | print
}
