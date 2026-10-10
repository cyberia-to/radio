# Verify the retained capsule without running any command it records.
def checked [args: list<string>] {
    let r = (run-external ($args | first) ...($args | skip 1) | complete)
    if $r.exit_code != 0 { error make {msg: $"command failed: ($args | to nuon)\n($r.stderr)\n($r.stdout)"} }
    $r.stdout
}

def sha [p: path] { checked [shasum -a 256 $p] | split row ' ' | first }

def main [--source-root: path] {
    let audit = $env.FILE_PWD
    let capsule = ($audit | path join receipts.tar.gz)
    let inventory = (open ($audit | path join payload-inputs.json))
    let paths = ($inventory | get path | sort)
    if ($paths | uniq | length) != ($paths | length) { error make {msg: 'duplicate inventory path'} }
    for p in $paths {
        if ($p | str starts-with '/') or ($p =~ '(^|/)\.\.(/|$)') or ($p =~ '[^a-zA-Z0-9_./-]') {
            error make {msg: $"unsafe payload path: ($p)"}
        }
    }
    let members = (checked [tar -tzf $capsule] | lines | sort)
    if $members != $paths { error make {msg: 'archive/inventory member mismatch'} }
    let modes = (checked [tar -tvzf $capsule] | lines)
    if ($modes | length) != ($paths | length) or ($modes | any {|line| not ($line | str starts-with '-')}) {
        error make {msg: 'archive must contain only regular files'}
    }
    let destination = (checked [mktemp -d /tmp/radio-pairs-audit-check.XXXXXX] | str trim)
    checked [tar -xzf $capsule -C $destination] | ignore
    for r in $inventory {
        let file = ($destination | path join $r.path)
        if (sha $file) != $r.sha256 or (ls $file | get 0.size | into int) != $r.bytes {
            error make {msg: $"payload content mismatch: ($r.path); extraction retained at ($destination)"}
        }
    }
    mut records = 0
    for p in (glob ($destination | path join logs '*.json')) {
        let r = (open $p)
        if ($r | get -o stdout_sha256) != null {
            let stem = ($p | path parse | get stem)
            for stream in [stdout stderr] {
                let actual = (sha ($destination | path join logs $"($stem).($stream)"))
                if $actual != ($r | get $"($stream)_sha256") {
                    error make {msg: $"raw command stream mismatch: ($stem).($stream)"}
                }
            }
            $records += 1
        }
    }
    if $records != 202 { error make {msg: $"expected 202 raw command receipts, found ($records)"} }
    mut source_files = 0
    if $source_root != null {
        for r in (open ($audit | path join source-freeze.json)) {
            if (sha ($source_root | path join $r.path)) != $r.sha256 {
                error make {msg: $"source mismatch: ($r.path)"}
            }
            $source_files += 1
        }
    }
    {capsule_sha256: (sha $capsule), payload_files: ($paths | length),
        command_receipts: $records, raw_streams: ($records * 2),
        checked_source_files: $source_files, extraction: $destination} | to json
}
