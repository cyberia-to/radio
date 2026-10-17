# Validate retained evidence; never execute a command recorded by the capsule.
def checked [args: list<string>] {
    let r = (run-external ($args | first) ...($args | skip 1) | complete)
    if $r.exit_code != 0 {
        error make {msg: $"command failed: ($args | to nuon)\n($r.stderr)\n($r.stdout)"}
    }
    $r.stdout
}

def sha [file: path] { open --raw $file | hash sha256 }

def review [destination: path, directory: string, index: string, bundle: string, overview: string] {
    let root = ($destination | path join $directory)
    let rows = (open ($root | path join $index))
    mut body = if $overview == '' { '' } else { open --raw ($root | path join $overview) }
    for entry in ($rows | enumerate) {
        let r = $entry.item
        let payload = ($r | get -o payload)
        let file = if $payload == null {
            $root | path join inputs ($r.file | path basename)
        } else { $destination | path join $payload }
        if (sha $file) != $r.sha256 or (ls $file | get 0.size | into int) != $r.bytes {
            error make {msg: $"review input mismatch: ($directory) / ($r.file)"}
        }
        let original = ($r | get -o original_input | default $r.file)
        let label = ($r | get -o path | default ($original | path basename))
        $body += $"\n===== SOURCE ($entry.index + 1): ($r.owner) / ($label) =====\nSHA256 ($r.sha256); ($r.note)\n"
        $body += (open --raw $file)
        $body += "\n===== END SOURCE =====\n"
    }
    if ($body | hash sha256) != (sha ($root | path join $bundle)) {
        error make {msg: $"review bundle reconstruction mismatch: ($directory)"}
    }
    $rows | length
}

def main [--source-root: path] {
    let audit = $env.FILE_PWD
    for line in (open --raw ($audit | path join SHA256SUMS) | lines) {
        let parsed = ($line | parse --regex '^(?<sha>[a-f0-9]{64})  (?<path>[a-zA-Z0-9_.-]+)$')
        if ($parsed | length) != 1 { error make {msg: 'invalid outer checksum line'} }
        let row = ($parsed | first)
        if (sha ($audit | path join $row.path)) != $row.sha {
            error make {msg: $"outer file changed: ($row.path)"}
        }
    }
    let capsule = ($audit | path join receipts.tar.gz)
    let meta = (open ($audit | path join capsule.json))
    let inventory = (open ($audit | path join payload-inputs.json))
    let paths = ($inventory | get path | sort)
    if (sha $capsule) != $meta.sha256 or ($paths | length) != $meta.payload_files {
        error make {msg: 'capsule identity/count mismatch'}
    }
    if ($paths | uniq | length) != ($paths | length) { error make {msg: 'duplicate payload path'} }
    for p in $paths {
        if ($p | str starts-with '/') or ($p =~ '(^|/)\.\.(/|$)') or ($p =~ '[^a-zA-Z0-9_./-]') {
            error make {msg: $"unsafe payload path: ($p)"}
        }
    }
    if (checked [tar -tzf $capsule] | lines | sort) != $paths {
        error make {msg: 'archive/inventory member mismatch'}
    }
    let modes = (checked [tar -tvzf $capsule] | lines)
    if ($modes | length) != ($paths | length) or ($modes | any {|line| not ($line | str starts-with '-')}) {
        error make {msg: 'archive must contain regular files only'}
    }
    let destination = (checked [mktemp -d /tmp/radio-empty-audit-check.XXXXXX] | str trim)
    checked [tar -xzf $capsule -C $destination] | ignore
    for r in $inventory {
        let file = ($destination | path join $r.path)
        if (sha $file) != $r.sha256 or (ls $file | get 0.size | into int) != $r.bytes {
            error make {msg: $"payload mismatch: ($r.path); extraction retained at ($destination)"}
        }
    }
    mut records = 0
    for p in (glob ($destination | path join logs '*.json')) {
        let r = (open $p)
        if ($r | get -o stdout_sha256) != null {
            let stem = ($p | path parse | get stem)
            for stream in [stdout stderr] {
                if (sha ($destination | path join logs $"($stem).($stream)")) != ($r | get $"($stream)_sha256") {
                    error make {msg: $"raw stream mismatch: ($stem).($stream)"}
                }
            }
            $records += 1
        }
    }
    if $records != $meta.command_records { error make {msg: 'command receipt count mismatch'} }
let bounded = (review $destination reviews/code-bounded index.json brief.txt overview.txt)
let plan = (review $destination reviews/plan index.json brief.txt overview.txt)
let historical = (checked [nu ($destination | path join historical superseded344 audit verify.nu)] | from json)
    mut source_files = 0
    for r in (open ($audit | path join source-freeze.json) | get files) {
        if (sha ($destination | path join sources final $r.path)) != $r.sha256 {
            error make {msg: $"retained source mismatch: ($r.path)"}
        }
        if $source_root != null {
            if (sha ($source_root | path join $r.path)) != $r.sha256 {
                error make {msg: $"checkout source mismatch: ($r.path)"}
            }
            $source_files += 1
        }
    }
    rm -r $destination
    {capsule_sha256: $meta.sha256, payload_files: ($paths | length),
        command_receipts: $records, raw_streams: ($records * 2),
        bounded_review_sections: $bounded, plan_sections: $plan,
        historical_capsule_sha256: $historical.capsule_sha256,
        checked_checkout_sources: $source_files, extraction_removed: true} | to json
}
