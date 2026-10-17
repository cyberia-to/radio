use ../2026-10-13-audit-cargo-packaging/replay.nu [stage finish]

def main [--repo: string, --live] {
  let own = if $repo == null { $env.FILE_PWD | path dirname | path dirname } else { $repo | path expand }
  let staged = (stage $env.FILE_PWD verify.nu [fixture-probe/Cargo.toml nostd/Cargo.toml nostd-parent/Cargo.toml seals/Cargo.toml])
  let args = ([--repo $own] | append (if $live { [--live] } else { [] }))
  let result = (^($nu.current-exe) ($staged.capsule | path join verify.nu) ...$args | complete)
  print --no-newline $result.stdout
  print --stderr --no-newline $result.stderr
  finish $staged $result.exit_code
}
