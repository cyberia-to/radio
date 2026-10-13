use ../2026-10-13-audit-cargo-packaging/replay.nu [stage finish]

def main [
  --implementation-revision: string
  --radio-repo: path = "~/cyber/radio"
  --hemera-repo: path = "~/cyber/hemera"
  --fetch
  --full-workspace
] {
  if $implementation_revision == null {
    error make {msg: '--implementation-revision must name the actual committed implementation'}
  }
  let staged = (stage $env.FILE_PWD reproduce.nu [Cargo.toml])
  mut args = [--implementation-revision $implementation_revision --radio-repo ($radio_repo | path expand) --hemera-repo ($hemera_repo | path expand)]
  if $fetch { $args = ($args | append '--fetch') }
  if $full_workspace { $args = ($args | append '--full-workspace') }
  let result = (^($nu.current-exe) ($staged.capsule | path join reproduce.nu) ...$args | complete)
  print --no-newline $result.stdout
  print --stderr --no-newline $result.stderr
  finish $staged $result.exit_code
}
