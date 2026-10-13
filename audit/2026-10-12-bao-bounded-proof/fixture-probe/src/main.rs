#[path = "../../../../cyber-bao/tests/support/proof.rs"]
mod fixtures;
fn main() {
    let dir = std::path::PathBuf::from(std::env::args_os().nth(1).unwrap());
    for c in fixtures::cases() {
        let name = format!("{}-log{}.bin", c.name, c.log);
        std::fs::write(dir.join(&name), &c.wire).unwrap();
        println!("{name} root={} size={} request={}..{} bytes={} actions={} output={:?}", hemera::Hash::from_bytes(c.root), c.size, c.request.start, c.request.end, c.wire.len(), c.actions, c.output);
    }
    let (root, wire) = fixtures::deep_prefix();
    std::fs::write(dir.join("synthetic-deep-prefix.bin"), &wire).unwrap();
    println!("synthetic-deep-prefix root={} bytes={} error_action=56 missing_offset=7432 missing_bytes=4096", hemera::Hash::from_bytes(root), wire.len());
}
