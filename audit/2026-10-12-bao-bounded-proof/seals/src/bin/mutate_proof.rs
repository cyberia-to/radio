fn main() {
    let mut proof = vec![0u8; 8];
    let view = bao_proof_seal_probes::finish(&proof);
    proof[0] = 1;
    let _ = view.size();
}
