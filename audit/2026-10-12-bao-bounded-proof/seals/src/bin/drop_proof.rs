fn main() {
    let proof = vec![0u8; 8];
    let view = bao_proof_seal_probes::finish(&proof);
    drop(proof);
    let _ = view.size();
}
