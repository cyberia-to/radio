fn main() {
    let proof = vec![0u8; 8];
    let view = bao_proof_seal_probes::finish(&proof);
    assert_eq!(view.size(), 0);
    assert!(view.items().is_complete());
}
