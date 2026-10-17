fn main() {
    let proof = vec![0u8; 8];
    let view = bao_proof_seal_probes::finish(&proof);
    for item in view.items() {
        if let cyber_bao::proof::ProofItem::Leaf { bytes, .. } = item { bytes[0] = 1; }
    }
}
