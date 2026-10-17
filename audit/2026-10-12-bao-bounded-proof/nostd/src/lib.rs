#![no_std]
pub fn job(bytes: &[u8]) -> Result<cyber_bao::proof::ProofVerifier<'_>, cyber_bao::proof::ProofError> { cyber_bao::proof::ProofVerifier::new(bytes, [0; 32], 0, cyber_bao::BlockSize(0), 0..0) }
