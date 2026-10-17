fn main() {
    fn require<T: serde::Deserialize<'static>>() {}
    require::<cyber_bao::proof::VerifiedProof<'static>>();
}
