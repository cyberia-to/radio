fn main() {
    fn require<T: serde::de::DeserializeOwned>() {}
    require::<cyber_bao::proof::VerifiedProof<'static>>();
}
