use anyhow::Result;
use iroh_blobs::store::mem::MemStore;
use radio_integration_tests::init_tracing;

#[tokio::test]
async fn poseidon2_hash_deterministic() -> Result<()> {
    let data = b"poseidon2 determinism test";
    let h1 = cyber_poseidon2::hash(data);
    let h2 = cyber_poseidon2::hash(data);
    assert_eq!(h1, h2);
    Ok(())
}

#[tokio::test]
async fn poseidon2_hash_different_inputs() -> Result<()> {
    let h1 = cyber_poseidon2::hash(b"alpha");
    let h2 = cyber_poseidon2::hash(b"beta");
    assert_ne!(h1, h2);
    Ok(())
}

#[tokio::test]
async fn poseidon2_streaming_consistency() -> Result<()> {
    let data = b"streaming hash consistency test with enough data to matter a lot!!";
    let direct = cyber_poseidon2::hash(data);
    let streaming = {
        let mut hasher = cyber_poseidon2::Hasher::new();
        hasher.update(&data[..10]);
        hasher.update(&data[10..30]);
        hasher.update(&data[30..]);
        hasher.finalize()
    };
    assert_eq!(direct, streaming);
    Ok(())
}

#[tokio::test]
async fn blob_store_hash_matches_iroh_blobs_hash() -> Result<()> {
    init_tracing();
    let store = MemStore::new();
    let data = b"blob store hash consistency";

    // Add via store
    let tt = store.add_bytes(data.to_vec()).await?;
    let store_hash = tt.hash;

    // iroh-blobs Hash::new computes the BAO root hash
    let expected = iroh_blobs::Hash::new(data);
    assert_eq!(store_hash, expected);

    Ok(())
}

#[tokio::test]
async fn blob_store_hash_round_trip() -> Result<()> {
    init_tracing();
    let store = MemStore::new();

    // Add data, read it back, add again — hash should be identical
    let data = vec![0x42u8; 8192]; // 8 KB = multiple BAO chunks
    let tt1 = store.add_bytes(data.clone()).await?;
    let read_back = store.get_bytes(tt1.hash).await?;
    assert_eq!(read_back.as_ref(), data.as_slice());

    // Re-adding the same data should produce the same hash
    let tt2 = store.add_bytes(data).await?;
    assert_eq!(tt1.hash, tt2.hash);

    Ok(())
}

#[tokio::test]
async fn poseidon2_keyed_hash_differs() -> Result<()> {
    let data = b"keyed hash test";
    let plain = cyber_poseidon2::hash(data);
    let keyed = cyber_poseidon2::keyed_hash(&[0u8; 32], data);
    assert_ne!(plain, keyed);
    Ok(())
}

#[tokio::test]
async fn poseidon2_derive_key() -> Result<()> {
    let k1 = cyber_poseidon2::derive_key("radio/test", b"material");
    let k2 = cyber_poseidon2::derive_key("radio/test", b"material");
    assert_eq!(k1, k2);

    let k3 = cyber_poseidon2::derive_key("radio/other", b"material");
    assert_ne!(k1, k3);
    Ok(())
}
