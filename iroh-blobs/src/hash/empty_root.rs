//! Published Hemera vectors, byte-preserving identities and real empty admission.
mod remote;
mod stores;

use std::{future::Future, str::FromStr, time::Duration};

use iroh::{EndpointAddr, PublicKey};
use iroh_tickets::Ticket;

use crate::{api::TempTag, ticket::BlobTicket, BlobFormat, Hash};

// Hemera d5f0a09539360934fb32db9b2e15a91995607db6 vectors/hemera.json.
const EMPTY_HEX: &str = "ea57b2e6b1ec7d2de11b15cb6d7060dd61d247fe0fbf5f7d3fb97a7be9328552";
const HELLO_HEX: &str = "626fa46e4e7bd5c87d630eef8333931a0b9198587400a0191eae7821692880d7";
const PLAIN_EMPTY_HEX: &str = "a67a71b221e6bdd6442a20432bf5d74c885d89e5dfbeec3ec4e334cb806d563c";

fn root(hex: &str) -> Hash {
    Hash::from_bytes(
        data_encoding::HEXLOWER
            .decode(hex.as_bytes())
            .unwrap()
            .try_into()
            .unwrap(),
    )
}

async fn bounded(test: impl Future<Output = ()>) {
    n0_future::time::timeout(Duration::from_secs(30), test)
        .await
        .expect("empty-root workflow exceeded 30 seconds");
}

fn hello_wire() -> Vec<u8> {
    let mut wire = 5u64.to_le_bytes().to_vec();
    wire.extend_from_slice(b"hello");
    wire
}

#[test]
fn published_empty_tree_domain() {
    let expected = root(EMPTY_HEX);
    assert_eq!(Hash::EMPTY, expected);
    assert_eq!(Hash::new(b""), expected);
    assert_eq!(
        hemera::tree::fixed_chunk_root(b"").as_bytes(),
        expected.as_bytes()
    );
    assert_eq!(
        hemera::tree::chunk_cv(b"", 0, true).as_bytes(),
        expected.as_bytes()
    );
    assert_eq!(hemera::hash(b"").to_hex(), PLAIN_EMPTY_HEX);
    assert_ne!(expected, root(PLAIN_EMPTY_HEX));
    assert_ne!(expected, Hash::from_bytes([0; 32]));
    assert_eq!(Hash::new(b"hello"), root(HELLO_HEX));
}

#[test]
fn raw_identity_serialization_preserves_all_bytes() {
    for hash in [root(EMPTY_HEX), Hash::from_bytes([0; 32]), root(HELLO_HEX)] {
        assert_eq!(Hash::from_str(&hash.to_hex()).unwrap(), hash);
        let binary = postcard::to_stdvec(&hash).unwrap();
        assert_eq!(binary, hash.as_bytes());
        assert_eq!(postcard::from_bytes::<Hash>(&binary).unwrap(), hash);
        let json = serde_json::to_string(&hash).unwrap();
        assert_eq!(json, format!("\"{}\"", hash.to_hex()));
        assert_eq!(serde_json::from_str::<Hash>(&json).unwrap(), hash);
    }
}

#[test]
fn ticket_envelope_preserves_canonical_zero_and_nonempty_keys() {
    let endpoint_hex = "ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6";
    let endpoint = PublicKey::from_str(endpoint_hex).unwrap();
    for hash in [root(EMPTY_HEX), Hash::from_bytes([0; 32]), root(HELLO_HEX)] {
        for (format, discriminant) in [(BlobFormat::Raw, 0), (BlobFormat::HashSeq, 1)] {
            let ticket = BlobTicket::new(EndpointAddr::new(endpoint), hash, format);
            let mut expected = vec![0]; // Variant0
            expected.extend(
                data_encoding::HEXLOWER
                    .decode(endpoint_hex.as_bytes())
                    .unwrap(),
            );
            expected.extend([0, 0, discriminant]); // no relay, no addresses, format
            expected.extend_from_slice(hash.as_bytes());
            assert_eq!(ticket.to_bytes(), expected);
            let parsed = BlobTicket::from_bytes(&expected).unwrap();
            assert_eq!(parsed, ticket);
            assert_eq!(parsed.hash(), hash);
            assert_eq!(parsed.format(), format);
        }
    }
}

#[test]
fn leaking_empty_tags_preserve_format() {
    for format in [BlobFormat::Raw, BlobFormat::HashSeq] {
        let tag = TempTag::leaking_empty(format);
        assert_eq!(tag.hash(), root(EMPTY_HEX));
        assert_eq!(tag.format(), format);
        assert_eq!(tag.hash_and_format(), (root(EMPTY_HEX), format).into());
        drop(tag);
    }
}
