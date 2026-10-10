use iroh::{EndpointAddr, SecretKey};
use iroh_tickets::Ticket;

use super::Hash;
use crate::{ticket::BlobTicket, BlobFormat};

#[test]
fn published_tree_anchors() {
    for (data, expected) in [
        (
            &b""[..],
            "ea57b2e6b1ec7d2de11b15cb6d7060dd61d247fe0fbf5f7d3fb97a7be9328552",
        ),
        (
            &b"hello"[..],
            "626fa46e4e7bd5c87d630eef8333931a0b9198587400a0191eae7821692880d7",
        ),
    ] {
        assert_eq!(Hash::new(data).to_hex(), expected);
        assert_eq!(hemera::tree::fixed_chunk_root(data).to_hex(), expected);
    }
}

#[test]
fn canonical_key_and_legacy_ticket_bytes() {
    let data: Vec<u8> = (0..8192)
        .map(|i| ((i * 31 + i / 4096) % 256) as u8)
        .collect();
    let canonical: Hash = "2abf65dd26465a7352707d79d18ff3aab9ee5d97614a774619c79ed527e20190"
        .parse()
        .unwrap();
    let old: Hash = "11890a7e7cf1e4de463a04bf53bfdf269d627983a221daaf9029a3ff43297389"
        .parse()
        .unwrap();
    assert_eq!(Hash::new(&data), canonical);
    assert_eq!(Hash::from(hemera::tree::fixed_chunk_root(&data)), canonical);
    let addr = EndpointAddr::new(SecretKey::from_bytes(&[42; 32]).public());
    for root in [canonical, old] {
        let ticket = BlobTicket::new(addr.clone(), root, BlobFormat::Raw);
        let bytes = ticket.to_bytes();
        let parsed = BlobTicket::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.hash(), root);
        assert_eq!(parsed.to_bytes(), bytes);
    }
    assert_ne!(canonical, old);
}
