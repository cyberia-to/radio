//! Error variants, literal coordinates and first-error precedence.
#[path = "support/proof.rs"]
mod support;

use cyber_bao::{
    BlockSize, TreeNode,
    proof::{ProofError, ProofVerifier},
    traversal::RangeTraversalError,
};
use hemera::{Hash, field::P};
use support::{Case, digest, named};

fn failure(c: &Case, expected: ProofError, action: usize) {
    let mut job =
        ProofVerifier::new(&c.wire, c.root, c.size, BlockSize(c.log), c.request.clone()).unwrap();
    for i in 1..action {
        assert!(
            job.step().unwrap().is_none(),
            "{} prematurely completed at {i}",
            c.name
        );
        assert!(!job.is_finished());
    }
    assert_eq!(
        job.step().unwrap_err(),
        expected,
        "{} action {action}",
        c.name
    );
    assert!(job.is_finished());
    for _ in 0..10 {
        assert_eq!(job.step().unwrap_err(), expected);
    }
}

#[test]
fn geometry_precedes_empty_request_and_root_canonicality() {
    for log in 0..=255 {
        let admitted = match usize::BITS {
            64 => log <= 51,
            32 => log <= 19,
            _ => panic!("unsupported host width"),
        };
        for size in [0, 1, u64::MAX] {
            let request = if size == 0 { 0..0 } else { 0..1 };
            let result = ProofVerifier::new(&[], [0; 32], size, BlockSize(log), request);
            if admitted {
                assert!(result.is_ok());
            } else {
                assert_eq!(
                    result.unwrap_err(),
                    ProofError::Geometry(RangeTraversalError::InvalidBlockSize)
                );
            }
        }
    }
    for request in [2..1, 0..6] {
        assert_eq!(
            ProofVerifier::new(&[], [255; 32], 5, BlockSize(0), request).unwrap_err(),
            ProofError::Geometry(RangeTraversalError::InvalidRange)
        );
    }
    assert_eq!(
        ProofVerifier::new(&[], [255; 32], 0, BlockSize(255), 1..0).unwrap_err(),
        ProofError::Geometry(RangeTraversalError::InvalidBlockSize)
    );
    assert_eq!(
        ProofVerifier::new(&[], [255; 32], 0, BlockSize(0), 0..1).unwrap_err(),
        ProofError::Geometry(RangeTraversalError::InvalidRange)
    );
    for at in [0, 2, 5] {
        assert_eq!(
            ProofVerifier::new(&[], [255; 32], 5, BlockSize(0), at..at).unwrap_err(),
            ProofError::EmptyRequest
        );
    }
}

#[test]
fn each_expected_root_word_has_exact_canonical_boundary() {
    for word in 0..4 {
        for value in [0, P - 1, P, u64::MAX] {
            let mut root = [0; 32];
            root[word * 8..word * 8 + 8].copy_from_slice(&value.to_le_bytes());
            let result = ProofVerifier::new(&[], root, 1, BlockSize(0), 0..1);
            if value < P {
                assert!(result.is_ok());
            } else {
                assert_eq!(
                    result.unwrap_err(),
                    ProofError::NonCanonicalRoot {
                        word: u8::try_from(word).unwrap()
                    }
                );
            }
        }
    }
    assert_eq!(
        ProofVerifier::new(&[], [255; 32], 1, BlockSize(0), 0..1).unwrap_err(),
        ProofError::NonCanonicalRoot { word: 0 }
    );
}

#[test]
fn header_size_is_trusted_input_and_every_truncation_is_exact() {
    for declared in [0, 4, 6, 4096, u64::MAX] {
        let mut c = named("hello");
        c.wire[..8].copy_from_slice(&declared.to_le_bytes());
        failure(
            &c,
            ProofError::SizeMismatch {
                expected: 5,
                declared,
            },
            1,
        );
    }
    for name in ["three-interior", "grouped-left"] {
        let mut c = named(name);
        let full = c.wire.clone();
        for len in 0..full.len() {
            c.wire = full[..len].to_vec();
            let (offset, needed, action) = if len < 8 {
                (0, 8, 1)
            } else if len < 72 {
                (8, 64, 2)
            } else if name == "three-interior" && len < 136 {
                (72, 64, 3)
            } else if name == "three-interior" {
                (136, 4096, 4)
            } else {
                (72, 8192, 3)
            };
            failure(&c, ProofError::Truncated { offset, needed }, action);
        }
    }
}

#[test]
fn both_children_all_words_reject_noncanonical_before_hashing() {
    for pair_start in [8, 72] {
        for child in [0, 32] {
            for word in 0..4 {
                for value in [P, u64::MAX] {
                    let mut c = named("three-interior");
                    let offset = pair_start + child + word * 8;
                    c.wire[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
                    failure(
                        &c,
                        ProofError::NonCanonicalHash { offset },
                        if pair_start == 8 { 2 } else { 3 },
                    );
                }
            }
        }
    }
    let mut c = named("three-interior");
    c.wire[8..16].copy_from_slice(&P.to_le_bytes());
    c.wire.truncate(71);
    failure(
        &c,
        ProofError::Truncated {
            offset: 8,
            needed: 64,
        },
        2,
    );
}

#[test]
fn canonical_parent_and_payload_corruption_never_publish() {
    for pair_start in [8, 72] {
        let mut c = named("three-interior");
        let left = c.wire[pair_start..pair_start + 32].to_vec();
        c.wire
            .copy_within(pair_start + 32..pair_start + 64, pair_start);
        c.wire[pair_start + 32..pair_start + 64].copy_from_slice(&left);
        failure(
            &c,
            ProofError::ParentMismatch {
                node: TreeNode::new(if pair_start == 8 { 3 } else { 1 }),
            },
            if pair_start == 8 { 2 } else { 3 },
        );
    }
    let mut c = named("three-interior");
    c.root = [0; 32];
    failure(
        &c,
        ProofError::ParentMismatch {
            node: TreeNode::new(3),
        },
        2,
    );
    let mut c = named("three-interior");
    c.wire[40..72].fill(0);
    failure(
        &c,
        ProofError::ParentMismatch {
            node: TreeNode::new(3),
        },
        2,
    );
    for (offset, start_chunk, action) in [(136, 0, 5), (4232, 1, 7)] {
        let mut c = named("three-boundary");
        c.wire[offset] ^= 1;
        failure(&c, ProofError::LeafMismatch { start_chunk }, action);
    }
    let mut c = named("sole-group");
    c.root = digest("11890a7e7cf1e4de463a04bf53bfdf269d627983a221daaf9029a3ff43297389");
    failure(&c, ProofError::LeafMismatch { start_chunk: 0 }, 5);
}

#[test]
fn representation_aliases_are_not_normalized() {
    let d = support::data(4096);
    let left = support::leaf(&d, 0);
    let zero = Hash::from_bytes([0; 32]);
    let root = support::parent(left, zero, true);
    let mut c = named("three-right");
    c.root = *root.as_bytes();
    c.size = 8192;
    c.request = 0..1;
    c.wire = 8192u64.to_le_bytes().to_vec();
    support::pair(&mut c.wire, left, zero);
    c.wire.extend_from_slice(&d);
    for word in 0..4 {
        let mut alias = c.wire.clone();
        let offset = 40 + word * 8;
        alias[offset..offset + 8].copy_from_slice(&P.to_le_bytes());
        std::mem::swap(&mut c.wire, &mut alias);
        failure(&c, ProofError::NonCanonicalHash { offset }, 2);
        std::mem::swap(&mut c.wire, &mut alias);
    }
}

#[test]
fn absolute_chunk_counter_is_not_relative_to_the_selected_group() {
    let mut c = named("three-right");
    let payload = c.wire[72..].to_vec();
    let wrong = support::leaf(&payload, 0);
    let zero = Hash::from_bytes([0; 32]);
    c.root = *support::parent(zero, wrong, true).as_bytes();
    c.wire = 12288u64.to_le_bytes().to_vec();
    support::pair(&mut c.wire, zero, wrong);
    c.wire.extend_from_slice(&payload);
    failure(&c, ProofError::LeafMismatch { start_chunk: 2 }, 4);
}

#[test]
fn exact_eof_is_a_separate_required_commit() {
    for name in ["empty", "hello", "three-boundary", "sole-group"] {
        for concatenate in [false, true] {
            let mut c = named(name);
            let end = c.wire.len();
            if concatenate {
                c.wire.extend_from_slice(&c.wire.clone());
            } else {
                c.wire.push(0);
            }
            failure(&c, ProofError::TrailingBytes { offset: end }, c.actions);
        }
    }
    let mut c = named("empty");
    c.root = [0; 32];
    failure(&c, ProofError::LeafMismatch { start_chunk: 0 }, 3);
    for name in ["hello", "three-right"] {
        let mut c = named(name);
        c.wire.truncate(8);
        failure(
            &c,
            ProofError::Truncated {
                offset: 8,
                needed: if name == "hello" { 5 } else { 64 },
            },
            2,
        );
    }
}

#[test]
fn maximum_frontier_prefix_uses_literal_small_missing_leaf() {
    let (root, wire) = support::deep_prefix();
    let c = Case {
        name: "deep",
        root,
        wire,
        size: u64::MAX,
        log: 0,
        request: 0..u64::MAX,
        actions: 56,
        output: Vec::new(),
    };
    failure(
        &c,
        ProofError::Truncated {
            offset: 7432,
            needed: 4096,
        },
        56,
    );
}

#[test]
#[cfg(target_pointer_width = "64")]
fn largest_group_width_is_geometry_not_allocation_admission() {
    let zero = Hash::from_bytes([0; 32]);
    let root = support::parent(zero, zero, true);
    let mut wire = u64::MAX.to_le_bytes().to_vec();
    support::pair(&mut wire, zero, zero);
    assert_eq!(wire.len(), 72);
    let c = Case {
        name: "large",
        root: *root.as_bytes(),
        wire,
        size: u64::MAX,
        log: 51,
        request: 0..1,
        actions: 3,
        output: Vec::new(),
    };
    failure(
        &c,
        ProofError::Truncated {
            offset: 72,
            needed: 1usize << 63,
        },
        3,
    );
}

#[test]
fn diagnostic_strings_and_core_error_trait_are_frozen() {
    fn core_error<E: core::error::Error>() {}
    core_error::<ProofError>();
    for (error, text) in [
        (
            ProofError::Geometry(RangeTraversalError::InvalidBlockSize),
            "invalid traversal block size",
        ),
        (
            ProofError::Geometry(RangeTraversalError::InvalidRange),
            "invalid traversal byte range",
        ),
        (ProofError::EmptyRequest, "empty request for nonempty file"),
        (
            ProofError::NonCanonicalRoot { word: 2 },
            "noncanonical expected root word 2",
        ),
        (
            ProofError::Truncated {
                offset: 72,
                needed: 4096,
            },
            "truncated proof at 72: need 4096 bytes",
        ),
        (
            ProofError::SizeMismatch {
                expected: 5,
                declared: 6,
            },
            "proof size 6 differs from expected 5",
        ),
        (
            ProofError::NonCanonicalHash { offset: 40 },
            "noncanonical proof hash word at 40",
        ),
        (
            ProofError::ParentMismatch {
                node: TreeNode::new(3),
            },
            "proof parent mismatch at node 3",
        ),
        (
            ProofError::LeafMismatch { start_chunk: 2 },
            "proof leaf mismatch at chunk 2",
        ),
        (
            ProofError::TrailingBytes { offset: 13 },
            "trailing proof bytes at 13",
        ),
    ] {
        assert_eq!(error.to_string(), text);
    }
}
