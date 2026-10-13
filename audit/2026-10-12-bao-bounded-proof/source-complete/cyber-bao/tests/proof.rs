//! Literal schedules, borrowed output and external scheduling; no legacy roundtrip oracle.
#[path = "support/proof.rs"]
mod support;

use cyber_bao::{
    BlockSize,
    proof::{ProofItem, ProofVerifier, VerifiedProof},
};
use support::{Case, cases, named};

fn finish(c: &Case) -> VerifiedProof<'_> {
    let mut job =
        ProofVerifier::new(&c.wire, c.root, c.size, BlockSize(c.log), c.request.clone()).unwrap();
    for index in 1..c.actions {
        assert!(!job.is_finished(), "{} action {index}", c.name);
        assert!(job.step().unwrap().is_none(), "{} action {index}", c.name);
    }
    assert!(!job.is_finished());
    let view = job.step().unwrap().expect("EOF action seals once");
    assert!(job.is_finished());
    for _ in 0..10 {
        assert!(job.step().unwrap().is_none());
    }
    view
}

fn output(c: &Case, view: &VerifiedProof<'_>) {
    assert_eq!(view.root(), c.root);
    assert_eq!(view.size(), c.size);
    assert_eq!(view.block_size(), BlockSize(c.log));
    assert_eq!(view.request(), c.request);
    let mut changed_copy = view.request();
    changed_copy.start = u64::MAX;
    assert_ne!(changed_copy, view.request());
    let mut items = view.items();
    let mut other = view.items();
    fn fused<T: std::iter::FusedIterator>(_: &T) {}
    fused(&items);
    assert_eq!(items.is_complete(), c.output.is_empty());
    let mut requested = Vec::new();
    for (index, expected) in c.output.iter().enumerate() {
        assert!(!items.is_complete());
        let item = items.next().unwrap();
        let parallel = other.next().unwrap();
        match (item, parallel, expected) {
            (ProofItem::Parent, ProofItem::Parent, None) => {}
            (
                ProofItem::Leaf {
                    file_offset,
                    proof_offset,
                    bytes,
                },
                ProofItem::Leaf {
                    file_offset: f,
                    proof_offset: p,
                    bytes: b,
                },
                Some((offset, file, len)),
            ) => {
                assert_eq!(
                    (proof_offset, file_offset, bytes.len()),
                    (*offset, *file, *len)
                );
                assert_eq!((f, p, b), (file_offset, proof_offset, bytes));
                assert_eq!(bytes, &c.wire[*offset..*offset + *len]);
                assert_eq!(bytes.as_ptr(), c.wire[*offset..].as_ptr());
                let start = c.request.start.max(file_offset);
                let end = c
                    .request
                    .end
                    .min(file_offset + u64::try_from(bytes.len()).unwrap());
                requested.extend_from_slice(
                    &bytes[usize::try_from(start - file_offset).unwrap()
                        ..usize::try_from(end - file_offset).unwrap()],
                );
            }
            _ => panic!("{} event {index}", c.name),
        }
        assert_eq!(items.is_complete(), index + 1 == c.output.len());
    }
    for _ in 0..10 {
        assert!(items.next().is_none());
        assert!(other.next().is_none());
    }
    if c.name == "hello" {
        assert_eq!(requested, b"ell");
    } else if c.size != 0 {
        let body = support::data(usize::try_from(c.size).unwrap());
        assert_eq!(
            requested,
            body[usize::try_from(c.request.start).unwrap()
                ..usize::try_from(c.request.end).unwrap()]
        );
    } else {
        assert!(requested.is_empty());
    }
}

#[test]
fn literal_schedules_and_exact_borrowed_coordinates() {
    for c in cases() {
        let view = finish(&c);
        output(&c, &view);
    }
}

#[test]
fn caller_quotas_and_total_are_not_renewed_by_groups_or_yields() {
    for c in cases() {
        for quota in [1, 2, c.actions, c.actions + 1] {
            for limit in [c.actions - 1, c.actions, c.actions + 1] {
                let mut job = ProofVerifier::new(
                    &c.wire,
                    c.root,
                    c.size,
                    BlockSize(c.log),
                    c.request.clone(),
                )
                .unwrap();
                let mut paid = 0;
                let mut completed = None;
                while !job.is_finished() && paid < limit {
                    for _ in 0..quota {
                        if job.is_finished() || paid == limit {
                            break;
                        }
                        paid += 1; // external harness budget, not a Radio or Kadek API
                        if let Some(view) = job.step().unwrap() {
                            completed = Some(view);
                        }
                    }
                }
                assert_eq!(paid, limit.min(c.actions));
                assert_eq!(completed.is_some(), limit >= c.actions);
                assert_eq!(job.is_finished(), limit >= c.actions);
                if let Some(view) = completed {
                    output(&c, &view);
                }
            }
        }
    }
}

#[test]
fn jobs_can_interleave_and_views_outlive_verifiers_and_cursors() {
    let a = named("three-boundary");
    let b = named("grouped-left");
    let (va, vb) = {
        let mut ja =
            ProofVerifier::new(&a.wire, a.root, a.size, BlockSize(a.log), a.request.clone())
                .unwrap();
        let mut jb =
            ProofVerifier::new(&b.wire, b.root, b.size, BlockSize(b.log), b.request.clone())
                .unwrap();
        for _ in 1..b.actions {
            assert!(ja.step().unwrap().is_none());
            assert!(jb.step().unwrap().is_none());
        }
        let vb = jb.step().unwrap().unwrap();
        assert!(ja.step().unwrap().is_none());
        let va = ja.step().unwrap().unwrap();
        (va, vb)
    };
    output(&a, &va);
    output(&b, &vb);
    let kept = {
        let mut items = vb.items();
        assert!(matches!(items.next(), Some(ProofItem::Parent)));
        match items.next().unwrap() {
            ProofItem::Leaf { bytes, .. } => bytes,
            _ => unreachable!(),
        }
    };
    assert_eq!(kept, &b.wire[72..]);
}

#[test]
fn cancelling_at_each_pending_stage_publishes_nothing() {
    for c in cases() {
        for stop in 0..c.actions {
            let mut job =
                ProofVerifier::new(&c.wire, c.root, c.size, BlockSize(c.log), c.request.clone())
                    .unwrap();
            for _ in 0..stop {
                assert!(job.step().unwrap().is_none());
            }
            assert!(!job.is_finished());
        }
    }
}

#[test]
fn debug_does_not_print_payload() {
    let c = named("hello");
    let job =
        ProofVerifier::new(&c.wire, c.root, c.size, BlockSize(c.log), c.request.clone()).unwrap();
    assert!(!format!("{job:?}").contains("104, 101, 108, 108, 111"));
    let view = finish(&c);
    assert!(!format!("{view:?}").contains("104, 101, 108, 108, 111"));
    let mut items = view.items();
    assert!(!format!("{items:?}").contains("104, 101, 108, 108, 111"));
    assert!(!format!("{:?}", items.next().unwrap()).contains("104, 101, 108, 108, 111"));
}

#[test]
fn parent_after_payload_resumes_the_frontier_and_borrowed_output() {
    // Independent four-leaf tree and literal carrier; no encoder or traversal oracle.
    let body: Vec<u8> = (0..16384)
        .map(|i| ((29 * i + 7 * (i / 4096)) % 251) as u8)
        .collect();
    let l0 = support::leaf(&body[..4096], 0);
    let l1 = support::leaf(&body[4096..8192], 1);
    let l2 = support::leaf(&body[8192..12288], 2);
    let l3 = support::leaf(&body[12288..], 3);
    let p01 = support::parent(l0, l1, false);
    let p23 = support::parent(l2, l3, false);
    let root = support::parent(p01, p23, true);
    assert_eq!(
        *root.as_bytes(),
        support::digest("e621f66b42fb61b260200dfa649d3f16d35cde5af2e8c04cc2551c109f00c6f6")
    );
    let mut wire = u64::try_from(body.len()).unwrap().to_le_bytes().to_vec();
    support::pair(&mut wire, p01, p23);
    support::pair(&mut wire, l0, l1);
    wire.extend_from_slice(&body[..8192]);
    assert_eq!(wire.len(), 8328);
    support::pair(&mut wire, l2, l3);
    wire.extend_from_slice(&body[8192..12288]);
    assert_eq!(wire.len(), 12488);
    let c = Case {
        name: "four-interleaved",
        root: *root.as_bytes(),
        size: 16384,
        log: 0,
        request: 4095..8193,
        wire,
        actions: 11,
        output: vec![
            None,
            None,
            Some((136, 0, 4096)),
            Some((4232, 4096, 4096)),
            None,
            Some((8392, 8192, 4096)),
        ],
    };
    for stop in 0..11 {
        let mut job =
            ProofVerifier::new(&c.wire, c.root, c.size, BlockSize(0), 4095..8193).unwrap();
        for _ in 0..stop {
            assert!(job.step().unwrap().is_none());
        }
        assert!(!job.is_finished());
    }
    let view = finish(&c);
    let mut items = view.items();
    let mut selected = Vec::new();
    for expected in &c.output {
        assert!(!items.is_complete());
        match (items.next().unwrap(), expected) {
            (ProofItem::Parent, None) => {}
            (
                ProofItem::Leaf {
                    proof_offset,
                    file_offset,
                    bytes,
                },
                Some((p, f, n)),
            ) => {
                assert_eq!((proof_offset, file_offset, bytes.len()), (*p, *f, *n));
                assert_eq!(bytes.as_ptr(), c.wire[*p..].as_ptr());
                let begin = usize::try_from(*f).unwrap();
                assert_eq!(bytes, &body[begin..begin + *n]);
                let start = 4095u64.max(*f) - *f;
                let end = 8193u64.min(*f + 4096) - *f;
                selected.extend_from_slice(
                    &bytes[usize::try_from(start).unwrap()..usize::try_from(end).unwrap()],
                );
            }
            _ => panic!("literal interleaved event mismatch"),
        }
    }
    assert!(items.is_complete());
    assert!(items.next().is_none());
    assert_eq!(selected, body[4095..8193]);
    assert_ne!(&c.wire[4231..4231 + selected.len()], selected);
}
