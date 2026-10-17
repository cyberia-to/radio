
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
        output: vec![None, None, Some((136, 0, 4096)), Some((4232, 4096, 4096)),
                     None, Some((8392, 8192, 4096))],
    };
    for stop in 0..11 {
        let mut job = ProofVerifier::new(&c.wire, c.root, c.size, BlockSize(0), 4095..8193).unwrap();
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
            (ProofItem::Leaf { proof_offset, file_offset, bytes }, Some((p, f, n))) => {
                assert_eq!((proof_offset, file_offset, bytes.len()), (*p, *f, *n));
                assert_eq!(bytes.as_ptr(), c.wire[*p..].as_ptr());
                let begin = usize::try_from(*f).unwrap();
                assert_eq!(bytes, &body[begin..begin + *n]);
                let start = 4095u64.max(*f) - *f;
                let end = 8193u64.min(*f + 4096) - *f;
                selected.extend_from_slice(&bytes[usize::try_from(start).unwrap()..usize::try_from(end).unwrap()]);
            }
            _ => panic!("literal interleaved event mismatch"),
        }
    }
    assert!(items.is_complete());
    assert!(items.next().is_none());
    assert_eq!(selected, body[4095..8193]);
    assert_ne!(&c.wire[4231..4231 + selected.len()], selected);
}
