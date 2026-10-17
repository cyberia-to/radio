//! Literal consumer of the committed strict reader: no hash/encoder/traversal oracle.
use std::{fs, iter::FusedIterator, ops::Range, path::Path};

use cyber_bao::{
    BlockSize,
    proof::{ProofItem, ProofVerifier, VerifiedProof},
};

#[derive(Clone, Copy)]
enum Event {
    Parent,
    Leaf {
        proof: usize,
        file: u64,
        bytes: usize,
    },
}
struct Case {
    name: &'static str,
    directory: &'static str,
    proof_file: &'static str,
    root: &'static str,
    size: u64,
    log: u8,
    request: Range<u64>,
    actions: usize,
    wire_bytes: usize,
    events: &'static [Event],
}
fn root(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64);
    std::array::from_fn(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
}
fn finish<'a>(case: &Case, proof: &'a [u8]) -> (VerifiedProof<'a>, usize) {
    let mut job = ProofVerifier::new(
        proof,
        root(case.root),
        case.size,
        BlockSize(case.log),
        case.request.clone(),
    )
    .unwrap();
    let mut calls = 0;
    for _ in 1..case.actions {
        assert!(!job.is_finished(), "{} early terminal", case.name);
        calls += 1;
        assert!(job.step().unwrap().is_none(), "{} early view", case.name);
    }
    assert!(!job.is_finished());
    calls += 1;
    let view = job
        .step()
        .unwrap()
        .expect("literal EOF action returns view");
    assert!(job.is_finished());
    for _ in 0..10 {
        assert!(job.step().unwrap().is_none());
    }
    (view, calls) // the view survives the verifier and still borrows the proof
}
fn fused<T: FusedIterator>(_: &T) {}
fn run(base: &Path, case: &Case) {
    let dir = base.join(case.directory);
    let proof = fs::read(dir.join(case.proof_file)).unwrap();
    let body = fs::read(dir.join("body.bin")).unwrap();
    let selected = fs::read(dir.join("selected.bin")).unwrap();
    assert_eq!(proof.len(), case.wire_bytes);
    assert_eq!(u64::try_from(body.len()).unwrap(), case.size);
    assert_eq!(
        selected,
        body[usize::try_from(case.request.start).unwrap()
            ..usize::try_from(case.request.end).unwrap()]
    );
    let (view, calls) = finish(case, &proof);
    assert_eq!(calls, case.actions);
    assert_eq!(view.root(), root(case.root));
    assert_eq!(view.size(), case.size);
    assert_eq!(view.block_size(), BlockSize(case.log));
    assert_eq!(view.request(), case.request);
    let mut items = view.items();
    fused(&items);
    assert_eq!(items.is_complete(), case.events.is_empty());
    let mut copied = Vec::new();
    let mut emitted = 0;
    let mut leaves = 0;
    for (index, expected) in case.events.iter().enumerate() {
        assert!(!items.is_complete());
        emitted += 1;
        match (items.next().unwrap(), expected) {
            (ProofItem::Parent, Event::Parent) => {}
            (
                ProofItem::Leaf {
                    file_offset,
                    proof_offset,
                    bytes,
                },
                Event::Leaf {
                    proof: p,
                    file: f,
                    bytes: n,
                },
            ) => {
                leaves += 1;
                assert_eq!((proof_offset, file_offset, bytes.len()), (*p, *f, *n));
                assert_eq!(bytes.as_ptr(), proof[*p..].as_ptr());
                assert_eq!(bytes, &proof[*p..*p + *n]);
                let file = usize::try_from(*f).unwrap();
                assert_eq!(bytes, &body[file..file + *n]);
                let first = case.request.start.max(*f) - *f;
                let end = case.request.end.min(*f + u64::try_from(*n).unwrap()) - *f;
                copied.extend_from_slice(
                    &bytes[usize::try_from(first).unwrap()..usize::try_from(end).unwrap()],
                );
                println!(
                    "{{\"case\":\"{}\",\"leaf\":{},\"proof_offset\":{},\"file_offset\":{},\"bytes\":{}}}",
                    case.name,
                    leaves,
                    proof_offset,
                    file_offset,
                    bytes.len()
                );
            }
            _ => panic!(
                "{} event {} disagrees with literal carrier",
                case.name, index
            ),
        }
        assert_eq!(items.is_complete(), index + 1 == case.events.len());
    }
    assert_eq!(emitted, case.events.len());
    assert!(items.is_complete());
    for _ in 0..10 {
        assert!(items.next().is_none());
    }
    assert_eq!(copied, selected);
    println!(
        "{{\"case\":\"{}\",\"root\":\"{}\",\"verification_actions\":{},\"output_items\":{},\"leaves\":{},\"selected_bytes\":{},\"status\":\"pass\"}}",
        case.name,
        case.root,
        calls,
        emitted,
        leaves,
        copied.len()
    );
}
fn main() {
    use Event::{Leaf as L, Parent as P};
    let base = std::env::args_os()
        .nth(1)
        .expect("frozen literal directory");
    let four = "e621f66b42fb61b260200dfa649d3f16d35cde5af2e8c04cc2551c109f00c6f6";
    let short = "06001dbd4d71e5149839bed85cbe3fc979fcfc45ef711a6d9ad2fdc1499da3e3";
    let cases = [
        Case {
            name: "interleaved",
            directory: "interleaved",
            proof_file: "interleaved.bao",
            root: four,
            size: 16384,
            log: 0,
            request: 4095..8193,
            actions: 11,
            wire_bytes: 12488,
            events: &[
                P,
                P,
                L {
                    proof: 136,
                    file: 0,
                    bytes: 4096,
                },
                L {
                    proof: 4232,
                    file: 4096,
                    bytes: 4096,
                },
                P,
                L {
                    proof: 8392,
                    file: 8192,
                    bytes: 4096,
                },
            ],
        },
        Case {
            name: "left",
            directory: "left",
            proof_file: "proof.bao",
            root: four,
            size: 16384,
            log: 0,
            request: 1..3,
            actions: 6,
            wire_bytes: 4232,
            events: &[
                P,
                P,
                L {
                    proof: 136,
                    file: 0,
                    bytes: 4096,
                },
            ],
        },
        Case {
            name: "right",
            directory: "right",
            proof_file: "proof.bao",
            root: four,
            size: 16384,
            log: 0,
            request: 12289..12292,
            actions: 6,
            wire_bytes: 4232,
            events: &[
                P,
                P,
                L {
                    proof: 136,
                    file: 12288,
                    bytes: 4096,
                },
            ],
        },
        Case {
            name: "grouped",
            directory: "grouped",
            proof_file: "proof.bao",
            root: four,
            size: 16384,
            log: 1,
            request: 8191..8193,
            actions: 11,
            wire_bytes: 16456,
            events: &[
                P,
                L {
                    proof: 72,
                    file: 0,
                    bytes: 8192,
                },
                L {
                    proof: 8264,
                    file: 8192,
                    bytes: 8192,
                },
            ],
        },
        Case {
            name: "short",
            directory: "short",
            proof_file: "proof.bao",
            root: short,
            size: 4099,
            log: 0,
            request: 4095..4099,
            actions: 7,
            wire_bytes: 4171,
            events: &[
                P,
                L {
                    proof: 72,
                    file: 0,
                    bytes: 4096,
                },
                L {
                    proof: 4168,
                    file: 4096,
                    bytes: 3,
                },
            ],
        },
        Case {
            name: "short-grouped",
            directory: "short-grouped",
            proof_file: "proof.bao",
            root: short,
            size: 4099,
            log: 1,
            request: 4095..4099,
            actions: 6,
            wire_bytes: 4107,
            events: &[L {
                proof: 8,
                file: 0,
                bytes: 4099,
            }],
        },
        Case {
            name: "empty",
            directory: "empty",
            proof_file: "proof.bao",
            root: "ea57b2e6b1ec7d2de11b15cb6d7060dd61d247fe0fbf5f7d3fb97a7be9328552",
            size: 0,
            log: 0,
            request: 0..0,
            actions: 4,
            wire_bytes: 8,
            events: &[],
        },
        Case {
            name: "pcm",
            directory: "pcm",
            proof_file: "proof.bao",
            root: "da570b332b3f2eac27cdaa83f58bd498ab7fc7736732ab9c1b8d4838c9e307a3",
            size: 14,
            log: 0,
            request: 5..13,
            actions: 4,
            wire_bytes: 22,
            events: &[L {
                proof: 8,
                file: 0,
                bytes: 14,
            }],
        },
    ];
    for case in &cases {
        run(Path::new(&base), case);
    }
    println!(
        "Eight committed-reader cases PASS; no encoder, traversal or root recomputation oracle; no Kadek adapter executed"
    );
}
