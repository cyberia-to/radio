//! Literal geometric expectations; no hash or authenticated proof is involved.
use core::{iter::FusedIterator, ops::Range};

use cyber_bao::{
    BaoChunk, BlockSize, TreeNode,
    traversal::{RangeTraversal, RangeTraversalError},
};

#[derive(Debug, PartialEq, Eq)]
enum Item {
    Parent(TreeNode, bool, bool, bool),
    Leaf(u64, usize, bool),
}

fn item(value: BaoChunk) -> Item {
    match value {
        BaoChunk::Parent {
            node,
            is_root,
            left,
            right,
        } => Item::Parent(node, is_root, left, right),
        BaoChunk::Leaf {
            start_chunk,
            size,
            is_root,
        } => Item::Leaf(start_chunk, size, is_root),
    }
}

// This parser reads authored preorder tokens. It contains no tree splitting,
// recursion, geometry traversal or production call. Last-leaf size is supplied.
fn literal(tokens: &str, log: u8, final_group: u64, final_size: usize) -> Vec<Item> {
    let group_chunks = 1u64 << log;
    let group_bytes = 4096usize << log;
    tokens
        .split_whitespace()
        .enumerate()
        .map(|(index, token)| {
            if let Some(parent) = token.strip_prefix('P') {
                let (node, visit) = parent.split_once(':').unwrap_or((parent, "B"));
                assert!(matches!(visit, "L" | "R" | "B"));
                Item::Parent(
                    TreeNode::new(node.parse().unwrap()),
                    index == 0,
                    visit != "R",
                    visit != "L",
                )
            } else {
                let group: u64 = token.strip_prefix('L').unwrap().parse().unwrap();
                Item::Leaf(
                    group * group_chunks,
                    if group == final_group {
                        final_size
                    } else {
                        group_bytes
                    },
                    index == 0,
                )
            }
        })
        .collect()
}

fn check(size: u64, log: u8, request: Range<u64>, expected: &[Item]) {
    let mut traversal = RangeTraversal::new(size, BlockSize(log), request).unwrap();
    fn fused<T: FusedIterator<Item = BaoChunk>>(_: &T) {}
    fused(&traversal);
    assert_eq!(traversal.is_complete(), expected.is_empty());
    for (index, value) in expected.iter().enumerate() {
        assert!(!traversal.is_complete());
        assert_eq!(&item(traversal.next().expect("one pending item")), value);
        assert_eq!(traversal.is_complete(), index + 1 == expected.len());
    }
    for _ in 0..3 {
        assert!(traversal.next().is_none());
        assert!(traversal.is_complete());
    }
}

const COMPLETE: &[(u64, &str)] = &[
    (1, "L0"),
    (2, "P1 L0 L1"),
    (3, "P3 P1 L0 L1 L2"),
    (5, "P7 P3 P1 L0 L1 P5 L2 L3 L4"),
    (7, "P7 P3 P1 L0 L1 P5 L2 L3 P11 P9 L4 L5 L6"),
    (
        16,
        "P15 P7 P3 P1 L0 L1 P5 L2 L3 P11 P9 L4 L5 P13 L6 L7 P23 P19 P17 L8 L9 P21 L10 L11 P27 P25 L12 L13 P29 L14 L15",
    ),
    (
        17,
        "P31 P15 P7 P3 P1 L0 L1 P5 L2 L3 P11 P9 L4 L5 P13 L6 L7 P23 P19 P17 L8 L9 P21 L10 L11 P27 P25 L12 L13 P29 L14 L15 L16",
    ),
];

#[test]
fn literal_complete_left_shapes_and_partial_last_groups() {
    for log in [0, 2] {
        let width = 4096u64 << log;
        for &(groups, tokens) in COMPLETE {
            for final_size in [1, width] {
                let size = (groups - 1) * width + final_size;
                let expected = literal(tokens, log, groups - 1, final_size as usize);
                assert_eq!(expected.len() as u64, 2 * groups - 1);
                check(size, log, 0..size, &expected);
            }
        }
    }
}

#[test]
fn literal_half_open_selection_flags_and_root_placement() {
    for log in [0, 2] {
        let g = 4096u64 << log;
        let cases = [
            (3, 3 * g - 1..3 * g, "P3:R L2"),
            (3, 0..1, "P3:L P1:L L0"),
            (3, g..2 * g, "P3:L P1:R L1"),
            (3, g - 1..g + 1, "P3:L P1:B L0 L1"),
            (3, 2 * g - 1..2 * g + 1, "P3:B P1:R L1 L2"),
            (7, 7 * g - 1..7 * g, "P7:R P11:R L6"),
            (7, 5 * g..6 * g, "P7:R P11:L P9:R L5"),
            (7, 3 * g..5 * g, "P7:B P3:R P5:R L3 P11:L P9:L L4"),
            (17, 17 * g - 1..17 * g, "P31:R L16"),
        ];
        for (groups, request, tokens) in cases {
            check(
                groups * g,
                log,
                request,
                &literal(tokens, log, groups - 1, g as usize),
            );
        }
        check(
            2 * g + 1,
            log,
            2 * g..2 * g + 1,
            &literal("P3:R L2", log, 2, 1),
        );
    }
}

#[test]
fn tiny_lengths_and_empty_requests_are_geometric() {
    for size in [1, 4095, 4096] {
        check(size, 0, 0..size, &[Item::Leaf(0, size as usize, true)]);
    }
    check(
        4097,
        0,
        0..4097,
        &[
            Item::Parent(TreeNode::new(1), true, true, true),
            Item::Leaf(0, 4096, false),
            Item::Leaf(1, 1, false),
        ],
    );
    for size in [0, 1, 4095, 4096, 4097, u64::MAX] {
        for at in [0, size / 2, size] {
            check(size, 0, at..at, &[]);
        }
    }
}

#[test]
#[allow(clippy::reversed_empty_ranges, reason = "invalid constructor inputs")]
fn exact_admission_errors_and_geometry_precedence() {
    use RangeTraversalError::{InvalidBlockSize, InvalidRange};
    for (size, request) in [
        (0, 0..1),
        (0, 1..1),
        (1, 1..0),
        (1, 0..2),
        (1, 2..2),
        (u64::MAX, u64::MAX..0),
    ] {
        assert_eq!(
            RangeTraversal::new(size, BlockSize(0), request).unwrap_err(),
            InvalidRange
        );
    }
    let max_log = match usize::BITS {
        32 => 19,
        64 => 51,
        bits => panic!("unsupported witness pointer width {bits}"),
    };
    for log in 0..=u8::MAX {
        let result = RangeTraversal::new(1, BlockSize(log), 0..1);
        if log <= max_log {
            let mut cursor = result.unwrap();
            assert_eq!(item(cursor.next().unwrap()), Item::Leaf(0, 1, true));
            assert!(cursor.is_complete());
            assert_eq!(
                RangeTraversal::new(1, BlockSize(log), 2..2).unwrap_err(),
                InvalidRange
            );
        } else {
            assert_eq!(result.unwrap_err(), InvalidBlockSize);
            assert_eq!(
                RangeTraversal::new(1, BlockSize(log), 2..2).unwrap_err(),
                InvalidBlockSize
            );
            assert_eq!(
                RangeTraversal::new(0, BlockSize(log), 0..0).unwrap_err(),
                InvalidBlockSize
            );
        }
    }
    fn core_error<E: core::error::Error>() {}
    core_error::<RangeTraversalError>();
    assert_eq!(InvalidBlockSize.to_string(), "invalid traversal block size");
    assert_eq!(InvalidRange.to_string(), "invalid traversal byte range");
}

// Independent complete-tree midpoint identities: left spine 2^k-1;
// right spine 2^53-2^k-1 for k=52..1, evaluated before implementation.
const MAX_LEFT: [u64; 52] = [
    4503599627370495,
    2251799813685247,
    1125899906842623,
    562949953421311,
    281474976710655,
    140737488355327,
    70368744177663,
    35184372088831,
    17592186044415,
    8796093022207,
    4398046511103,
    2199023255551,
    1099511627775,
    549755813887,
    274877906943,
    137438953471,
    68719476735,
    34359738367,
    17179869183,
    8589934591,
    4294967295,
    2147483647,
    1073741823,
    536870911,
    268435455,
    134217727,
    67108863,
    33554431,
    16777215,
    8388607,
    4194303,
    2097151,
    1048575,
    524287,
    262143,
    131071,
    65535,
    32767,
    16383,
    8191,
    4095,
    2047,
    1023,
    511,
    255,
    127,
    63,
    31,
    15,
    7,
    3,
    1,
];
const MAX_RIGHT: [u64; 52] = [
    4503599627370495,
    6755399441055743,
    7881299347898367,
    8444249301319679,
    8725724278030335,
    8866461766385663,
    8936830510563327,
    8972014882652159,
    8989607068696575,
    8998403161718783,
    9002801208229887,
    9005000231485439,
    9006099743113215,
    9006649498927103,
    9006924376834047,
    9007061815787519,
    9007130535264255,
    9007164895002623,
    9007182074871807,
    9007190664806399,
    9007194959773695,
    9007197107257343,
    9007198180999167,
    9007198717870079,
    9007198986305535,
    9007199120523263,
    9007199187632127,
    9007199221186559,
    9007199237963775,
    9007199246352383,
    9007199250546687,
    9007199252643839,
    9007199253692415,
    9007199254216703,
    9007199254478847,
    9007199254609919,
    9007199254675455,
    9007199254708223,
    9007199254724607,
    9007199254732799,
    9007199254736895,
    9007199254738943,
    9007199254739967,
    9007199254740479,
    9007199254740735,
    9007199254740863,
    9007199254740927,
    9007199254740959,
    9007199254740975,
    9007199254740983,
    9007199254740987,
    9007199254740989,
];

#[test]
fn maximum_file_final_path_uses_literal_remainder() {
    let mut expected: Vec<_> = MAX_RIGHT
        .iter()
        .enumerate()
        .map(|(i, &node)| Item::Parent(TreeNode::new(node), i == 0, false, true))
        .collect();
    expected.push(Item::Leaf(4503599627370495, 4095, false));
    check(u64::MAX, 0, u64::MAX - 1..u64::MAX, &expected);
    #[cfg(target_pointer_width = "64")]
    check(
        u64::MAX,
        51,
        u64::MAX - 1..u64::MAX,
        &[
            Item::Parent(TreeNode::new(1), true, false, true),
            Item::Leaf(2251799813685248, 9223372036854775807, false),
        ],
    );
}

#[test]
fn maximum_left_prefix_requires_fifty_three_pending_slots() {
    // Entire request leaves all 52 right siblings pending at the first leaf.
    // Only this finite prefix is polled; no enormous body or full walk exists.
    let mut cursor = RangeTraversal::new(u64::MAX, BlockSize(0), 0..u64::MAX).unwrap();
    for (i, node) in MAX_LEFT.into_iter().enumerate() {
        assert_eq!(
            item(cursor.next().unwrap()),
            Item::Parent(TreeNode::new(node), i == 0, true, true)
        );
        assert!(!cursor.is_complete());
    }
    assert_eq!(item(cursor.next().unwrap()), Item::Leaf(0, 4096, false));
    assert_eq!(item(cursor.next().unwrap()), Item::Leaf(1, 4096, false));
    assert!(!cursor.is_complete());
}

#[test]
fn caller_pauses_and_interleaving_preserve_progress() {
    let a_expected = literal("P7:R P11:R L6", 0, 6, 4096);
    let b_expected = literal(COMPLETE[3].1, 0, 4, 1);
    for pause in 0..=b_expected.len() {
        let mut a = RangeTraversal::new(7 * 4096, BlockSize(0), 7 * 4096 - 1..7 * 4096).unwrap();
        let mut b = RangeTraversal::new(4 * 4096 + 1, BlockSize(0), 0..4 * 4096 + 1).unwrap();
        let mut before = Vec::new();
        for _ in 0..pause {
            before.push(item(b.next().unwrap()));
        }
        for expected in &a_expected {
            assert_eq!(&item(a.next().unwrap()), expected);
        }
        assert!(a.is_complete());
        assert!(a.next().is_none());
        assert_eq!(before, b_expected[..pause]);
        for expected in &b_expected[pause..] {
            assert_eq!(&item(b.next().unwrap()), expected);
        }
        assert!(b.is_complete());
        assert!(b.next().is_none());
    }
}

#[cfg(feature = "std")]
#[test]
fn finite_eager_compatibility_is_supplemental() {
    use cyber_bao::{BaoTree, ChunkNum, ChunkRanges};
    for log in [0, 2] {
        let g = 4096u64 << log;
        for &(groups, _) in COMPLETE {
            let size = (groups - 1) * g + 1;
            for request in [0..size, size - 1..size] {
                let old_ranges = ChunkRanges::from(
                    ChunkNum(request.start / 4096)..ChunkNum((request.end - 1) / 4096 + 1),
                );
                let eager: Vec<_> = BaoTree::new(size, BlockSize(log))
                    .pre_order_chunks_filtered(&old_ranges)
                    .into_iter()
                    .map(item)
                    .collect();
                let bounded: Vec<_> = RangeTraversal::new(size, BlockSize(log), request)
                    .unwrap()
                    .map(item)
                    .collect();
                assert_eq!(bounded, eager);
            }
        }
    }
}
