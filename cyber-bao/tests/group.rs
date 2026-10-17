//! Finite independent tree literals; the backend deliberately cannot clone hashes.
use std::cell::RefCell;

use cyber_bao::{
    HashBackend, Poseidon2Backend,
    group::{GroupHashError, GroupHasher},
};

#[derive(Debug, Eq, PartialEq)]
struct Symbol(String);
impl Clone for Symbol {
    fn clone(&self) -> Self {
        panic!("hash Clone is forbidden")
    }
}
impl AsRef<[u8]> for Symbol {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}
struct Recorder {
    events: RefCell<Vec<(String, bool)>>,
    start: u64,
}
impl Recorder {
    fn new(start: u64) -> Self {
        Self {
            events: RefCell::new(Vec::new()),
            start,
        }
    }
}
impl HashBackend for Recorder {
    type Hash = Symbol;
    fn chunk_hash(&self, data: &[u8], counter: u64, root: bool) -> Symbol {
        let index = counter - self.start;
        assert!(data.iter().all(|&b| b == index as u8));
        let name = format!("L{index}");
        self.events
            .borrow_mut()
            .push((format!("{name}:{}:{counter}", data.len()), root));
        Symbol(name)
    }
    fn parent_hash(&self, l: &Symbol, r: &Symbol, root: bool) -> Symbol {
        let name = format!("({}{})", l.0, r.0);
        self.events.borrow_mut().push((name.clone(), root));
        Symbol(name)
    }
    fn hash_size(&self) -> usize {
        panic!("unused hash_size")
    }
    fn zero_hash(&self) -> Symbol {
        panic!("unused placeholder")
    }
    fn hash_from_bytes(&self, _: &[u8]) -> Symbol {
        panic!("unused deserialize")
    }
}
// Post-order kernels written as literal identities, independent of the frontier.
const E1: &[&str] = &["L0"];
const E2: &[&str] = &["L0", "L1", "(L0L1)"];
const E3: &[&str] = &["L0", "L1", "(L0L1)", "L2", "((L0L1)L2)"];
const E5: &[&str] = &[
    "L0",
    "L1",
    "(L0L1)",
    "L2",
    "L3",
    "(L2L3)",
    "((L0L1)(L2L3))",
    "L4",
    "(((L0L1)(L2L3))L4)",
];
const E7: &[&str] = &[
    "L0",
    "L1",
    "(L0L1)",
    "L2",
    "L3",
    "(L2L3)",
    "((L0L1)(L2L3))",
    "L4",
    "L5",
    "(L4L5)",
    "L6",
    "((L4L5)L6)",
    "(((L0L1)(L2L3))((L4L5)L6))",
];
const E16: &[&str] = &[
    "L0",
    "L1",
    "(L0L1)",
    "L2",
    "L3",
    "(L2L3)",
    "((L0L1)(L2L3))",
    "L4",
    "L5",
    "(L4L5)",
    "L6",
    "L7",
    "(L6L7)",
    "((L4L5)(L6L7))",
    "(((L0L1)(L2L3))((L4L5)(L6L7)))",
    "L8",
    "L9",
    "(L8L9)",
    "L10",
    "L11",
    "(L10L11)",
    "((L8L9)(L10L11))",
    "L12",
    "L13",
    "(L12L13)",
    "L14",
    "L15",
    "(L14L15)",
    "((L12L13)(L14L15))",
    "(((L8L9)(L10L11))((L12L13)(L14L15)))",
    "((((L0L1)(L2L3))((L4L5)(L6L7)))(((L8L9)(L10L11))((L12L13)(L14L15))))",
];
const T17: &str = "(((((L0L1)(L2L3))((L4L5)(L6L7)))(((L8L9)(L10L11))((L12L13)(L14L15))))L16)";
fn events(n: usize) -> Vec<&'static str> {
    match n {
        1 => E1.to_vec(),
        2 => E2.to_vec(),
        3 => E3.to_vec(),
        5 => E5.to_vec(),
        7 => E7.to_vec(),
        16 => E16.to_vec(),
        17 => E16.iter().copied().chain(["L16", T17]).collect(),
        _ => panic!("no literal"),
    }
}
fn patterned(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i / 4096) as u8).collect()
}
fn check_events(backend: &Recorder, expected: &[&str], len: usize, root: bool) {
    let observed = backend.events.borrow();
    assert_eq!(observed.len(), expected.len());
    for (i, (&name, (actual, flag))) in expected.iter().zip(observed.iter()).enumerate() {
        let identity = if let Some(leaf) = name.strip_prefix('L') {
            let leaf: usize = leaf.parse().unwrap();
            format!(
                "{name}:{}:{}",
                len.saturating_sub(leaf * 4096).min(4096),
                backend.start + leaf as u64
            )
        } else {
            name.to_owned()
        };
        assert_eq!(*actual, identity);
        assert_eq!(*flag, root && i + 1 == expected.len());
    }
}
#[test]
fn sixty_literal_cases_have_one_kernel_per_step_and_move_only_hashes() {
    let mut cases = vec![(0, 1, 1)];
    for (n, count) in [(1, 1), (2, 3), (3, 5), (5, 9), (7, 13), (16, 31), (17, 33)] {
        cases.extend([(n * 4096, n, count), ((n - 1) * 4096 + 1, n, count)]);
    }
    let mut checked = 0;
    for (len, n, count) in cases {
        for start in [0, 37] {
            for root in [false, true] {
                let data = patterned(len);
                let backend = Recorder::new(start);
                let mut machine = GroupHasher::new(&backend, &data, start, root).unwrap();
                assert!(backend.events.borrow().is_empty());
                assert!(!machine.is_complete());
                let expected = events(n);
                assert_eq!(expected.len(), count);
                for step in 1..=count {
                    let value = machine.step();
                    assert_eq!(backend.events.borrow().len(), step);
                    assert_eq!(machine.is_complete(), step == count);
                    if step == count {
                        assert_eq!(value.unwrap().0, *expected.last().unwrap());
                    } else {
                        assert!(value.is_none());
                    }
                }
                assert!(machine.step().is_none());
                assert!(machine.step().is_none());
                assert!(machine.is_complete());
                check_events(&backend, &expected, len, root);
                // This also exercises Debug without a Debug bound on Recorder.
                assert!(!format!("{machine:?}").is_empty());
                checked += 1;
            }
        }
    }
    assert_eq!(checked, 60);
}
#[test]
fn caller_total_and_one_action_calls_pause_at_every_boundary() {
    for (n, total) in [(1, 1), (3, 5), (7, 13)] {
        let data = patterned(n * 4096);
        for limit in [total - 1, total] {
            for pause in 0..=limit {
                let backend = Recorder::new(37);
                let mut machine = GroupHasher::new(&backend, &data, 37, true).unwrap();
                let mut used = 0;
                let mut ready = None;
                for stop in [pause, limit] {
                    while !machine.is_complete() && used < stop {
                        // A new public call admits exactly one kernel from a persistent total.
                        assert!(used < limit);
                        used += 1;
                        ready = machine.step();
                        assert_eq!(backend.events.borrow().len(), used);
                    }
                    let before = backend.events.borrow().len();
                    // No admission => no step, including an exhausted outer call.
                    assert_eq!(before, used);
                }
                assert_eq!(used, limit);
                if limit == total {
                    assert!(machine.is_complete());
                    assert_eq!(ready.as_ref().unwrap().0, *events(n).last().unwrap());
                    assert!(machine.step().is_none());
                    assert_eq!(ready.unwrap().0, *events(n).last().unwrap());
                } else {
                    assert!(!machine.is_complete());
                    assert!(ready.is_none());
                }
                assert_eq!(backend.events.borrow().len(), limit);
            }
        }
    }
}
#[test]
fn absolute_counter_bounds_are_checked_before_any_backend_call() {
    for len in [0, 1, 4096] {
        let backend = Recorder::new(u64::MAX);
        let data = patterned(len);
        let mut machine = GroupHasher::new(&backend, &data, u64::MAX, true).unwrap();
        assert_eq!(machine.step().unwrap().0, "L0");
        check_events(&backend, E1, len, true);
    }
    let data = patterned(4097);
    let backend = Recorder::new(u64::MAX - 1);
    let mut machine = GroupHasher::new(&backend, &data, u64::MAX - 1, false).unwrap();
    assert!(machine.step().is_none());
    assert!(machine.step().is_none());
    assert_eq!(machine.step().unwrap().0, "(L0L1)");
    check_events(&backend, E2, 4097, false);
    let backend = Recorder::new(u64::MAX);
    assert_eq!(
        GroupHasher::new(&backend, &data, u64::MAX, true).unwrap_err(),
        GroupHashError::CounterOverflow
    );
    assert!(backend.events.borrow().is_empty());
}
fn concrete(data: &[u8], start: u64, root: bool) -> hemera::Hash {
    let backend = Poseidon2Backend;
    let mut machine = GroupHasher::new(&backend, data, start, root).unwrap();
    loop {
        if let Some(hash) = machine.step() {
            return hash;
        }
    }
}
fn hex(hash: &hemera::Hash) -> String {
    hash.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}
fn deterministic(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| ((i * 31 + i / 4096) % 256) as u8)
        .collect()
}
#[test]
fn concrete_roots_match_frozen_literals_and_pinned_complete_left_oracle() {
    assert_eq!(
        hex(&concrete(b"", 0, true)),
        "ea57b2e6b1ec7d2de11b15cb6d7060dd61d247fe0fbf5f7d3fb97a7be9328552"
    );
    assert_eq!(
        hex(&concrete(b"hello", 0, true)),
        "626fa46e4e7bd5c87d630eef8333931a0b9198587400a0191eae7821692880d7"
    );
    let data = deterministic(8192);
    assert_eq!(
        hex(&concrete(&data, 0, true)),
        "2abf65dd26465a7352707d79d18ff3aab9ee5d97614a774619c79ed527e20190"
    );
    assert_eq!(
        hex(&concrete(&data, 0, false)),
        "11890a7e7cf1e4de463a04bf53bfdf269d627983a221daaf9029a3ff43297389"
    );
    // Shared pinned kernels: shape/root regression evidence, not independent cryptography.
    for len in [
        0, 1, 4095, 4096, 4097, 8192, 12288, 16385, 28672, 65536, 65537,
    ] {
        let data = deterministic(len);
        assert_eq!(
            concrete(&data, 0, true),
            hemera::tree::fixed_chunk_root(&data)
        );
    }
}
#[test]
fn nonzero_counter_internal_cv_uses_literal_partitions() {
    use hemera::tree::{chunk_cv, parent_cv};
    let data = deterministic(28672);
    let l = |n: usize| chunk_cv(&data[n * 4096..(n + 1) * 4096], 37 + n as u64, false);
    let p = |a, b| parent_cv(&a, &b, false);
    assert_eq!(concrete(&data[..4096], 37, false), l(0));
    assert_eq!(concrete(&data[..12288], 37, false), p(p(l(0), l(1)), l(2)));
    assert_eq!(
        concrete(&data, 37, false),
        p(p(p(l(0), l(1)), p(l(2), l(3))), p(p(l(4), l(5)), l(6)))
    );
}
