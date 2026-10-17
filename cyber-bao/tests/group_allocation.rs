#![cfg(feature = "std")]
//! Thread-local host allocator observation; inputs and harness are outside the guard.
use cyber_bao::{Poseidon2Backend, group::GroupHasher};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    hint::black_box,
};
struct ObservedAllocator;
thread_local! {
    static ACTIVE: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}
fn record() {
    ACTIVE.with(|a| {
        if a.get() {
            ALLOCATIONS.with(|n| n.set(n.get() + 1));
        }
    });
}
// SAFETY: every allocation/deallocation is forwarded unchanged to System.
unsafe impl GlobalAlloc for ObservedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record();
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record();
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record();
        unsafe { System.realloc(ptr, layout, size) }
    }
}
#[global_allocator]
static ALLOCATOR: ObservedAllocator = ObservedAllocator;
fn measured(f: impl FnOnce()) -> usize {
    struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            ACTIVE.with(|a| a.set(false));
        }
    }
    ALLOCATIONS.with(|n| n.set(0));
    ACTIVE.with(|a| a.set(true));
    let guard = Guard;
    f();
    drop(guard);
    ALLOCATIONS.with(Cell::get)
}
#[test]
fn concrete_reducer_construction_steps_poll_and_drop_do_not_allocate() {
    assert!(
        measured(|| {
            black_box(vec![42u8; black_box(17)]);
        }) > 0
    );
    for data in [
        Vec::new(),
        b"hello".to_vec(),
        vec![7; 4097],
        vec![19; 65537],
    ] {
        let allocations = measured(|| {
            let backend = Poseidon2Backend;
            let mut machine = GroupHasher::new(&backend, &data, 0, true).unwrap();
            while !machine.is_complete() {
                black_box(machine.step());
            }
            assert!(machine.step().is_none());
            assert!(machine.step().is_none());
            // Scope exit drops the machine inside the measured region.
            black_box(machine);
        });
        assert_eq!(allocations, 0, "input length {}", data.len());
    }
}
