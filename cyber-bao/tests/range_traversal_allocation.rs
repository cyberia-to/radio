#![cfg(feature = "std")]
//! Finite constructor/step/drop allocation observation, with a positive control.
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    hint::black_box,
};

use cyber_bao::{BlockSize, traversal::RangeTraversal};

thread_local! {
    static ACTIVE: Cell<bool> = const { Cell::new(false) };
    static COUNT: Cell<usize> = const { Cell::new(0) };
}
struct Allocator;
fn record() {
    ACTIVE.with(|active| {
        if active.get() {
            COUNT.with(|count| count.set(count.get() + 1));
        }
    });
}
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record();
        // SAFETY: forwarded allocator contract and unchanged layout.
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record();
        // SAFETY: forwarded allocator contract and unchanged layout.
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record();
        // SAFETY: forwarded allocator contract and unchanged arguments.
        unsafe { System.realloc(ptr, layout, size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarded allocator contract. Frees are not allocation events.
        unsafe { System.dealloc(ptr, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

fn measured(f: impl FnOnce()) -> usize {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            ACTIVE.with(|active| active.set(false));
        }
    }
    COUNT.with(|count| count.set(0));
    ACTIVE.with(|active| assert!(!active.replace(true)));
    let guard = Reset;
    f();
    drop(guard);
    COUNT.with(Cell::get)
}

#[test]
fn construction_steps_terminal_polls_and_drop_allocate_nothing() {
    assert!(
        measured(|| {
            black_box(vec![17u8; 17]);
        }) > 0
    );
    for (size, log, request, steps, complete) in [
        (0, 0, 0..0, 0, true),
        (4097, 0, 0..4097, 3, true),
        (114688, 2, 49152..81920, 7, true),
        (u64::MAX, 0, u64::MAX - 1..u64::MAX, 53, true),
        (u64::MAX, 0, 0..u64::MAX, 54, false),
    ] {
        assert_eq!(
            measured(|| {
                let mut cursor = RangeTraversal::new(size, BlockSize(log), request).unwrap();
                for _ in 0..steps {
                    assert!(black_box(cursor.next()).is_some());
                }
                assert_eq!(cursor.is_complete(), complete);
                if complete {
                    for _ in 0..3 {
                        assert!(black_box(cursor.next()).is_none());
                    }
                }
                black_box(cursor);
            }),
            0
        );
    }
    assert_eq!(
        measured(|| {
            assert!(RangeTraversal::new(1, BlockSize(255), 0..1).is_err());
            assert!(RangeTraversal::new(1, BlockSize(0), 2..2).is_err());
        }),
        0
    );
}
