//! Concrete host observation; fixture allocation and destruction are outside it.
#[path = "support/proof.rs"]
mod support;

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    hint::black_box,
};

use cyber_bao::{BlockSize, proof::ProofVerifier};

thread_local! {
    static ACTIVE: Cell<bool> = const { Cell::new(false) };
    static COUNT: Cell<usize> = const { Cell::new(0) };
}
struct Allocator;
fn record() {
    ACTIVE.with(|active| {
        if active.get() {
            COUNT.with(|n| n.set(n.get() + 1));
        }
    });
}
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record();
        // SAFETY: preserve the allocator's incoming layout.
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record();
        // SAFETY: preserve the allocator's incoming layout.
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record();
        // SAFETY: preserve the original pointer/layout and requested new size.
        unsafe { System.realloc(ptr, layout, size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: preserve the original allocation identity; frees are not allocs.
        unsafe { System.dealloc(ptr, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

fn observed<T>(f: impl FnOnce() -> T) -> T {
    struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            ACTIVE.with(|a| a.set(false));
        }
    }
    COUNT.with(|n| n.set(0));
    ACTIVE.with(|a| assert!(!a.replace(true)));
    let guard = Guard;
    let result = f();
    drop(guard);
    assert_eq!(COUNT.with(Cell::get), 0);
    result
}

#[test]
fn concrete_verifier_all_stages_output_failure_and_cancel_allocate_nothing() {
    COUNT.with(|n| n.set(0));
    ACTIVE.with(|a| a.set(true));
    let positive = black_box(vec![17u8; 17]);
    ACTIVE.with(|a| a.set(false));
    assert!(COUNT.with(Cell::get) > 0);
    drop(positive);
    let all = support::cases(); // construction and eventual drop outside observation
    for c in &all {
        let mut job = observed(|| {
            ProofVerifier::new(&c.wire, c.root, c.size, BlockSize(c.log), c.request.clone())
                .unwrap()
        });
        let mut view = None;
        while !job.is_finished() {
            if let Some(v) = observed(|| job.step().unwrap()) {
                view = Some(v);
            }
        }
        let view = view.unwrap();
        for _ in 0..10 {
            assert!(observed(|| job.step().unwrap()).is_none());
        }
        let mut items = observed(|| view.items());
        while !items.is_complete() {
            black_box(observed(|| items.next()));
        }
        for _ in 0..10 {
            assert!(observed(|| items.next()).is_none());
        }
        observed(|| {
            black_box(items);
            black_box(view);
            black_box(job);
        });
        for stop in 0..c.actions {
            let mut job = observed(|| {
                ProofVerifier::new(&c.wire, c.root, c.size, BlockSize(c.log), c.request.clone())
                    .unwrap()
            });
            for _ in 0..stop {
                assert!(observed(|| job.step().unwrap()).is_none());
            }
            observed(|| {
                black_box(job);
            });
        }
    }
    let mut corrupt = support::named("three-boundary");
    corrupt.wire.push(0);
    let mut job = observed(|| {
        ProofVerifier::new(
            &corrupt.wire,
            corrupt.root,
            corrupt.size,
            BlockSize(corrupt.log),
            corrupt.request.clone(),
        )
        .unwrap()
    });
    for _ in 1..corrupt.actions {
        assert!(observed(|| job.step().unwrap()).is_none());
    }
    let error = observed(|| job.step().unwrap_err());
    for _ in 0..10 {
        assert_eq!(observed(|| job.step().unwrap_err()), error);
    }
    observed(|| {
        black_box(job);
    });
    assert!(observed(|| ProofVerifier::new(&[], [0; 32], 0, BlockSize(255), 0..0)).is_err());
}
