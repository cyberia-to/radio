#![no_std]
#![no_main]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let _ = core::hint::black_box(bao_proof_nostd_probe::chunk());
    loop { core::hint::spin_loop(); }
}
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! { loop { core::hint::spin_loop(); } }
