/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    Common libraries for MCU ROM.

--*/

#![no_std]

mod fuses;
pub use fuses::*;
mod rom;
pub use rom::*;
mod i3c;
mod recovery;
pub trait FatalErrorHandler {
    fn fatal_error(&mut self, code: u32) -> !;
}

pub trait RecoveryIntfPeripheral {
    fn read_indirect_fifo_status_2(&self) -> u32;
    fn write_i3c_ec_soc_mgmt_if_rec_intf_cfg(&self, value: u32);
    fn read_prot_cap2(&self) -> u32;
    fn read_device_status0(&self) -> u32;
    fn read_recovery_status(&self) -> u32;
    fn set_indirect_fifo_ctrl_1(&self, value: u32);
    fn write_indirect_fifo_data(&self, value: u32);
    fn read_recovery_if_recovery_ctrl(&self) -> u32;
    fn set_recovery_if_recovery_ctrl(&self, value: u32);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlashAccessError {
    InvalidPartition,
    InvalidStatus,
    StorageError,
    ReadFailed,
    WriteFailed,
    Unknown,
}

pub trait FlashPartitionIntf {
    fn read(&self, partition_offset: usize, buf: &mut [u8]) -> Result<(), FlashAccessError>;
    fn write(&self, partition_offset: usize, buf: &[u8]) -> Result<(), FlashAccessError>;
    fn erase(&self, partition_offset: usize, len: usize) -> Result<(), FlashAccessError>;
}

static mut FATAL_ERROR_HANDLER: Option<&'static mut dyn FatalErrorHandler> = None;

/// Set the fatal error handler.
///
/// SAFETY: it is important that the passed fatal handler is never used otherwise
/// and no other references exist to it. It is recommended to create a single instance
/// of the struct and pass it in immediatly, and never use it otherwise.
pub fn set_fatal_error_handler(handler: &'static mut dyn FatalErrorHandler) {
    unsafe {
        FATAL_ERROR_HANDLER = Some(handler);
    }
}

#[no_mangle]
#[inline(never)]
#[cfg(target_arch = "riscv32")]
fn panic_is_possible() {
    core::hint::black_box(());
    // The existence of this symbol is used to inform test_panic_missing
    // that panics are possible. Do not remove or rename this symbol.
}

#[panic_handler]
#[inline(never)]
#[cfg(target_arch = "riscv32")]
fn rom_panic(_: &core::panic::PanicInfo) -> ! {
    panic_is_possible();
    fatal_error(0);
}

#[inline(never)]
#[allow(dead_code)]
#[allow(clippy::empty_loop)]
pub fn fatal_error(code: u32) -> ! {
    #[allow(static_mut_refs)]
    if let Some(handler) = unsafe { FATAL_ERROR_HANDLER.as_mut() } {
        handler.fatal_error(code);
    } else {
        // If no handler is set, just loop forever
        loop {}
    }
}
