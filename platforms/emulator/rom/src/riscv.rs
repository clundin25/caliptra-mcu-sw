/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains main RISC-V entry point for MCU ROM

--*/

use crate::io::{EMULATOR_WRITER, FATAL_ERROR_HANDLER};
use core::fmt::Write;
// For flash ctrl driver testing
use romtime::StaticRef;
use tock_registers::interfaces::{Readable, Writeable};
use crate::flash_ctrl::{
    flash_erase, flash_read, flash_write, EmulatedFlashCtrl,
};
use registers_generated::main_flash_ctrl::{self, regs::MainFlashCtrl};
pub const MAIN_FLASH_CTRL_BASE: StaticRef<MainFlashCtrl> =
    unsafe { StaticRef::new(main_flash_ctrl::MAIN_FLASH_CTRL_ADDR as *const MainFlashCtrl) };
/// flash ctrl driver testing ended

#[cfg(target_arch = "riscv32")]
core::arch::global_asm!(include_str!("start.s"));

use mcu_config::McuMemoryMap;
use romtime::HexWord;

#[cfg(feature = "test-mcu-rom-flash-access")]
#[no_mangle]
pub fn test_flash_access_marker() {
    // This function is only compiled if the feature is enabled
    romtime::println!(
        "[mcu-rom][xs debug] test_flash_access_marker called from MCU ROM"
    );
    test_flash_access();
}

// re-export this so the common ROM can use it
#[no_mangle]
#[used]
pub static MCU_MEMORY_MAP: McuMemoryMap = mcu_config_emulator::EMULATOR_MEMORY_MAP;

pub extern "C" fn rom_entry() -> ! {
    unsafe {
        #[allow(static_mut_refs)]
        romtime::set_printer(&mut EMULATOR_WRITER);
    }
    unsafe {
        #[allow(static_mut_refs)]
        mcu_rom_common::set_fatal_error_handler(&mut FATAL_ERROR_HANDLER);
    }

    mcu_rom_common::rom_start();

    #[cfg(feature = "test-mcu-rom-flash-access")]
    test_flash_access_marker();

    romtime::println!(
        "[mcu-rom] Jumping to firmware at {}",
        HexWord((MCU_MEMORY_MAP.sram_offset as u32) + 0x80)
    );
    exit_rom();
}

fn exit_rom() -> ! {
    unsafe {
        core::arch::asm! {
                "// Clear the stack
            la a0, STACK_ORIGIN      // dest
            la a1, STACK_SIZE        // len
            add a1, a1, a0
        1:
            sw zero, 0(a0)
            addi a0, a0, 4
            bltu a0, a1, 1b

            // Clear all registers
            li x1,  0; li x2,  0; li x3,  0; li x4,  0;
            li x5,  0; li x6,  0; li x7,  0; li x8,  0;
            li x9,  0; li x10, 0; li x11, 0; li x12, 0;
            li x13, 0; li x14, 0; li x15, 0; li x16, 0;
            li x17, 0; li x18, 0; li x19, 0; li x20, 0;
            li x21, 0; li x22, 0; li x23, 0; li x24, 0;
            li x25, 0; li x26, 0; li x27, 0; li x28, 0;
            li x29, 0; li x30, 0; li x31, 0;

            // jump to runtime
            li a3, 0x40000080
            jr a3",
                options(noreturn),
        }
    }
}


#[cfg(feature = "test-mcu-rom-flash-access")]
pub fn test_flash_access() {

    // Initialize flash controller
    let flash_ctrl = EmulatedFlashCtrl::new(MAIN_FLASH_CTRL_BASE);
    flash_ctrl.init();

    romtime::println!("[mcu-rom][xs debug]Flash controller initialized");

    // Test flash access: erase, write, read, arbitrary length of data 1024 bytes.
    // Execute the test multiple times with different start addresses.
    const TEST_DATA_SIZE: usize = 1024;
    const NUM_ITER: usize = 4;
    const ADDR_STEP: usize = 0x1000;

    for iter in 0..NUM_ITER {
        let mut test_data = [0; TEST_DATA_SIZE];
        for i in 0..test_data.len() {
            test_data[i] = (i as u8).wrapping_add(iter as u8);
        }

        let start_addr = 0x50 + iter * ADDR_STEP;
        let mut read_buf = [0; TEST_DATA_SIZE];

        // Erase the flash
        let ret = flash_erase(&flash_ctrl, start_addr, test_data.len());
        assert!(ret.is_ok(), "Flash erase failed at addr {:#x}", start_addr);

        // Write the data to flash
        let ret = flash_write(&flash_ctrl, start_addr, &test_data);
        assert!(ret.is_ok(), "Flash write failed at addr {:#x}", start_addr);

        // Read the data back from flash
        let ret = flash_read(&flash_ctrl, start_addr, &mut read_buf);
        assert!(ret.is_ok(), "Flash read failed at addr {:#x}", start_addr);

        // Verify the data
        for i in 0..test_data.len() {
            if read_buf[i] != test_data[i] {
                assert_eq!(
                    read_buf[i], test_data[i],
                    "[mcu-rom][xs debug] Flash data mismatch at iter {}, index {}: expected {:02x}, got {:02x}",
                    iter,
                    i,
                    test_data[i],
                    read_buf[i]
                );

            }
        }
        romtime::println!(
            "[mcu-rom][xs debug] Flash data verified successfully at addr {:#x}",
            start_addr
        );
    }

    romtime::println!("[mcu-rom][xs debug]Flash controller test access done");
}
