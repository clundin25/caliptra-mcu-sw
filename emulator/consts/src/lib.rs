/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    File contains constant types related to the MCU.

--*/

use caliptra_emu_cpu::{CpuArgs, CpuOrgArgs};

pub const DEFAULT_CPU_ARGS: CpuArgs = CpuArgs {
    org: CpuOrgArgs {
        rom: ROM_ORG,
        rom_size: ROM_SIZE,
        iccm: RAM_ORG,
        iccm_size: RAM_SIZE,
        dccm: 0x5000_0000,
        dccm_size: 256 * 1024,
        reset_vector: ROM_ORG,
    },
};

pub const RAM_ORG: u32 = 0x4000_0000;
pub const RAM_SIZE: u32 = 384 * 1024;
pub const ROM_ORG: u32 = 0x8000_0000;
pub const ROM_SIZE: u32 = 48 * 1024;
pub const EXTERNAL_TEST_SRAM_SIZE: u32 = 4 * 1024;
pub const ROM_DEDICATED_RAM_ORG: u32 = 0x5000_0000;
pub const ROM_DEDICATED_RAM_SIZE: u32 = 256 * 1024;

pub const DIRECT_READ_FLASH_ORG: u32 = 0x3800_0000;
pub const DIRECT_READ_FLASH_SIZE: u32 = 64 * 1024 * 1024;
