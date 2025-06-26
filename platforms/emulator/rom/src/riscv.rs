/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains main RISC-V entry point for MCU ROM

--*/

use crate::io::{EMULATOR_WRITER, FATAL_ERROR_HANDLER};
use core::fmt::Write;

#[cfg(target_arch = "riscv32")]
core::arch::global_asm!(include_str!("start.s"));

#[allow(unused_imports)]
use crate::flash::flash_api::FlashPartition;
#[allow(unused_imports)]
use crate::flash::flash_ctrl::{
    EmulatedFlashCtrl, PRIMARY_FLASH_CTRL_BASE, SECONDARY_FLASH_CTRL_BASE,
};
use mcu_config::boot::{BootConfig, BootConfigError, PartitionId, PartitionStatus, RollbackEnable};
use mcu_config::{McuMemoryMap, McuStraps};
use mcu_config_emulator::flash::{
    PartitionTable, StandAloneChecksumCalculator, IMAGE_A_PARTITION, IMAGE_B_PARTITION,
    PARTITION_TABLE,
};
#[allow(unused_imports)]
use mcu_rom_common::{fatal_error, FlashPartitionIntf};
use registers_generated::primary_flash_ctrl::{
    self,
    bits::{CtrlRegwen, FlControl, FlInterruptEnable, FlInterruptState, OpStatus},
    regs::PrimaryFlashCtrl,
};
use romtime::HexWord;
use zerocopy::{FromBytes, IntoBytes};

// re-export these so the common ROM can use it
#[no_mangle]
#[used]
pub static MCU_MEMORY_MAP: McuMemoryMap = mcu_config_emulator::EMULATOR_MEMORY_MAP;

#[no_mangle]
#[used]
pub static MCU_STRAPS: McuStraps = mcu_config_emulator::EMULATOR_MCU_STRAPS;

pub extern "C" fn rom_entry() -> ! {
    unsafe {
        #[allow(static_mut_refs)]
        romtime::set_printer(&mut EMULATOR_WRITER);
    }
    unsafe {
        #[allow(static_mut_refs)]
        mcu_rom_common::set_fatal_error_handler(&mut FATAL_ERROR_HANDLER);
    }

    #[cfg(feature = "test-flash-based-boot")]
    {
        // Initialize the flash controller for testing purposes
        let mut partition_table_flash =
            EmulatedFlashCtrl::initialize_flash_ctrl(PRIMARY_FLASH_CTRL_BASE);
        let mut partition_table_driver = FlashPartition::new(
            &partition_table_flash,
            "Partition Table",
            PARTITION_TABLE.offset,
            PARTITION_TABLE.size,
        )
        .map_err(|_| {
            fatal_error(1);
        })
        .ok()
        .unwrap();

        let mut boot_cfg = FlashBootCfg::new(&mut partition_table_driver);
        let active_partition = boot_cfg
            .get_active_partition()
            .map_err(|_| {
                fatal_error(1);
            })
            .ok()
            .unwrap();

        let partition_a_flash = EmulatedFlashCtrl::initialize_flash_ctrl(PRIMARY_FLASH_CTRL_BASE);
        let partition_b_flash = EmulatedFlashCtrl::initialize_flash_ctrl(SECONDARY_FLASH_CTRL_BASE);

        let mut partition_a_driver = FlashPartition::new(
            &partition_a_flash,
            "Image A",
            IMAGE_A_PARTITION.offset,
            IMAGE_A_PARTITION.size,
        )
        .map_err(|_| {
            fatal_error(1);
        })
        .ok()
        .unwrap();
        let mut partition_b_driver = FlashPartition::new(
            &partition_b_flash,
            "Image B",
            IMAGE_B_PARTITION.offset,
            IMAGE_B_PARTITION.size,
        )
        .map_err(|_| {
            fatal_error(1);
        })
        .ok()
        .unwrap();

        let mut flash_image_partition_driver = match active_partition {
            PartitionId::A => {
                romtime::println!("[mcu-rom] Booting from Partition A");
                RomEmulatedFlash::new(&mut partition_a_driver)
            }
            PartitionId::B => {
                romtime::println!("[mcu-rom] Booting from Partition B");
                RomEmulatedFlash::new(&mut partition_b_driver)
            }
            _ => fatal_error(1),
        };

        mcu_rom_common::rom_start(Some(&mut flash_image_partition_driver));
    }
    #[cfg(not(feature = "test-flash-based-boot"))]
    {
        mcu_rom_common::rom_start(None);
    }

    #[cfg(feature = "test-mcu-rom-flash-access")]
    {
        let primary_flash_ctrl = EmulatedFlashCtrl::initialize_flash_ctrl(PRIMARY_FLASH_CTRL_BASE);
        let test_par =
            FlashPartition::new(&primary_flash_ctrl, "TestPartition", 0x200_0000, 0x100_0000)
                .unwrap();
        crate::flash::flash_test::test_rom_flash_access(&test_par);
    }

    romtime::println!(
        "[mcu-rom] Jumping to firmware at {}",
        HexWord(MCU_MEMORY_MAP.sram_offset as u32)
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
            li a3, 0x40000000
            jr a3",
                options(noreturn),
        }
    }
}

pub struct RomEmulatedFlash<'a> {
    flash_driver: &'a mut FlashPartition<'a>,
}

impl<'a> RomEmulatedFlash<'a> {
    pub fn new(flash_partition_driver: &'a mut FlashPartition<'a>) -> Self {
        Self {
            flash_driver: flash_partition_driver,
        }
    }
}

impl<'a> FlashPartitionIntf for RomEmulatedFlash<'a> {
    fn read(
        &self,
        partition_offset: usize,
        buf: &mut [u8],
    ) -> Result<(), mcu_rom_common::FlashAccessError> {
        self.flash_driver
            .read(partition_offset, buf)
            .map_err(|_| mcu_rom_common::FlashAccessError::ReadFailed)
    }

    fn write(
        &self,
        partition_offset: usize,
        buf: &[u8],
    ) -> Result<(), mcu_rom_common::FlashAccessError> {
        self.flash_driver
            .write(partition_offset, buf)
            .map_err(|_| mcu_rom_common::FlashAccessError::WriteFailed)
    }

    fn erase(
        &self,
        partition_offset: usize,
        len: usize,
    ) -> Result<(), mcu_rom_common::FlashAccessError> {
        self.flash_driver
            .erase(partition_offset, len)
            .map_err(|_| mcu_rom_common::FlashAccessError::StorageError)
    }
}

pub struct FlashBootCfg<'a> {
    flash_driver: &'a mut FlashPartition<'a>,
}

impl<'a> FlashBootCfg<'a> {
    pub fn new(flash_driver: &'a mut FlashPartition<'a>) -> Self {
        Self { flash_driver }
    }

    pub fn read_partition_table(&self) -> Result<PartitionTable, ()> {
        let mut partition_table_data: [u8; core::mem::size_of::<PartitionTable>()] =
            [0; core::mem::size_of::<PartitionTable>()];
        self.flash_driver
            .read(0, &mut partition_table_data)
            .expect("Failed to read partition table data");

        let (partition_table, _) =
            PartitionTable::read_from_prefix(&partition_table_data).map_err(|_| ())?;
        // Verify checksum
        let checksum_calculator = StandAloneChecksumCalculator::new();
        if !partition_table.verify_checksum(&checksum_calculator) {
            return Err(());
        }
        Ok(partition_table)
    }
}

impl<'a> BootConfig for FlashBootCfg<'a> {
    fn get_active_partition(&self) -> Result<PartitionId, BootConfigError> {
        let partition_table = self
            .read_partition_table()
            .map_err(|_| BootConfigError::ReadFailed)?;

        let (active_partition, _) = partition_table.get_active_partition();
        Ok(active_partition)
    }

    fn set_active_partition(&mut self, partition_id: PartitionId) -> Result<(), BootConfigError> {
        let mut partition_table = self
            .read_partition_table()
            .map_err(|_| BootConfigError::ReadFailed)?;
        partition_table.set_active_partition(partition_id);
        partition_table.populate_checksum(&StandAloneChecksumCalculator::new());
        self.flash_driver
            .write(0, partition_table.as_bytes())
            .map_err(|_| BootConfigError::WriteFailed)?;
        Ok(())
    }

    fn increment_boot_count(&self, partition_id: PartitionId) -> Result<u16, BootConfigError> {
        let mut partition_table = self
            .read_partition_table()
            .map_err(|_| BootConfigError::ReadFailed)?;
        let boot_count = match partition_id {
            PartitionId::A => {
                partition_table.partition_a_boot_count += 1;
                partition_table.partition_a_boot_count
            }
            PartitionId::B => {
                partition_table.partition_b_boot_count += 1;
                partition_table.partition_b_boot_count
            }
            _ => return Err(BootConfigError::InvalidPartition),
        };
        // Write the updated partition table back to flash
        let checksum_calculator = StandAloneChecksumCalculator::new();
        partition_table.populate_checksum(&checksum_calculator);

        self.flash_driver
            .write(0, partition_table.as_bytes())
            .map_err(|_| BootConfigError::WriteFailed)?;
        Ok(boot_count)
    }

    fn get_boot_count(&self, partition_id: PartitionId) -> Result<u16, BootConfigError> {
        let partition_table = self
            .read_partition_table()
            .map_err(|_| BootConfigError::ReadFailed)?;
        match partition_id {
            PartitionId::A => Ok(partition_table.partition_a_boot_count),
            PartitionId::B => Ok(partition_table.partition_b_boot_count),
            _ => Err(BootConfigError::InvalidPartition),
        }
    }

    fn set_rollback_enable(&mut self, enable: bool) -> Result<(), BootConfigError> {
        let mut partition_table = self
            .read_partition_table()
            .map_err(|_| BootConfigError::ReadFailed)?;
        partition_table.rollback_enable = if enable {
            RollbackEnable::Enabled as u32
        } else {
            RollbackEnable::Disabled as u32
        };
        partition_table.populate_checksum(&StandAloneChecksumCalculator::new());
        self.flash_driver
            .write(0, partition_table.as_bytes())
            .map_err(|_| BootConfigError::WriteFailed)?;
        Ok(())
    }

    fn set_partition_status(
        &mut self,
        partition_id: mcu_config::boot::PartitionId,
        status: mcu_config::boot::PartitionStatus,
    ) -> Result<(), mcu_config::boot::BootConfigError> {
        let mut partition_table = self
            .read_partition_table()
            .map_err(|_| BootConfigError::ReadFailed)?;
        match partition_id {
            PartitionId::A => partition_table.partition_a_status = status as u16,
            PartitionId::B => partition_table.partition_b_status = status as u16,
            _ => return Err(BootConfigError::InvalidPartition),
        }
        // Write the updated partition table back to flash
        let checksum_calculator = StandAloneChecksumCalculator::new();
        partition_table.populate_checksum(&checksum_calculator);

        self.flash_driver
            .write(0, partition_table.as_bytes())
            .map_err(|_| BootConfigError::WriteFailed)?;
        Ok(())
    }

    fn get_partition_status(
        &self,
        partition_id: mcu_config::boot::PartitionId,
    ) -> Result<mcu_config::boot::PartitionStatus, mcu_config::boot::BootConfigError> {
        let partition_table = self
            .read_partition_table()
            .map_err(|_| BootConfigError::ReadFailed)?;
        match partition_id {
            PartitionId::A => Ok(partition_table
                .partition_a_status
                .try_into()
                .unwrap_or(PartitionStatus::Invalid)),
            PartitionId::B => Ok(partition_table
                .partition_b_status
                .try_into()
                .unwrap_or(PartitionStatus::Invalid)),
            _ => Err(BootConfigError::InvalidPartition),
        }
    }

    fn is_rollback_enabled(&self) -> Result<bool, mcu_config::boot::BootConfigError> {
        let partition_table = self
            .read_partition_table()
            .map_err(|_| BootConfigError::ReadFailed)?;
        Ok(partition_table.rollback_enable == RollbackEnable::Enabled as u32)
    }
}
