// Licensed under the Apache-2.0 license

use libsyscall_caliptra::dma::{AXIAddr, DMASource, DMATransaction, DMA as DMASyscall};
use core::fmt::Write;
use libtock_platform::Syscalls;
use romtime::{println, test_exit};
use zerocopy::{FromBytes, IntoBytes};

const MCU_SRAM_HI_OFFSET: u64 = 0x1000_0000;
const EXTERNAL_SRAM_HI_OFFSET: u64 = 0x2000_0000;


#[allow(unused)]
pub(crate) async fn test_dma<S: Syscalls>() {
    println!("Starting DMA test");

    let dma_syscall = DMASyscall::<S>::new();

    let my_buffer_source = [0xABu8; 16];
    let mut my_buffer_dest = [0u8; 16];

    // Address of my_buffer_source
    let source_address = (MCU_SRAM_HI_OFFSET << 32) |  (&my_buffer_source as *const _ as u64);
    let dest_address = (MCU_SRAM_HI_OFFSET << 32) |  (&my_buffer_dest as *const _ as u64);

    println!("Emulator source address: {:#x}", source_address);
    println!("Emulator destination address: {:#x}", dest_address);

    let transaction = DMATransaction {
        byte_count: 16,
        source: DMASource::Address(source_address),
        dest_addr: dest_address,
    };
    println!("Emulator calling DMA transfer");
    dma_syscall.xfer(&transaction).await.unwrap();
    println!("Emulator DMA transfer completed my_buffer_dest: {:?}", my_buffer_dest);

}
