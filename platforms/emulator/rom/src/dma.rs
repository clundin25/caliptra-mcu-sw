// Licensed under the Apache-2.0 license

// Dma controller driver for the dummy dma controller in the emulator.


use romtime::StaticRef;
use registers_generated::dma_ctrl::{bits::*, regs::*, DMA_CTRL_ADDR};
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};

pub const DMA_CTRL_BASE: StaticRef<DmaCtrl> =
    unsafe { StaticRef::new(DMA_CTRL_ADDR as *const DmaCtrl) };

use mcu_rom_common::{Dma, DMAError, DMAStatus, DmaRoute};

const MCU_SRAM_HI_OFFSET: u64 = 0x4000_0000; // Mapped to ROM SRAM space

const INDIRECT_FIFO_AXI_ADDRESS: u64 = 0x3000_0000_0000_0000;
fn local_ram_to_axi_address(addr: u32) -> u64 {
    // Convert a local address to an AXI address
    (MCU_SRAM_HI_OFFSET << 32) | (addr as u64)
}

pub struct EmulatedDmaCtrl {
    registers: StaticRef<DmaCtrl>
}

impl EmulatedDmaCtrl {
    pub fn new() -> EmulatedDmaCtrl {
        let instance = EmulatedDmaCtrl {
            registers: DMA_CTRL_BASE
        };
        instance.init();
        instance
    }

    pub fn init(&self) {
        self.registers
            .dma_op_status
            .modify(DmaOpStatus::Err::CLEAR + DmaOpStatus::Done::CLEAR);

        self.clear_error_interrupt();
        self.clear_event_interrupt();
    }

    fn enable_interrupts(&self) {
        self.registers
            .dma_interrupt_enable
            .modify(DmaInterruptEnable::Error::SET + DmaInterruptEnable::Event::SET);
    }

    fn disable_interrupts(&self) {
        self.registers
            .dma_interrupt_enable
            .modify(DmaInterruptEnable::Error::CLEAR + DmaInterruptEnable::Event::CLEAR);
    }

    fn clear_error_interrupt(&self) {
        // Clear the error interrupt. Write 1 to clear
        self.registers
            .dma_interrupt_state
            .modify(DmaInterruptState::Error::SET);
    }

    fn clear_event_interrupt(&self) {
        // Clear the event interrupt. Write 1 to clear
        self.registers
            .dma_interrupt_state
            .modify(DmaInterruptState::Event::SET);
    }

    pub fn poll_interrupts(&self) -> Result<DMAStatus, DMAError> {

        let res ;
        romtime::println!("12");
        loop {
            let dmactrl_intr = self.registers.dma_interrupt_state.extract();
            if dmactrl_intr.is_set(DmaInterruptState::Error)
            {
                romtime::println!("14");
                let op_status = self.registers.dma_op_status.extract();

                // Clear the op_status register
                self.registers.dma_op_status.modify(DmaOpStatus::Err::CLEAR);

                self.clear_error_interrupt();

                if op_status.is_set(DmaOpStatus::Err) {
                    res = Err(DMAError::AxiWriteError);
                    
                } else {
                    res = Err(DMAError::AxiReadError);
                }
                break;
            }
            else if dmactrl_intr.is_set(DmaInterruptState::Event) {
                romtime::println!("15");
                // Clear the op_status register
                self.registers
                    .dma_op_status
                    .modify(DmaOpStatus::Done::CLEAR);

                // Clear the interrupt before callback as it is possible that the callback will start another operation.
                // Otherwise, emulated dma ctrl won't allow starting another operation if the previous one is not cleared.
                self.clear_event_interrupt();

                res = Ok(DMAStatus::TxnDone);
                break;
            }
        }
        romtime::println!("16");

        self.disable_interrupts();
        romtime::println!("17");
        res

    }

}

impl Dma for EmulatedDmaCtrl {
    fn configure_transfer(
        &self,
        byte_count: usize,
        block_size: usize,
        src_addr: Option<u64>,
        dest_addr: Option<u64>,
    ) -> Result<(), DMAError> {
        // Check if the parameters are valid
        if byte_count == 0 || block_size == 0 || block_size > byte_count {
            return Err(DMAError::CommandError);
        }

        romtime::println!("DmaEMulator source addr {:#x}", src_addr.unwrap_or(0));
        // Set the source and destination addresses
        if let Some(src_addr) = src_addr {
            self.registers
                .source_addr_high
                .set((src_addr >> 32) as u32);
            self.registers
                .source_addr_lower
                .set((src_addr & 0xffff_ffff) as u32);

        } else {
            return Err(DMAError::CommandError);
        }

        if let Some(dest_addr) = dest_addr {
             self.registers
            .dest_addr_high
            .set((dest_addr >> 32) as u32);

            self.registers
                .dest_addr_lower
                .set((dest_addr & 0xffff_ffff) as u32);

        } else {
            return Err(DMAError::CommandError);
        }

        // Set the transfer size
        self.registers.xfer_size.set(byte_count as u32);

        Ok(())
    }

    fn start_transfer(
        &self,
        route: DmaRoute,
    ) -> Result<(), DMAError> {
        if route != DmaRoute::AxiToAxi {
            // Only AxiToAxi route is supported
            return Err(DMAError::CommandError);
        }
        self.enable_interrupts();
        self.registers.dma_control.modify(DmaControl::Start::SET);
        Ok(())
    }

    fn wait_transaction_done(&self) -> Result<DMAStatus, DMAError> {
        self.poll_interrupts()
    }

    fn write_fifo(&self, data: &[u8]) -> Result<(), DMAError> {
        let source_address = local_ram_to_axi_address(data.as_ptr() as u32);

        romtime::println!("8");
        self.configure_transfer(
            data.len(),
            data.len(),
            Some(source_address),
            Some(INDIRECT_FIFO_AXI_ADDRESS),
        )?;
        romtime::println!("9");
        self.start_transfer(DmaRoute::AxiToAxi)?;
        romtime::println!("11");
        match self.wait_transaction_done() {
            Ok(DMAStatus::TxnDone) => {
                // Transaction is done, we can exit
                romtime::println!("12");
                return Ok(());
            }
            Ok(_) => {
                return Err(DMAError::AxiWriteError);
            }
            Err(e) => {
                romtime::println!("14");
                return Err(e);
            }
            
        }
        
    }


}
