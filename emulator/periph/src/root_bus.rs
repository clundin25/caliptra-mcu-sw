/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    File contains the root Bus implementation for a full-featured Caliptra emulator.

--*/

use crate::{spi_host::SpiHost, EmuCtrl, Uart};
use caliptra_emu_bus::{Bus, BusError, Clock, Ram, Rom};
use caliptra_emu_bus::{Device, Event, EventData};
use caliptra_emu_cpu::{Pic, PicMmioRegisters};
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use emulator_consts::{
    DIRECT_READ_FLASH_ORG, DIRECT_READ_FLASH_SIZE, EXTERNAL_TEST_SRAM_SIZE, RAM_SIZE,
    ROM_DEDICATED_RAM_ORG, ROM_DEDICATED_RAM_SIZE,
};
use std::{
    cell::RefCell,
    path::PathBuf,
    rc::Rc,
    sync::{mpsc, Arc, Mutex},
};

#[derive(Debug, Clone)]
pub struct McuRootBusOffsets {
    pub rom_offset: u32,
    pub rom_size: u32,
    pub uart_offset: u32,
    pub uart_size: u32,
    pub ctrl_offset: u32,
    pub ctrl_size: u32,
    pub spi_offset: u32,
    pub spi_size: u32,
    pub ram_offset: u32,
    pub ram_size: u32,
    pub rom_dedicated_ram_offset: u32,
    pub rom_dedicated_ram_size: u32,
    pub pic_offset: u32,
    pub external_test_sram_offset: u32,
    pub external_test_sram_size: u32,
    pub direct_read_flash_offset: u32,
    pub direct_read_flash_size: u32,
}

impl Default for McuRootBusOffsets {
    fn default() -> Self {
        Self {
            rom_offset: 0,
            rom_size: 0xc000,
            uart_offset: 0x1000_1000,
            uart_size: 0x100,
            ctrl_offset: 0x1000_2000,
            ctrl_size: 0x4,
            spi_offset: 0x2000_0000,
            spi_size: 0x40,
            ram_offset: 0x4000_0000,
            ram_size: 0x60000,
            rom_dedicated_ram_offset: ROM_DEDICATED_RAM_ORG,
            rom_dedicated_ram_size: ROM_DEDICATED_RAM_SIZE,
            pic_offset: 0x6000_0000,
            external_test_sram_offset: 0x8000_0000,
            external_test_sram_size: 0x1000,
            direct_read_flash_offset: DIRECT_READ_FLASH_ORG,
            direct_read_flash_size: DIRECT_READ_FLASH_SIZE,
        }
    }
}

const PIC_SIZE: u32 = 0x5400;

/// Caliptra Root Bus Arguments
#[derive(Default)]
pub struct McuRootBusArgs {
    pub pic: Rc<Pic>,
    pub clock: Rc<Clock>,
    pub rom: Vec<u8>,
    pub log_dir: PathBuf,
    pub uart_output: Option<Rc<RefCell<Vec<u8>>>>,
    pub uart_rx: Option<Arc<Mutex<Option<u8>>>>,
    pub offsets: McuRootBusOffsets,
}

pub struct McuRootBus {
    pub rom: Rom,
    pub uart: Uart,
    pub ctrl: EmuCtrl,
    pub spi: SpiHost,
    pub ram: Rc<RefCell<Ram>>,
    pub rom_sram: Rc<RefCell<Ram>>,
    pub pic_regs: PicMmioRegisters,
    pub external_test_sram: Rc<RefCell<Ram>>,
    pub direct_read_flash: Rc<RefCell<Ram>>,
    event_sender: Option<mpsc::Sender<Event>>,
    offsets: McuRootBusOffsets,
}

impl McuRootBus {
    pub const UART_NOTIF_IRQ: u8 = 16;
    pub const I3C_ERROR_IRQ: u8 = 17;
    pub const I3C_NOTIF_IRQ: u8 = 18;
    pub const PRIMARY_FLASH_CTRL_ERROR_IRQ: u8 = 19;
    pub const PRIMARY_FLASH_CTRL_EVENT_IRQ: u8 = 20;
    pub const SECONDARY_FLASH_CTRL_ERROR_IRQ: u8 = 21;
    pub const SECONDARY_FLASH_CTRL_EVENT_IRQ: u8 = 22;
    pub const DMA_ERROR_IRQ: u8 = 23;
    pub const DMA_EVENT_IRQ: u8 = 24;
    pub const DOE_MBOX_EVENT_IRQ: u8 = 25;

    pub fn new(mut args: McuRootBusArgs) -> Result<Self, std::io::Error> {
        let clock = args.clock;
        let pic = args.pic;
        let rom = Rom::new(std::mem::take(&mut args.rom));
        let uart_irq = pic.register_irq(Self::UART_NOTIF_IRQ);
        let ram = Ram::new(vec![0; RAM_SIZE as usize]);
        let rom_sram = Ram::new(vec![0; ROM_DEDICATED_RAM_SIZE as usize]);
        let external_test_sram = Ram::new(vec![0; EXTERNAL_TEST_SRAM_SIZE as usize]);
        let direct_read_flash = Ram::new(vec![0; DIRECT_READ_FLASH_SIZE as usize]);

        Ok(Self {
            rom,
            ram: Rc::new(RefCell::new(ram)),
            rom_sram: Rc::new(RefCell::new(rom_sram)),
            spi: SpiHost::new(&clock.clone()),
            uart: Uart::new(args.uart_output, args.uart_rx, uart_irq, &clock.clone()),
            ctrl: EmuCtrl::new(),
            pic_regs: pic.mmio_regs(clock.clone()),
            event_sender: None,
            external_test_sram: Rc::new(RefCell::new(external_test_sram)),
            direct_read_flash: Rc::new(RefCell::new(direct_read_flash)),
            offsets: args.offsets,
        })
    }

    pub fn load_ram(&mut self, offset: usize, data: &[u8]) {
        if offset + data.len() > self.ram.borrow().len() as usize {
            panic!("Data exceeds RAM size");
        }
        self.ram.borrow_mut().data_mut()[offset..offset + data.len()].copy_from_slice(data);
    }

    pub fn load_test_sram(&mut self, offset: usize, data: &[u8]) {
        if offset + data.len() > self.external_test_sram.borrow().len() as usize {
            panic!("Data exceeds TEST SRAM size");
        }
        self.ram.borrow_mut().data_mut()[offset..offset + data.len()].copy_from_slice(data);
    }
}

impl Bus for McuRootBus {
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        if addr >= self.offsets.rom_offset && addr < self.offsets.rom_offset + self.offsets.rom_size
        {
            return self.rom.read(size, addr - self.offsets.rom_offset);
        }
        if addr >= self.offsets.uart_offset
            && addr < self.offsets.uart_offset + self.offsets.uart_size
        {
            return self.uart.read(size, addr - self.offsets.uart_offset);
        }
        if addr >= self.offsets.ctrl_offset
            && addr < self.offsets.ctrl_offset + self.offsets.ctrl_size
        {
            return self.ctrl.read(size, addr - self.offsets.ctrl_offset);
        }
        if addr >= self.offsets.spi_offset && addr < self.offsets.spi_offset + self.offsets.spi_size
        {
            return self.spi.read(size, addr - self.offsets.spi_offset);
        }
        if addr >= self.offsets.ram_offset && addr < self.offsets.ram_offset + self.offsets.ram_size
        {
            return self
                .ram
                .borrow_mut()
                .read(size, addr - self.offsets.ram_offset);
        }
        if addr >= self.offsets.rom_dedicated_ram_offset
            && addr < self.offsets.rom_dedicated_ram_offset + self.offsets.rom_dedicated_ram_size
        {
            return self
                .rom_sram
                .borrow_mut()
                .read(size, addr - self.offsets.rom_dedicated_ram_offset);
        }
        if addr >= self.offsets.pic_offset && addr < self.offsets.pic_offset + PIC_SIZE {
            return self.pic_regs.read(size, addr - self.offsets.pic_offset);
        }
        if addr >= self.offsets.external_test_sram_offset
            && addr < self.offsets.external_test_sram_offset + self.offsets.external_test_sram_size
        {
            return self
                .external_test_sram
                .borrow_mut()
                .read(size, addr - self.offsets.external_test_sram_offset);
        }
        if addr >= self.offsets.direct_read_flash_offset
            && addr < self.offsets.direct_read_flash_offset + self.offsets.direct_read_flash_size
        {
            return self
                .direct_read_flash
                .borrow_mut()
                .read(size, addr - self.offsets.direct_read_flash_offset);
        }
        Err(BusError::LoadAccessFault)
    }

    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError> {
        if addr >= self.offsets.rom_offset && addr < self.offsets.rom_offset + self.offsets.rom_size
        {
            return self.rom.write(size, addr - self.offsets.rom_offset, val);
        }
        if addr >= self.offsets.uart_offset
            && addr < self.offsets.uart_offset + self.offsets.uart_size
        {
            return self.uart.write(size, addr - self.offsets.uart_offset, val);
        }
        if addr >= self.offsets.ctrl_offset
            && addr < self.offsets.ctrl_offset + self.offsets.ctrl_size
        {
            return self.ctrl.write(size, addr - self.offsets.ctrl_offset, val);
        }
        if addr >= self.offsets.spi_offset && addr < self.offsets.spi_offset + self.offsets.spi_size
        {
            return self.spi.write(size, addr - self.offsets.spi_offset, val);
        }
        if addr >= self.offsets.ram_offset && addr < self.offsets.ram_offset + self.offsets.ram_size
        {
            return self
                .ram
                .borrow_mut()
                .write(size, addr - self.offsets.ram_offset, val);
        }
        if addr >= self.offsets.rom_dedicated_ram_offset
            && addr < self.offsets.rom_dedicated_ram_offset + self.offsets.rom_dedicated_ram_size
        {
            return self.rom_sram.borrow_mut().write(
                size,
                addr - self.offsets.rom_dedicated_ram_offset,
                val,
            );
        }
        if addr >= self.offsets.pic_offset && addr < self.offsets.pic_offset + PIC_SIZE {
            return self
                .pic_regs
                .write(size, addr - self.offsets.pic_offset, val);
        }
        if addr >= self.offsets.external_test_sram_offset
            && addr < self.offsets.external_test_sram_offset + self.offsets.external_test_sram_size
        {
            return self.external_test_sram.borrow_mut().write(
                size,
                addr - self.offsets.external_test_sram_offset,
                val,
            );
        }
        Err(BusError::StoreAccessFault)
    }

    fn poll(&mut self) {
        self.rom.poll();
        self.uart.poll();
        self.ctrl.poll();
        self.spi.poll();
        self.ram.borrow_mut().poll();
        self.rom_sram.borrow_mut().poll();
        self.pic_regs.poll();
        self.external_test_sram.borrow_mut().poll();
        self.direct_read_flash.borrow_mut().poll();
    }

    fn warm_reset(&mut self) {
        self.rom.warm_reset();
        self.uart.warm_reset();
        self.ctrl.warm_reset();
        self.spi.warm_reset();
        self.ram.borrow_mut().warm_reset();
        self.rom_sram.borrow_mut().warm_reset();
        self.pic_regs.warm_reset();
        self.external_test_sram.borrow_mut().warm_reset();
        self.direct_read_flash.borrow_mut().warm_reset();
    }

    fn update_reset(&mut self) {
        self.rom.update_reset();
        self.uart.update_reset();
        self.ctrl.update_reset();
        self.spi.update_reset();
        self.ram.borrow_mut().update_reset();
        self.rom_sram.borrow_mut().update_reset();
        self.pic_regs.update_reset();
        self.external_test_sram.borrow_mut().update_reset();
        self.direct_read_flash.borrow_mut().update_reset();
    }

    fn register_outgoing_events(&mut self, sender: mpsc::Sender<Event>) {
        self.rom.register_outgoing_events(sender.clone());
        self.uart.register_outgoing_events(sender.clone());
        self.ctrl.register_outgoing_events(sender.clone());
        self.spi.register_outgoing_events(sender.clone());
        self.ram
            .borrow_mut()
            .register_outgoing_events(sender.clone());
        self.pic_regs.register_outgoing_events(sender.clone());
        self.event_sender = Some(sender);
    }

    fn incoming_event(&mut self, event: Rc<Event>) {
        self.rom.incoming_event(event.clone());
        self.uart.incoming_event(event.clone());
        self.ctrl.incoming_event(event.clone());
        self.spi.incoming_event(event.clone());
        self.ram.borrow_mut().incoming_event(event.clone());
        self.pic_regs.incoming_event(event.clone());

        if let (Device::MCU, EventData::MemoryRead { start_addr, len }) =
            (event.dest, event.event.clone())
        {
            let start = start_addr as usize;
            let len = len as usize;
            if start >= RAM_SIZE as usize || start + len >= RAM_SIZE as usize {
                println!(
                    "Ignoring invalid MCU RAM read from {}..{}",
                    start,
                    start + len
                );
            } else {
                let ram = self.ram.borrow();
                let ram_size = ram.len() as usize;
                let len = len.min(ram_size - start);

                if let Some(event_sender) = self.event_sender.as_ref() {
                    event_sender
                        .send(Event {
                            src: Device::MCU,
                            dest: event.src,
                            event: EventData::MemoryReadResponse {
                                start_addr,
                                data: ram.data()[start..start + len].to_vec(),
                            },
                        })
                        .unwrap();
                }
            }
        }

        if let (Device::MCU, EventData::MemoryWrite { start_addr, data }) =
            (event.dest, event.event.clone())
        {
            let start = start_addr as usize;
            if start >= RAM_SIZE as usize || start + data.len() >= RAM_SIZE as usize {
                println!(
                    "Ignoring invalid MCU RAM write to {}..{}",
                    start,
                    start + data.len()
                );
            } else {
                let mut ram = self.ram.borrow_mut();
                let ram_size = ram.len() as usize;
                let len = data.len().min(ram_size - start);
                ram.data_mut()[start..start + len].copy_from_slice(&data[..len]);
            }
        }

        if let (Device::ExternalTestSram, EventData::MemoryRead { start_addr, len }) =
            (event.dest, event.event.clone())
        {
            let start = start_addr as usize;
            let len = len as usize;
            if start >= EXTERNAL_TEST_SRAM_SIZE as usize
                || start + len >= EXTERNAL_TEST_SRAM_SIZE as usize
            {
                println!(
                    "Ignoring invalid MCU TEST RAM read from {}..{}",
                    start,
                    start + len
                );
            } else {
                let ram = self.external_test_sram.borrow();
                let ram_size = ram.len() as usize;
                let len = len.min(ram_size - start);

                if let Some(event_sender) = self.event_sender.as_ref() {
                    event_sender
                        .send(Event {
                            src: Device::MCU,
                            dest: event.src,
                            event: EventData::MemoryReadResponse {
                                start_addr,
                                data: ram.data()[start..start + len].to_vec(),
                            },
                        })
                        .unwrap();
                }
            }
        }
    }
}
