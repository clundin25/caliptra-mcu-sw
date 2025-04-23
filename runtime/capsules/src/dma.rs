// Licensed under the Apache-2.0 license

//! This provides  the dma partition syscall driver

use core::cmp;
use kernel::grant::{AllowRoCount, AllowRwCount, Grant, UpcallCount};
use kernel::hil::sensors::PressureClient;
use kernel::processbuffer::{ReadableProcessBuffer, WriteableProcessBuffer};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::utilities::cells::{OptionalCell, TakeCell};
use kernel::{process, ErrorCode, ProcessId};
use dma_driver::dma_ctrl::EmulatedDmaCtrl;
use romtime::println;

/// Each partition is presented to userspace as a separate driver number.
/// Below is the temporary driver number for each partition.
pub const DMA_CTRL_DRIVER_NUM: usize = 0x9000_0000;

pub const BUF_LEN: usize = 512;

pub const BLOCK_SIZE: usize = 1; // Currently supported block size is 1 byte (byte transfer)

/// Subscription IDs for asynchronous notifications.
mod dma_subscribe {
    pub const XFER_DONE: u32 = 0;
}

mod dma_cmd {
    pub const SET_BYTE_XFER_COUNT: u32 = 0;
    pub const SET_SRC_ADDR: u32 = 1;
    pub const SET_DEST_ADDR: u32 = 2;
    pub const XFER_AXI_TO_AXI: u32 = 3;
}

pub struct App { 
    pub source_address: Option<u64>,
    pub dest_address: Option<u64>,
    pub length: usize,
}

impl Default for App {
    fn default() -> Self {
        App {
            source_address: None,
            dest_address: None,
            length: 0,
        }
    }
}

pub struct Dma<'a> {
    // The underlying dma storage driver.
    driver: &'a dyn dma_driver::hil::DMA,
    // Per-app state.
    apps: Grant<
        App,
        UpcallCount< 1 >,
        AllowRoCount< 0 >,
        AllowRwCount< 0 >,
    >,
    current_app: OptionalCell<ProcessId>,

}

impl<'a> Dma<'a> {
    pub fn new(
        driver: &'a dyn dma_driver::hil::DMA,
        grant: Grant<
            App,
            UpcallCount<1>,
            AllowRoCount<0>,
            AllowRwCount<0>,
        >,
    ) -> Dma<'a> {
        Dma {
            driver,
            apps: grant,
            current_app: OptionalCell::empty(),
        }
    }


    fn set_source_address(&self, address: u64, processid: Option<ProcessId>) -> Result<(), ErrorCode> {
        processid.map_or(Err(ErrorCode::FAIL), |processid| {
            self.apps
                .enter(processid, |app, _| {
                    app.source_address = Some(address);
                    Ok(())
                })
                .unwrap_or_else(|err| Err(err.into()))
        })
    }

    fn set_destination_address(&self, address: u64, processid: Option<ProcessId>) -> Result<(), ErrorCode> {
        processid.map_or(Err(ErrorCode::FAIL), |processid| {
            self.apps
                .enter(processid, |app, _| {
                    app.dest_address = Some(address);
                    Ok(())
                })
                .unwrap_or_else(|err| Err(err.into()))
        })
    }

    fn set_transfer_size(&self, size: usize, processid: Option<ProcessId>) -> Result<(), ErrorCode> {
        processid.map_or(Err(ErrorCode::FAIL), |processid| {
            self.apps
                .enter(processid, |app, _| {
                    app.length = size;
                    Ok(())
                })
                .unwrap_or_else(|err| Err(err.into()))
        })
    }

    fn start_transfer(&self, processid: Option<ProcessId>) -> Result<(), ErrorCode> {
        println!("Device capsule start transfer");
        if self.current_app.is_none() {
            if let Some(pid) = processid {
                println!("Device capsule set process id {:?}", pid);
                self.current_app.set(pid);
            }
        }
        processid.map_or(Err(ErrorCode::FAIL), |processid| {
            self.apps
                .enter(processid, |app, _| {
                    self.driver.configure_transfer(app.length, BLOCK_SIZE, app.source_address, app.dest_address)?;
                    self.driver.start_transfer(dma_driver::hil::DmaRoute::AxiToAxi, dma_driver::hil::DmaRoute::AxiToAxi, false)
                })
                .unwrap_or_else(|err| Err(err.into()))
        })
    }

}


impl dma_driver::hil::DMAClient for Dma<'_> {
   
    fn transfer_complete(&self, status: dma_driver::hil::DMAStatus) {
        println!("Device capsule transfer complete");
        if let Some(processid) = self.current_app.take() {
            println!("Device capsule processid {:?}", processid);
            let _ = self.apps.enter(processid, move |_, kernel_data| {
                println!("Device Scheduling upcall");
                // Signal the app.
                kernel_data
                    .schedule_upcall(dma_subscribe::XFER_DONE as usize, (status as usize, 0, 0))
                    .ok();
            });
        };
                
    }
    
    fn transfer_error(&self, error: dma_driver::hil::DMAError) {
        println!("Device capsule transfer error");
        if let Some(processid) = self.current_app.take() {
            let _ = self.apps.enter(processid, move |_, kernel_data| {
                println!("Device Scheduling upcall");
                // Signal the app.
                kernel_data
                    .schedule_upcall(dma_subscribe::XFER_DONE as usize, (error as usize, 0, 0))
                    .ok();
            });
        };
    }
}

/// Provide an interface for userland.
impl SyscallDriver for Dma<'_> {
    /// Command interface.
    ///
    /// Commands are selected by the lowest 8 bits of the first argument.
    ///
    /// ### `command_num`
    ///
    /// - `0`: Return Ok(()) if this driver is included on the platform.
    /// - `1`: Return the number of bytes available to userspace.
    /// - `2`: Start a read
    /// - `3`: Start a write
    /// - `4`: Start an erase
    /// - `5`: Return the chunk size for reads and writes
    fn command(
        &self,
        command_num: usize,
        r2: usize,
        r3: usize,
        processid: ProcessId,
    ) -> CommandReturn {
        match command_num as u32 {
            dma_cmd::SET_BYTE_XFER_COUNT => {
                match self.set_transfer_size(r2, Some(processid)) {
                    Ok(()) => CommandReturn::success(),
                    Err(e) => CommandReturn::failure(e),
                }
            }
            dma_cmd::SET_SRC_ADDR => {
                let addr : u64 = (r3 as u64) << 32 | (r2 as u64);
                match self.set_source_address(addr, Some(processid)) {
                    Ok(()) => CommandReturn::success(),
                    Err(e) => CommandReturn::failure(e),
                }
            }
            dma_cmd::SET_DEST_ADDR => {
                let addr : u64 = (r3 as u64) << 32 | (r2 as u64);
                match self.set_destination_address(addr, Some(processid)) {
                    Ok(()) => CommandReturn::success(),
                    Err(e) => CommandReturn::failure(e),
                }
            }
            dma_cmd::XFER_AXI_TO_AXI => {
                // Start the transfer
                match self.start_transfer(Some(processid)) {
                    Ok(()) => CommandReturn::success(),
                    Err(e) => CommandReturn::failure(e),
                }
            }

            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }
    }

    fn allocate_grant(&self, processid: ProcessId) -> Result<(), kernel::process::Error> {
        self.apps.enter(processid, |_, _| {})
    }
}
