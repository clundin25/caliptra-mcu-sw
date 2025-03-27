// This code is translated from the Xilinx I3C C driver:
// https://github.com/Xilinx/embeddedsw/tree/master/XilinxProcessorIPLib/drivers/i3c/src
// Which is:
// Copyright (C) 2024 Advanced Micro Devices, Inc. All Rights Reserved
// SPDX-License-Identifier: MIT

#![allow(dead_code)]

use std::time::Duration;
use tock_registers::interfaces::{Readable, Writeable};
use tock_registers::register_structs;
use tock_registers::registers::{ReadOnly, ReadWrite};

const XI3C_BROADCAST_ADDRESS: u8 = 0x7e;

register_structs! {
    pub XI3c {
        (0x0 => pub version: ReadOnly<u32>), // Version Register
        (0x4 => pub reset: ReadWrite<u32>), // Soft Reset Register
        (0x8 => pub cr: ReadWrite<u32>), // Control Register
        (0xC => pub address: ReadWrite<u32>), // Target Address Register
        (0x10 => pub sr: ReadWrite<u32>), // Status Register
        (0x14 => pub intr_status: ReadWrite<u32>), // Status Event Register
        (0x18 => pub intr_re: ReadWrite<u32>), // Status Event Enable(Rising Edge) Register
        (0x1C => pub intr_fe: ReadWrite<u32>), // Status Event Enable(Falling Edge) Register
        (0x20 => pub cmd_fifo: ReadWrite<u32>), // I3C Command FIFO Register
        (0x24 => pub wr_fifo: ReadWrite<u32>), // I3C Write Data FIFO Register
        (0x28 => pub rd_fifo: ReadWrite<u32>), // I3C Read Data FIFO Register
        (0x2C => pub resp_status_fifo: ReadWrite<u32>), // I3C Response status FIFO Register
        (0x30 => pub fifo_lvl_status: ReadWrite<u32>), // I3C CMD & WR FIFO LVL Register
        (0x34 => pub fifo_lvl_status_1: ReadWrite<u32>), // I3C RESP & RD FIFO LVL  Register
        (0x38 => pub scl_high_time: ReadWrite<u32>), // I3C SCL HIGH Register
        (0x3C => pub scl_low_time: ReadWrite<u32>), // I3C SCL LOW  Register
        (0x40 => pub sda_hold_time: ReadWrite<u32>), // I3C SDA HOLD Register
        (0x44 => pub bus_idle: ReadWrite<u32>), // I3C CONTROLLER BUS IDLE Register
        (0x48 => pub tsu_start: ReadWrite<u32>), // I3C START SETUP Register
        (0x4C => pub thd_start: ReadWrite<u32>), // I3C START HOLD Register
        (0x50 => pub tsu_stop: ReadWrite<u32>), // I3C STOP Setup Register
        (0x54 => pub od_scl_high_time: ReadWrite<u32>), // I3C OD SCL HIGH Register
        (0x58 => pub od_scl_low_time: ReadWrite<u32>), // I3C OD SCL LOW  Register
        (0x5C => _reserved),
        (0x60 => pub target_addr_bcr: ReadWrite<u32>), // I3C Target dynamic Address and BCR Register
        (0x64 => @END),
    }
}

#[derive(Clone)]
pub struct Config {
    pub device_id: u16,
    pub base_address: *mut u32,
    pub input_clock_hz: u32,
    pub rw_fifo_depth: u8,
    pub wr_threshold: u8,
    pub device_count: u8,
    pub ibi_capable: bool,
    pub hj_capable: bool,
}

#[derive(Copy, Clone, Default)]
pub struct Command {
    pub cmd_type: u8,
    pub no_repeated_start: u8,
    pub pec: u8,
    pub target_addr: u8,
    pub rw: u8,
    pub byte_count: u16,
    pub tid: u8,
}
#[derive(Copy, Clone, Default)]
pub struct TargetInfo {
    pub dyna_addr: u8,
    pub id: u64,
    pub bcr: u8,
    pub dcr: u8,
}

pub struct Controller {
    pub config: Config,
    pub ready: bool,
    pub error: u8,
    pub cur_device_count: u8,
    pub status_handler: Option<Box<dyn ErrorHandler>>,
    pub target_info_table: [TargetInfo; 108],
}

pub trait ErrorHandler {
    fn handle_error(&self, error: u32);
}

pub static DYNA_ADDR_LIST: [u8; 108] = [
    0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
    0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
    0x5a, 0x5b, 0x5c, 0x5d, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a,
    0x6b, 0x6c, 0x6d, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x77,
];

impl Controller {
    pub fn new(base_ptr: *mut u32) -> Self {
        Controller {
            config: Config {
                device_id: 0,
                base_address: base_ptr,
                input_clock_hz: 0,
                rw_fifo_depth: 0,
                wr_threshold: 0,
                device_count: 0,
                ibi_capable: false,
                hj_capable: false,
            },
            ready: false,
            error: 0,
            cur_device_count: 0,
            status_handler: None,
            target_info_table: [TargetInfo::default(); 108],
        }
    }

    #[inline(always)]
    pub(crate) const fn regs(&self) -> &XI3c {
        unsafe { &*(self.config.base_address as *const XI3c) }
    }

    pub fn bus_init(&mut self) -> Result<(), i32> {
        let mut cmd: Command = Command {
            cmd_type: 0,
            no_repeated_start: 0,
            pec: 0,
            target_addr: 0,
            rw: 0,
            byte_count: 0,
            tid: 0,
        };
        cmd.target_addr = XI3C_BROADCAST_ADDRESS;
        cmd.no_repeated_start = 1;
        cmd.tid = 0;
        cmd.pec = 0;
        cmd.cmd_type = 1;
        const XI3C_CCC_BRDCAST_DISEC: u8 = 0x1;
        self.send_transfer_cmd(&mut cmd, 0x1)?;
        cmd.target_addr = XI3C_BROADCAST_ADDRESS;
        cmd.no_repeated_start = 1;
        cmd.tid = 0;
        cmd.pec = 0;
        cmd.cmd_type = 1;
        const XI3C_CCC_BRDCAST_ENEC: u8 = 0x0;
        self.send_transfer_cmd(&mut cmd, XI3C_CCC_BRDCAST_ENEC)?;
        cmd.target_addr = XI3C_BROADCAST_ADDRESS;
        cmd.no_repeated_start = 1;
        cmd.tid = 0;
        cmd.pec = 0;
        cmd.cmd_type = 1;
        const XI3C_CCC_BRDCAST_RSTDAA: u8 = 0x6;
        self.send_transfer_cmd(&mut cmd, XI3C_CCC_BRDCAST_RSTDAA)?;
        Ok(())
    }

    pub fn cfg_initialize(&mut self, config: &Config, effective_addr: usize) -> Result<(), i32> {
        if self.ready {
            return Err(5);
        }
        self.config.device_id = config.device_id;
        self.config.base_address = effective_addr as *mut u32;
        self.config.input_clock_hz = config.input_clock_hz;
        self.config.rw_fifo_depth = config.rw_fifo_depth;
        self.config.wr_threshold = (config.wr_threshold as i32 * 4) as u8;
        self.config.device_count = config.device_count;
        self.config.ibi_capable = config.ibi_capable;
        self.config.hj_capable = config.hj_capable;
        self.cur_device_count = 0;
        self.ready = true;
        self.reset();
        self.reset_fifos();
        if self.config.ibi_capable {
            self.enable_ibi();
        }
        if self.config.hj_capable {
            self.enable_hotjoin();
        }
        self.enable(1);
        self.bus_init()?;
        if self.config.ibi_capable && self.config.device_count as i32 != 0 {
            self.dyna_addr_assign(&DYNA_ADDR_LIST, self.config.device_count)?;
            self.config_ibi(self.config.device_count);
        }
        if self.config.hj_capable {
            self.regs().intr_re.set(self.regs().intr_re.get() | 0x100);
        }
        Ok(())
    }

    pub fn fill_cmd_fifo(&mut self, cmd: &Command) {
        let dev_addr = ((cmd.target_addr as i32 & 0x7f) << 1 | cmd.rw as i32 & 0x1) as u8;
        let mut transfer_cmd = (cmd.cmd_type as i32 & 0xf) as u32;
        transfer_cmd |= ((cmd.no_repeated_start as i32 & 0x1) as u32) << 4;
        transfer_cmd |= ((cmd.pec as i32 & 0x1) as u32) << 5;
        transfer_cmd |= (dev_addr as u32) << 8;
        transfer_cmd |= ((cmd.byte_count as i32 & 0xfff) as u32) << 16;
        transfer_cmd |= ((cmd.tid as i32 & 0xf) as u32) << 28;
        self.regs().cmd_fifo.set(transfer_cmd);
    }

    pub fn write_tx_fifo(&mut self, send_buffer: &[u8]) -> usize {
        let data = if send_buffer.len() > 3 {
            u32::from_be_bytes(send_buffer[0..4].try_into().unwrap())
        } else {
            let mut data = 0;
            for (i, x) in send_buffer.iter().enumerate() {
                data |= (*x as u32) << (24 - 8 * i);
            }
            data
        };
        self.regs().wr_fifo.set(data);
        send_buffer.len().max(4)
    }

    pub fn read_rx_fifo(&mut self, recv_byte_count: u16) -> Vec<u8> {
        let data = self.regs().rd_fifo.get();
        if recv_byte_count > 3 {
            data.to_be_bytes().to_vec()
        } else {
            data.to_be_bytes()[0..recv_byte_count as usize].to_vec()
        }
    }

    pub fn dyna_addr_assign(&mut self, dyna_addr: &[u8], dev_count: u8) -> Result<(), i32> {
        let mut cmd: Command = Command {
            cmd_type: 0,
            no_repeated_start: 0,
            pec: 0,
            target_addr: 0,
            rw: 0,
            byte_count: 0,
            tid: 0,
        };
        assert!(self.ready);
        cmd.no_repeated_start = 0;
        cmd.target_addr = XI3C_BROADCAST_ADDRESS;
        cmd.tid = 0;
        cmd.pec = 0;
        cmd.cmd_type = 1;
        self.send_transfer_cmd(&mut cmd, 0x7)?;
        let mut index = 0;
        while index < dev_count as u16 && index < 108 {
            let addr = (((dyna_addr[index as usize]) as i32) << 1
                | get_odd_parity(dyna_addr[index as usize]) as i32) as u8;
            self.write_tx_fifo(&[addr]);
            if index + 1 == dev_count as u16 {
                cmd.no_repeated_start = 1;
            } else {
                cmd.no_repeated_start = 0;
            }
            cmd.target_addr = XI3C_BROADCAST_ADDRESS;
            cmd.tid = 0;
            cmd.pec = 0;
            cmd.cmd_type = 1;

            let recv_buffer = self.master_recv_polled(&mut cmd, 9)?;

            self.target_info_table[self.cur_device_count as usize].id = (recv_buffer[0] as u64)
                << 40
                | (recv_buffer[1] as u64) << 32
                | (recv_buffer[2] as u64) << 24
                | (recv_buffer[3] as u64) << 16
                | (recv_buffer[4] as u64) << 8
                | recv_buffer[5] as u64;
            self.target_info_table[self.cur_device_count as usize].bcr = recv_buffer[6];
            self.target_info_table[self.cur_device_count as usize].dcr = recv_buffer[7];
            self.target_info_table[self.cur_device_count as usize].dyna_addr =
                dyna_addr[index as usize];
            self.cur_device_count = (self.cur_device_count).wrapping_add(1);
            index = index.wrapping_add(1);
        }
        Ok(())
    }

    pub fn config_ibi(&mut self, dev_count: u8) {
        assert!(self.ready);
        let mut index = 0;
        while (index as i32) < dev_count as i32 && (index as i32) < 108 {
            self.update_addr_bcr(index);
            index = index.wrapping_add(1);
        }
    }

    #[inline]
    fn enable(&mut self, enable: u8) {
        assert!(self.ready);
        let mut data = self.regs().cr.get();
        data &= !0x1;
        data |= enable as u32;
        self.regs().cr.set(data);
    }

    #[inline]
    fn enable_ibi(&mut self) {
        assert!(self.ready);
        let mut data = self.regs().cr.get();
        data |= 0x8;
        self.regs().cr.set(data);
    }

    #[inline]
    fn enable_hotjoin(&mut self) {
        assert!(self.ready);
        let mut data = self.regs().cr.get();
        data |= 0x10;
        self.regs().cr.set(data);
    }

    #[inline]
    pub fn update_addr_bcr(&mut self, dev_index: u16) {
        assert!(self.ready);
        let mut addr_bcr =
            (self.target_info_table[dev_index as usize].dyna_addr as i32 & 0x7f) as u32;
        addr_bcr |= ((self.target_info_table[dev_index as usize].bcr as i32 & 0xff) as u32) << 8;
        self.regs().target_addr_bcr.set(addr_bcr);
    }

    #[inline]
    pub fn reset(&mut self) {
        assert!(self.ready);
        let mut data = self.regs().reset.get();
        data |= 0x1;
        self.regs().reset.set(data);
        std::thread::sleep(Duration::from_micros(50));
        data &= !0x1;
        self.regs().reset.set(data);
        std::thread::sleep(Duration::from_micros(10));
    }

    #[inline]
    pub fn reset_fifos(&mut self) {
        assert!(self.ready);
        let mut data = self.regs().reset.get();
        data |= 0x1e;
        self.regs().reset.set(data);
        std::thread::sleep(Duration::from_micros(50));
        data &= !0x1e;
        self.regs().reset.set(data);
        std::thread::sleep(Duration::from_micros(10));
    }
}

// Computes the parity, inverted.
#[inline]
fn get_odd_parity(addr: u8) -> u8 {
    addr.count_ones() as u8 & 1 ^ 1
}
