// This code is translated from the Xilinx I3C C driver:
// https://github.com/Xilinx/embeddedsw/tree/master/XilinxProcessorIPLib/drivers/i3c/src
// Which is:
// Copyright (C) 2024 Advanced Micro Devices, Inc. All Rights Reserved
// SPDX-License-Identifier: MIT

#![allow(dead_code)]

use super::xi3c::{Command, Controller, ErrorHandler, DYNA_ADDR_LIST};
use std::time::{Duration, Instant};
use tock_registers::interfaces::{Readable, Writeable};

impl Controller {
    /// Sets I3C Scl clock frequency.
    /// - s_clk_hz is Scl clock to be configured in Hz.
    /// - mode is the mode of operation I2C/I3C.
    pub fn set_s_clk(&mut self, s_clk_hz: u32, mode: u8) {
        assert!(s_clk_hz > 0);
        let t_high = (self.config.input_clock_hz)
            .wrapping_add(s_clk_hz)
            .wrapping_sub(1)
            .wrapping_div(s_clk_hz)
            >> 1;
        let t_low = t_high;
        let mut t_hold = t_low.wrapping_mul(4).wrapping_div(10);
        let core_period_ns = 1_000_000_000_u32
            .wrapping_add(self.config.input_clock_hz)
            .wrapping_sub(1)
            .wrapping_div(self.config.input_clock_hz);
        if (self.regs().version.get() & 0xff00) >> 8 == 0 {
            t_hold = if t_hold < 5 { 5 } else { t_hold };
        } else {
            t_hold = if t_hold < 6 { 6 } else { t_hold };
        }
        self.regs()
            .scl_high_time
            .set(t_high.wrapping_sub(2) & 0x3ffff);
        self.regs()
            .scl_low_time
            .set(t_low.wrapping_sub(2) & 0x3ffff);
        self.regs()
            .sda_hold_time
            .set(t_hold.wrapping_sub(2) & 0x3ffff);
        let tcas_min: u32;
        let mut od_t_high: u32;
        let mut od_t_low: u32;
        if mode == 0 {
            self.regs()
                .od_scl_high_time
                .set(t_high.wrapping_sub(2) & 0x3ffff);
            self.regs()
                .od_scl_low_time
                .set(t_low.wrapping_sub(2) & 0x3ffff);
            tcas_min = 600000_u32
                .wrapping_add(core_period_ns)
                .wrapping_sub(1)
                .wrapping_div(core_period_ns);
        } else {
            od_t_low = 500000_u32
                .wrapping_add(core_period_ns)
                .wrapping_sub(1)
                .wrapping_div(core_period_ns);
            od_t_high = 41000_u32
                .wrapping_add(core_period_ns)
                .wrapping_sub(1)
                .wrapping_div(core_period_ns);
            od_t_low = if t_low < od_t_low { od_t_low } else { t_low };
            od_t_high = if t_high > od_t_high {
                od_t_high
            } else {
                t_high
            };
            self.regs()
                .od_scl_high_time
                .set(od_t_high.wrapping_sub(2) & 0x3ffff);
            self.regs()
                .od_scl_low_time
                .set(od_t_low.wrapping_sub(2) & 0x3ffff);
            tcas_min = 260000_u32
                .wrapping_add(core_period_ns)
                .wrapping_sub(1)
                .wrapping_div(core_period_ns);
        }
        let thd_start = if t_high > tcas_min { t_high } else { tcas_min };
        let tsu_start = if t_low > tcas_min { t_low } else { tcas_min };
        let tsu_stop = if t_low > tcas_min { t_low } else { tcas_min };
        self.regs()
            .tsu_start
            .set(tsu_start.wrapping_sub(2) & 0x3ffff);
        self.regs()
            .thd_start
            .set(thd_start.wrapping_sub(2) & 0x3ffff);
        self.regs().tsu_stop.set(tsu_stop.wrapping_sub(2) & 0x3ffff);
    }

    fn get_response(&mut self) -> i32 {
        let happened = self.wait_for_event(0x10, 0x10, 2000000);
        if !happened {
            println!("Event failed to happen");
            return 31;
        }
        let response_data = self.regs().resp_status_fifo.get();
        ((response_data & 0x1e0) >> 5) as i32
    }

    pub fn send_transfer_cmd(&mut self, cmd: &mut Command, mut data: u8) -> Result<(), i32> {
        assert!(self.ready);

        self.send_buffer_ptr = &mut data;
        self.send_byte_count = 1;
        self.write_tx_fifo();
        cmd.target_addr = 0x7e;
        cmd.rw = 0;
        cmd.byte_count = 1;
        self.fill_cmd_fifo(cmd);
        println!("Send transfer waiting for response");
        if self.get_response() != 0 {
            return Err(28);
        }
        Ok(())
    }

    pub unsafe fn master_send(
        &mut self,
        cmd: &mut Command,
        msg_ptr: *mut u8,
        byte_count: u16,
    ) -> i32 {
        if msg_ptr.is_null() {
            return 13;
        }
        if byte_count > 4095 {
            return 28;
        }
        self.send_buffer_ptr = msg_ptr;
        self.send_byte_count = byte_count;
        (*cmd).byte_count = byte_count;
        (*cmd).rw = 0;
        let wr_fifo_space = (self.regs().fifo_lvl_status.get() & 0xffff) as u16;
        let mut space_index: u16 = 0;
        while space_index < wr_fifo_space && self.send_byte_count > 0 {
            self.write_tx_fifo();
            space_index = space_index.wrapping_add(1);
        }
        if (self.config.wr_threshold as u16) < byte_count {
            self.regs().intr_fe.set(self.regs().intr_fe.get() | 0x20);
        }
        self.regs().intr_re.set(self.regs().intr_re.get() | 0x10);
        self.fill_cmd_fifo(cmd);
        0
    }

    pub unsafe fn master_recv(
        &mut self,
        cmd: &mut Command,
        msg_ptr: *mut u8,
        byte_count: u16,
    ) -> i32 {
        if msg_ptr.is_null() {
            return 13;
        }
        if byte_count > 4095 {
            return 27;
        }
        self.recv_buffer_ptr = msg_ptr;
        self.recv_byte_count = byte_count;
        cmd.byte_count = byte_count;
        cmd.rw = 1;
        self.regs()
            .intr_re
            .set(self.regs().intr_re.get() | 0x40 | 0x10);
        self.fill_cmd_fifo(cmd);
        0
    }

    pub unsafe fn master_send_polled(
        &mut self,
        cmd: &mut Command,
        msg_ptr: *const u8,
        byte_count: u16,
    ) -> Result<(), i32> {
        if msg_ptr.is_null() {
            return Err(13);
        }
        if byte_count > 4095 {
            return Err(28);
        }
        self.send_buffer_ptr = msg_ptr;
        self.send_byte_count = byte_count;
        cmd.byte_count = byte_count;
        cmd.rw = 0;
        self.fill_cmd_fifo(cmd);
        #[allow(clippy::while_immutable_condition)]
        while self.send_byte_count as i32 > 0 {
            let wr_fifo_space = (self.regs().fifo_lvl_status.get() & 0xffff) as u16;
            let mut space_index: u16 = 0;
            while (space_index as i32) < wr_fifo_space as i32 && self.send_byte_count as i32 > 0 {
                self.write_tx_fifo();
                space_index = space_index.wrapping_add(1);
            }
        }
        if self.get_response() != 0 {
            Err(28)
        } else {
            Ok(())
        }
    }

    pub unsafe fn master_recv_polled(
        &mut self,
        cmd: &mut Command,
        msg_ptr: *mut u8,
        byte_count: u16,
    ) -> Result<(), i32> {
        if msg_ptr.is_null() {
            return Err(13);
        }
        if byte_count as i32 > 4095 {
            return Err(27);
        }
        self.recv_buffer_ptr = msg_ptr;
        if cmd.target_addr as i32 == 0x7e {
            self.recv_byte_count = (byte_count as i32 - 1) as u16;
        } else {
            self.recv_byte_count = byte_count;
        }
        cmd.byte_count = byte_count;
        cmd.rw = 1;
        self.fill_cmd_fifo(cmd);
        #[allow(clippy::while_immutable_condition)]
        while self.recv_byte_count as i32 > 0 {
            let rx_data_available = (self.regs().fifo_lvl_status_1.get() & 0xffff) as u16;
            let mut data_index: u16 = 0;
            while (data_index as i32) < rx_data_available as i32 && self.recv_byte_count as i32 > 0
            {
                self.read_rx_fifo();
                data_index = data_index.wrapping_add(1);
            }
        }
        if self.get_response() != 0 {
            Err(27)
        } else {
            Ok(())
        }
    }
    fn ibi_read_rx_fifo(&mut self) {
        let rx_data_available = (self.regs().fifo_lvl_status_1.get() & 0xffff) as u16;
        let mut data_index: u16 = 0;
        while (data_index as i32) < rx_data_available as i32 {
            self.recv_byte_count = 4;
            self.read_rx_fifo();
            data_index = data_index.wrapping_add(1);
        }
    }

    #[allow(dead_code)]
    pub fn set_status_handler(&mut self, handler: Box<dyn ErrorHandler>) {
        assert!(self.ready);
        self.status_handler = Some(handler);
    }

    pub fn master_interrupt_handler(&mut self) -> Result<(), i32> {
        let mut data_index: u16;
        let mut rx_data_available: u16;
        let mut dyna_addr: [u8; 1] = [0; 1];
        let intr_status_reg = self.regs().intr_status.get();
        self.regs().intr_status.set(intr_status_reg);
        if intr_status_reg & 0x100 != 0 {
            if self.cur_device_count as i32 <= 108 {
                dyna_addr[0] = DYNA_ADDR_LIST[self.cur_device_count as usize];
                self.dyna_addr_assign(&dyna_addr, 1)?;
                self.update_addr_bcr((self.cur_device_count as i32 - 1) as u16);
            }
            self.reset_fifos();
        }
        if intr_status_reg & 0x80 != 0 {
            while self.regs().sr.get() & 0x8000 != 0 || self.regs().sr.get() & 0x10 == 0 {
                self.ibi_read_rx_fifo();
            }
            self.regs().intr_re.set(self.regs().intr_re.get() & !0x80);
        }
        if intr_status_reg & 0x20 != 0 {
            let wr_fifo_space = (self.regs().fifo_lvl_status.get() & 0xffff) as u16;
            let mut space_index: u16 = 0;
            while (space_index as i32) < wr_fifo_space as i32 && self.send_byte_count as i32 > 0 {
                self.write_tx_fifo();
                space_index = space_index.wrapping_add(1);
            }
            if self.send_byte_count as i32 <= 0 {
                self.regs().intr_fe.set(self.regs().intr_fe.get() & !0x20);
            }
        }
        if intr_status_reg & 0x40 != 0 {
            rx_data_available = (self.regs().fifo_lvl_status_1.get() & 0xffff) as u16;
            data_index = 0;
            while (data_index as i32) < rx_data_available as i32 && self.recv_byte_count as i32 > 0
            {
                self.read_rx_fifo();
                data_index = data_index.wrapping_add(1);
            }
            if self.recv_byte_count as i32 <= 0 {
                self.regs().intr_re.set(self.regs().intr_re.get() & !0x40);
            }
        }
        if intr_status_reg & 0x10 != 0 {
            if self.recv_byte_count as i32 > 0 {
                rx_data_available = (self.regs().fifo_lvl_status_1.get() & 0xffff) as u16;
                data_index = 0;
                while (data_index as i32) < rx_data_available as i32
                    && self.recv_byte_count as i32 > 0
                {
                    self.read_rx_fifo();
                    data_index = data_index.wrapping_add(1);
                }
            }
            if self.config.ibi_capable {
                self.ibi_read_rx_fifo();
            }
            let response_data = self.regs().resp_status_fifo.get();
            self.error = ((response_data & 0x1e0) >> 5) as u8;
            self.regs()
                .intr_re
                .set(self.regs().intr_re.get() & !(0x10 | 0x40));
            self.regs().intr_fe.set(self.regs().intr_fe.get() & !0x20);
            if let Some(handler) = self.status_handler.as_ref() {
                handler.handle_error(self.error as u32);
            }
        }
        Ok(())
    }

    pub unsafe fn ibi_recv(&mut self, msg_ptr: *mut u8) -> i32 {
        assert!(!msg_ptr.is_null());
        self.recv_buffer_ptr = msg_ptr;
        self.regs()
            .intr_re
            .set(self.regs().intr_re.get() | 0x80 | 0x10);
        0
    }

    pub unsafe fn ibi_recv_polled(&mut self, msg_ptr: *mut u8) -> i32 {
        assert!(!msg_ptr.is_null());
        self.recv_buffer_ptr = msg_ptr;
        let mut data_index: u16;
        let mut rx_data_available: u16;
        let happened = self.wait_for_event(0x8000, 0x8000, 2000000 * 10);
        if happened {
            while self.regs().sr.get() & 0x8000 != 0 || self.regs().sr.get() & 0x10 == 0 {
                rx_data_available = (self.regs().fifo_lvl_status_1.get() & 0xffff) as u16;
                data_index = 0;
                while (data_index as i32) < rx_data_available as i32 {
                    self.recv_byte_count = 4;
                    self.read_rx_fifo();
                    data_index = data_index.wrapping_add(1);
                }
            }
            rx_data_available = (self.regs().fifo_lvl_status_1.get() & 0xffff) as u16;
            data_index = 0;
            while (data_index as i32) < rx_data_available as i32 {
                self.recv_byte_count = 4;
                self.read_rx_fifo();
                data_index = data_index.wrapping_add(1);
            }
        }
        if self.get_response() != 0 {
            27
        } else {
            0
        }
    }

    /// Wait for a specific event to occur in the status register.
    /// Returns true if the event occurred withing the timeout period.
    pub fn wait_for_event(&mut self, event_mask: u32, event: u32, timeout_us: u32) -> bool {
        let start_time = Instant::now();
        let timeout_duration = Duration::from_micros(timeout_us as u64);

        while start_time.elapsed() < timeout_duration {
            let event_status = self.regs().sr.get() & event_mask;
            if event_status == event {
                return true;
            }
            std::thread::sleep(Duration::from_micros(1));
        }
        false
    }
}
