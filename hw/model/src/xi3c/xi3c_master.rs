// This code is translated from the Xilinx I3C C driver:
// https://github.com/Xilinx/embeddedsw/tree/master/XilinxProcessorIPLib/drivers/i3c/src
// Which is:
// Copyright (C) 2024 Advanced Micro Devices, Inc. All Rights Reserved
// SPDX-License-Identifier: MIT

#![allow(dead_code)]

use crate::xi3c::xi3c::{XI3C_BROADCAST_ADDRESS, XST_SEND_ERROR};

use super::xi3c::{
    Command, Controller, ErrorHandler, DYNA_ADDR_LIST, MAX_TIMEOUT_US, XI3C_INTR_HJ_MASK,
    XI3C_INTR_IBI_MASK, XI3C_INTR_WR_FIFO_ALMOST_FULL_MASK, XI3C_SR_RD_FIFO_NOT_EMPTY_MASK,
    XI3C_SR_RESP_NOT_EMPTY_MASK, XST_NO_DATA, XST_RECV_ERROR,
};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tock_registers::interfaces::{Readable, Writeable};

impl Controller {
    /// Sets I3C Scl clock frequency.
    /// - s_clk_hz is Scl clock to be configured in Hz.
    /// - mode is the mode of operation I2C/I3C.
    pub fn set_s_clk(&mut self, input_clock_hz: u32, s_clk_hz: u32, mode: u8) {
        assert!(s_clk_hz > 0);
        let t_high = input_clock_hz
            .wrapping_add(s_clk_hz)
            .wrapping_sub(1)
            .wrapping_div(s_clk_hz)
            >> 1;
        let t_low = t_high;
        let mut t_hold = t_low.wrapping_mul(4).wrapping_div(10);
        let core_period_ns = 1_000_000_000_u32
            .wrapping_add(input_clock_hz)
            .wrapping_sub(1)
            .wrapping_div(input_clock_hz);
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
            od_t_low = 500_u32
                .wrapping_add(core_period_ns)
                .wrapping_sub(1)
                .wrapping_div(core_period_ns);
            od_t_high = 41_u32
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
        let happened = self.wait_for_event(
            XI3C_SR_RESP_NOT_EMPTY_MASK,
            XI3C_SR_RESP_NOT_EMPTY_MASK,
            MAX_TIMEOUT_US,
        );
        if !happened {
            return 31;
        }
        let response_data = self.regs().resp_status_fifo.get();
        ((response_data & 0x1e0) >> 5) as i32
    }

    pub fn send_transfer_cmd(&mut self, cmd: &mut Command, data: u8) -> Result<(), i32> {
        assert!(self.ready);

        self.write_tx_fifo(&[data]);
        cmd.target_addr = XI3C_BROADCAST_ADDRESS;
        cmd.rw = 0;
        cmd.byte_count = 1;
        self.fill_cmd_fifo(cmd);
        if self.get_response() != 0 {
            return Err(XST_SEND_ERROR);
        }
        Ok(())
    }

    pub fn master_send(&mut self, cmd: &mut Command, mut msg_ptr: &[u8], byte_count: u16) -> i32 {
        if msg_ptr.is_empty() {
            return 13;
        }
        if byte_count > 4095 {
            return 28;
        }
        msg_ptr = &msg_ptr[..byte_count as usize];
        cmd.byte_count = byte_count;
        cmd.rw = 0;
        let wr_fifo_space = (self.regs().fifo_lvl_status.get() & 0xffff) as u16;
        let mut space_index: u16 = 0;
        while space_index < wr_fifo_space && !msg_ptr.is_empty() {
            let size = self.write_tx_fifo(msg_ptr);
            msg_ptr = &msg_ptr[size..];
            space_index += 1;
        }
        if (self.config.wr_threshold as u16) < byte_count {
            self.regs().intr_fe.set(self.regs().intr_fe.get() | 0x20);
        }
        self.regs().intr_re.set(self.regs().intr_re.get() | 0x10);
        self.fill_cmd_fifo(cmd);
        0
    }

    /// This function initiates a polled mode send in master mode.
    ///
    /// It sends data to the FIFO and waits for the slave to pick them up.
    /// If controller fails to send data due arbitration lost or any other error,
    /// will stop transfer status.
    /// - msg_ptr is the pointer to the send buffer.
    /// - byte_count is the number of bytes to be sent.
    pub fn master_send_polled(
        &mut self,
        cmd: &mut Command,
        mut msg_ptr: &[u8],
        byte_count: u16,
    ) -> Result<(), i32> {
        if msg_ptr.is_empty() {
            return Err(XST_NO_DATA);
        }
        if byte_count > 4095 {
            return Err(XST_SEND_ERROR);
        }
        msg_ptr = &msg_ptr[..byte_count as usize];
        cmd.byte_count = byte_count;
        cmd.rw = 0;
        self.fill_cmd_fifo(cmd);
        while !msg_ptr.is_empty() {
            let wr_fifo_space = (self.regs().fifo_lvl_status.get() & 0xffff) as u16;
            let mut space_index: u16 = 0;
            while space_index < wr_fifo_space && !msg_ptr.is_empty() {
                let written = self.write_tx_fifo(msg_ptr);
                msg_ptr = &msg_ptr[written..];
                space_index += 1;
            }
        }
        println!("Waiting for master_send_polled response");
        if self.get_response() != 0 {
            Err(XST_SEND_ERROR)
        } else {
            println!("master_send_polled OK");
            Ok(())
        }
    }

    pub fn master_recv_polled(
        &mut self,
        running: Option<Arc<AtomicBool>>,
        cmd: &mut Command,
        byte_count: u16,
    ) -> Result<Vec<u8>, i32> {
        self.master_recv(cmd, byte_count)?;
        self.master_recv_finish(running, cmd, byte_count)
    }

    /// Starts a receive from a target, but does not wait on the result (must call .master_recv_finish() separately).
    pub fn master_recv(&mut self, cmd: &mut Command, byte_count: u16) -> Result<(), i32> {
        if byte_count > 4095 {
            return Err(XST_RECV_ERROR);
        }
        cmd.byte_count = byte_count;
        cmd.rw = 1;
        self.fill_cmd_fifo(cmd);
        Ok(())
    }

    /// Receives up to 4 bytes from the read FIFO.
    /// Could return fewer. 0 bytes are returned if no data is available.
    pub fn master_recv_4_bytes(&mut self) -> Vec<u8> {
        let rx_data_available = (self.regs().fifo_lvl_status_1.get() & 0xffff) as u16;
        if rx_data_available > 0 {
            self.read_rx_fifo(rx_data_available.min(4))
        } else {
            vec![]
        }
    }

    /// Finishes a receive from a target.
    pub fn master_recv_finish(
        &mut self,
        running: Option<Arc<AtomicBool>>,
        cmd: &Command,
        byte_count: u16,
    ) -> Result<Vec<u8>, i32> {
        let mut recv_byte_count = if cmd.target_addr == XI3C_BROADCAST_ADDRESS {
            (byte_count as i32 - 1) as u16
        } else {
            byte_count
        };
        let mut recv = vec![];
        let running = running.unwrap_or_else(|| Arc::new(AtomicBool::new(true)));
        while running.load(Ordering::Relaxed) && recv_byte_count > 0 {
            let rx_data_available = (self.regs().fifo_lvl_status_1.get() & 0xffff) as u16;
            let mut data_index: u16 = 0;
            while data_index < rx_data_available && recv_byte_count > 0 {
                let new_bytes = self.read_rx_fifo(recv_byte_count);
                recv.extend(&new_bytes);
                recv_byte_count = recv_byte_count.saturating_sub(new_bytes.len() as u16);
                data_index += 1;
            }
        }
        if self.get_response() != 0 {
            Err(XST_RECV_ERROR)
        } else {
            Ok(recv)
        }
    }

    fn ibi_read_rx_fifo(&mut self) -> Vec<u8> {
        let rx_data_available = (self.regs().fifo_lvl_status_1.get() & 0xffff) as u16;
        let mut data_index: u16 = 0;
        let mut recv = vec![];
        while data_index < rx_data_available {
            recv.extend(self.read_rx_fifo(4));
            data_index += 1;
        }
        recv
    }

    #[allow(dead_code)]
    pub fn set_status_handler(&mut self, handler: Box<dyn ErrorHandler>) {
        assert!(self.ready);
        self.status_handler = Some(handler);
    }

    pub fn master_interrupt_handler(&mut self) -> Result<(), i32> {
        let mut dyna_addr: [u8; 1] = [0; 1];
        let intr_status_reg = self.regs().intr_status.get();
        self.regs().intr_status.set(intr_status_reg);
        if intr_status_reg & XI3C_INTR_HJ_MASK != 0 {
            if self.cur_device_count as i32 <= 108 {
                dyna_addr[0] = DYNA_ADDR_LIST[self.cur_device_count as usize];
                self.dyna_addr_assign(&dyna_addr, 1)?;
                self.update_addr_bcr((self.cur_device_count as i32 - 1) as u16);
            }
            self.reset_fifos();
        }
        if intr_status_reg & XI3C_INTR_IBI_MASK != 0 {
            while self.regs().sr.get() & XI3C_SR_RD_FIFO_NOT_EMPTY_MASK != 0
                || self.regs().sr.get() & XI3C_SR_RESP_NOT_EMPTY_MASK == 0
            {
                self.ibi_read_rx_fifo();
            }
            self.regs()
                .intr_re
                .set(self.regs().intr_re.get() & !XI3C_INTR_IBI_MASK);
        }
        if intr_status_reg & XI3C_INTR_WR_FIFO_ALMOST_FULL_MASK != 0 {
            // We don't support buffering data locally.
            // let wr_fifo_space = (self.regs().fifo_lvl_status.get() & 0xffff) as u16;
            // let mut space_index: u16 = 0;
            // while (space_index as i32) < wr_fifo_space as i32 && self.send_byte_count as i32 > 0 {
            //     self.write_tx_fifo();
            //     space_index = space_index.wrapping_add(1);
            // }
            // if self.send_byte_count as i32 <= 0 {
            self.regs()
                .intr_fe
                .set(self.regs().intr_fe.get() & !XI3C_INTR_WR_FIFO_ALMOST_FULL_MASK);
            // }
        }
        // No FIFO interrupts.
        // if intr_status_reg & XI3C_INTR_RD_FULL_MASK != 0 {
        //     rx_data_available = (self.regs().fifo_lvl_status_1.get() & 0xffff) as u16;
        //     data_index = 0;
        //     while (data_index as i32) < rx_data_available as i32 && self.recv_byte_count as i32 > 0
        //     {
        //         self.read_rx_fifo();
        //         data_index = data_index.wrapping_add(1);
        //     }
        //     if self.recv_byte_count as i32 <= 0 {
        //         self.regs().intr_re.set(self.regs().intr_re.get() & !0x40);
        //     }
        // }
        // if intr_status_reg & XI3C_INTR_RESP_NOT_EMPTY_MASK != 0 {
        //     if self.recv_byte_count as i32 > 0 {
        //         rx_data_available = (self.regs().fifo_lvl_status_1.get() & 0xffff) as u16;
        //         data_index = 0;
        //         while (data_index as i32) < rx_data_available as i32
        //             && self.recv_byte_count as i32 > 0
        //         {
        //             self.read_rx_fifo();
        //             data_index = data_index.wrapping_add(1);
        //         }
        //     }
        //     if self.config.ibi_capable {
        //         self.ibi_read_rx_fifo();
        //     }
        //     let response_data = self.regs().resp_status_fifo.get();
        //     self.error = ((response_data & 0x1e0) >> 5) as u8;
        //     self.regs()
        //         .intr_re
        //         .set(self.regs().intr_re.get() & !(0x10 | 0x40));
        //     self.regs().intr_fe.set(self.regs().intr_fe.get() & !0x20);
        //     if let Some(handler) = self.status_handler.as_ref() {
        //         handler.handle_error(self.error as u32);
        //     }
        // }
        Ok(())
    }

    pub fn ibi_recv_polled(&mut self) -> Result<Vec<u8>, i32> {
        let mut recv = vec![];
        let mut data_index: u16;
        let mut rx_data_available: u16;
        let happened = self.wait_for_event(
            XI3C_SR_RD_FIFO_NOT_EMPTY_MASK,
            XI3C_SR_RD_FIFO_NOT_EMPTY_MASK,
            MAX_TIMEOUT_US * 10,
        );
        if happened {
            while self.regs().sr.get() & XI3C_SR_RD_FIFO_NOT_EMPTY_MASK != 0
                || self.regs().sr.get() & XI3C_SR_RESP_NOT_EMPTY_MASK == 0
            {
                rx_data_available = (self.regs().fifo_lvl_status_1.get() & 0xffff) as u16;
                data_index = 0;
                while data_index < rx_data_available {
                    recv.extend(self.read_rx_fifo(4));
                    data_index += 1;
                }
            }
            rx_data_available = (self.regs().fifo_lvl_status_1.get() & 0xffff) as u16;
            data_index = 0;
            while data_index < rx_data_available {
                recv.extend(self.read_rx_fifo(4));
                data_index += 1;
            }
        }
        if self.get_response() != 0 {
            Err(XST_RECV_ERROR)
        } else {
            Ok(recv)
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
