// Licensed under the Apache-2.0 license

//! Host-side MMIO driver for `caliptra_fpga_ulpi_host` (`S_AXI_WRAPPER + 0x4000`,
//! physical address `0xA401_4000`), providing zero-cable internal FPGA ULPI
//! USB3320 PHY emulation + USB 2.0 High-Speed Host transactions ("Architecture B").

use anyhow::{bail, ensure, Result};
use std::time::{Duration, Instant};

pub const ULPI_HOST_WRAPPER_WORD_OFFSET: usize = 0x4000 / 4;
pub const ULPI_HOST_MAGIC: u32 = 0x5553_4248; // "USBH"

const REG_MAGIC: usize = 0x00 / 4;
const REG_CTRL: usize = 0x04 / 4;
const REG_STATUS: usize = 0x08 / 4;
const REG_CMD: usize = 0x0C / 4;
const REG_TIMEOUT: usize = 0x10 / 4;
const REG_DIAG: usize = 0x14 / 4;
const REG_TX_BUF_BASE: usize = 0x40 / 4;
const REG_RX_BUF_BASE: usize = 0x80 / 4;

const CTRL_VBUS_VALID: u32 = 1 << 0;
const CTRL_AUTO_SOF_EN: u32 = 1 << 1;
const CTRL_SOFT_RESET: u32 = 1 << 2;

const OP_BUS_RESET_HS: u32 = 1;
const OP_SETUP: u32 = 2;
const OP_OUT: u32 = 3;
const OP_IN: u32 = 4;

const PID_NIB_ACK: u8 = 0x2;
const PID_NIB_DATA0: u8 = 0x3;
const PID_NIB_NYET: u8 = 0x6;
const PID_NIB_NAK: u8 = 0xA;
const PID_NIB_DATA1: u8 = 0xB;
const PID_NIB_STALL: u8 = 0xE;

#[derive(Clone, Copy, Debug)]
pub struct UlpiHostStatus {
    pub raw: u32,
    pub busy: bool,
    pub done: bool,
    pub timeout_err: bool,
    pub ulpi_init_done: bool,
    pub dev_connected: bool,
    pub hs_active: bool,
    pub recovery_payload_available: bool,
    pub recovery_image_activated: bool,
    pub rx_pid: u8,
    pub rx_len: usize,
    pub ulpi_func_ctrl: u8,
    pub hl_state: u8,
}

impl From<u32> for UlpiHostStatus {
    fn from(raw: u32) -> Self {
        Self {
            raw,
            busy: (raw & (1 << 0)) != 0,
            done: (raw & (1 << 1)) != 0,
            timeout_err: (raw & (1 << 2)) != 0,
            ulpi_init_done: (raw & (1 << 3)) != 0,
            dev_connected: (raw & (1 << 4)) != 0,
            hs_active: (raw & (1 << 5)) != 0,
            recovery_payload_available: (raw & (1 << 6)) != 0,
            recovery_image_activated: (raw & (1 << 7)) != 0,
            rx_pid: ((raw >> 8) & 0xF) as u8,
            rx_len: ((raw >> 12) & 0xFF) as usize,
            ulpi_func_ctrl: ((raw >> 20) & 0xFF) as u8,
            hl_state: ((raw >> 28) & 0xF) as u8,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct UlpiHostDiag {
    pub raw: u32,
    pub sof_count: u16,
    pub ulpi_reg_op_count: u8,
    pub last_ulpi_cmd: u8,
}

impl From<u32> for UlpiHostDiag {
    fn from(raw: u32) -> Self {
        Self {
            raw,
            sof_count: (raw & 0xFFFF) as u16,
            ulpi_reg_op_count: ((raw >> 16) & 0xFF) as u8,
            last_ulpi_cmd: ((raw >> 24) & 0xFF) as u8,
        }
    }
}

#[derive(Clone, Debug)]
pub struct EnumeratedDevice {
    pub address: u8,
    pub vendor_id: u16,
    pub product_id: u16,
    pub bcd_device: u16,
    pub ocp_interface: u8,
    pub device_descriptor: [u8; 18],
    pub config_descriptor: Vec<u8>,
}

pub struct FpgaUlpiUsbHost {
    base: *mut u32,
    device_addr: u8,
    ocp_interface: u8,
    /// Data PID (`PID_NIB_DATA0`/`PID_NIB_DATA1`) of the first DATA packet the
    /// device returned on the most recent control-read DATA stage. USB 2.0
    /// requires DATA1 here; `DATA0` is a device-side toggle anomaly that a strict
    /// host controller would reject. Exposed for triage via
    /// [`Self::last_data_in_pid`].
    last_data_in_pid: std::cell::Cell<u8>,
    /// Count of control-read DATA stages that began with DATA0.
    data0_first_count: std::cell::Cell<u32>,
}

// Safety: `base` points into the process-wide `Wrapper` UIO mapping owned by `ModelFpgaSubsystem`.
unsafe impl Send for FpgaUlpiUsbHost {}

impl FpgaUlpiUsbHost {
    /// Construct from the base `S_AXI_WRAPPER` (`0xA401_0000`) `u32` pointer.
    ///
    /// # Safety
    /// `wrapper_ptr` must point to a valid 64 KiB `uio0 map0` mapping.
    pub unsafe fn from_wrapper_ptr(wrapper_ptr: *mut u32) -> Result<Self> {
        let base = unsafe { wrapper_ptr.add(ULPI_HOST_WRAPPER_WORD_OFFSET) };
        let host = Self {
            base,
            device_addr: 0,
            ocp_interface: 0,
            last_data_in_pid: std::cell::Cell::new(0),
            data0_first_count: std::cell::Cell::new(0),
        };
        let magic = host.magic();
        ensure!(
            magic == ULPI_HOST_MAGIC,
            "caliptra_fpga_ulpi_host magic mismatch at S_AXI_WRAPPER+0x4000: got 0x{magic:08x}, expected 0x{ULPI_HOST_MAGIC:08x}"
        );
        Ok(host)
    }

    #[inline]
    fn read_reg(&self, word_idx: usize) -> u32 {
        unsafe { self.base.add(word_idx).read_volatile() }
    }

    #[inline]
    fn write_reg(&self, word_idx: usize, val: u32) {
        unsafe { self.base.add(word_idx).write_volatile(val) }
    }

    pub fn magic(&self) -> u32 {
        self.read_reg(REG_MAGIC)
    }

    pub fn status(&self) -> UlpiHostStatus {
        UlpiHostStatus::from(self.read_reg(REG_STATUS))
    }

    pub fn diag(&self) -> UlpiHostDiag {
        UlpiHostDiag::from(self.read_reg(REG_DIAG))
    }

    pub fn device_address(&self) -> u8 {
        self.device_addr
    }

    /// PID nibble of the first DATA packet of the last control-read DATA stage
    /// (`0x3` = DATA0, `0xB` = DATA1).
    pub fn last_data_in_pid(&self) -> u8 {
        self.last_data_in_pid.get()
    }

    /// Number of control reads whose DATA stage started with DATA0 (spec
    /// violation; see `last_data_in_pid`).
    pub fn data0_first_count(&self) -> u32 {
        self.data0_first_count.get()
    }

    pub fn ocp_interface(&self) -> u8 {
        self.ocp_interface
    }

    pub fn soft_reset(&mut self) {
        self.device_addr = 0;
        self.ocp_interface = 0;
        self.write_reg(REG_CTRL, CTRL_VBUS_VALID | CTRL_SOFT_RESET);
        std::thread::sleep(Duration::from_micros(10));
        self.write_reg(REG_CTRL, CTRL_VBUS_VALID);
        self.write_reg(REG_TIMEOUT, 200_000);
    }

    fn write_tx_buf(&self, data: &[u8]) {
        assert!(data.len() <= 64);
        for (idx, chunk) in data.chunks(4).enumerate() {
            let mut word = [0u8; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            self.write_reg(REG_TX_BUF_BASE + idx, u32::from_le_bytes(word));
        }
    }

    fn read_rx_buf(&self, out: &mut [u8], len: usize) {
        let n = len.min(out.len()).min(64);
        for idx in 0..n.div_ceil(4) {
            let bytes = self.read_reg(REG_RX_BUF_BASE + idx).to_le_bytes();
            let dst_start = idx * 4;
            let copy_len = (n - dst_start).min(4);
            out[dst_start..dst_start + copy_len].copy_from_slice(&bytes[..copy_len]);
        }
    }

    fn make_cmd(op: u32, toggle: bool, addr: u8, endp: u8, tx_len: usize) -> u32 {
        (op & 0x7)
            | (u32::from(toggle) << 3)
            | (u32::from(addr & 0x7F) << 8)
            | (u32::from(endp & 0x0F) << 16)
            | (((tx_len.min(64)) as u32) << 20)
    }

    fn exec_cmd(&self, cmd: u32, timeout: Duration) -> Result<UlpiHostStatus> {
        let start = Instant::now();
        while self.status().busy {
            if start.elapsed() > timeout {
                bail!(
                    "ULPI host busy before command 0x{cmd:08x}: {:?}",
                    self.status()
                );
            }
            std::hint::spin_loop();
        }
        self.write_reg(REG_CMD, cmd);
        loop {
            let st = self.status();
            if !st.busy && st.done {
                return Ok(st);
            }
            if start.elapsed() > timeout {
                bail!(
                    "ULPI host command 0x{cmd:08x} timed out: status={:?}, diag={:?}",
                    st,
                    self.diag()
                );
            }
            std::hint::spin_loop();
        }
    }

    /// Perform USB 2.0 High-Speed Bus Reset + K-J-K-J-K-J Chirp negotiation and
    /// enable hardware Auto-SOF microframe keepalive.
    pub fn bus_reset_high_speed<F: FnMut()>(&mut self, mut step_fn: F) -> Result<()> {
        self.device_addr = 0;
        self.write_reg(REG_CTRL, CTRL_VBUS_VALID);
        let st = self.exec_cmd(
            Self::make_cmd(OP_BUS_RESET_HS, false, 0, 0, 0),
            Duration::from_secs(1),
        )?;
        ensure!(
            !st.timeout_err && st.hs_active,
            "High-Speed Bus Reset / Chirp failed: status={:?}, diag={:?}",
            st,
            self.diag()
        );
        self.write_reg(REG_CTRL, CTRL_VBUS_VALID | CTRL_AUTO_SOF_EN);
        // Allow MCU ROM LpcipUsbDriver::poll() to service DresC (~1 ms).
        // The ULPI host now runs on the 60 MHz PHY clock and drives spec-timed
        // Auto-SOF microframes (125 us) itself, so this is purely a software
        // settle delay for the MCU side.
        let wait_start = Instant::now();
        while wait_start.elapsed() < Duration::from_millis(2) {
            step_fn();
            std::thread::sleep(Duration::from_micros(100));
        }
        Ok(())
    }

    fn exec_setup<F: FnMut()>(
        &self,
        addr: u8,
        setup: &[u8; 8],
        step_fn: &mut F,
        deadline: Instant,
    ) -> Result<()> {
        self.write_tx_buf(setup);
        loop {
            let rem = deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or_else(|| anyhow::anyhow!("SETUP stage timeout at addr={addr}"))?;
            let st = self.exec_cmd(Self::make_cmd(OP_SETUP, false, addr, 0, 8), rem)?;
            if !st.timeout_err && st.rx_pid == PID_NIB_ACK {
                return Ok(());
            }
            step_fn();
            std::thread::sleep(Duration::from_micros(50));
        }
    }

    pub fn control_read_raw<F: FnMut()>(
        &self,
        addr: u8,
        bm_request_type: u8,
        b_request: u8,
        w_value: u16,
        w_index: u16,
        w_length: u16,
        out: &mut [u8],
        mut step_fn: F,
        timeout: Duration,
    ) -> Result<usize> {
        ensure!(
            (bm_request_type & 0x80) != 0,
            "control_read_raw requires Device-to-Host bmRequestType (got 0x{bm_request_type:02x})"
        );
        ensure!(
            usize::from(w_length) <= out.len() && w_length <= 64,
            "control_read_raw w_length={w_length} exceeds single-packet buffer (len={})",
            out.len()
        );
        let deadline = Instant::now() + timeout;
        let setup = [
            bm_request_type,
            b_request,
            (w_value & 0xFF) as u8,
            (w_value >> 8) as u8,
            (w_index & 0xFF) as u8,
            (w_index >> 8) as u8,
            (w_length & 0xFF) as u8,
            (w_length >> 8) as u8,
        ];
        self.exec_setup(addr, &setup, &mut step_fn, deadline)?;

        // DATA IN stage
        let rx_len = loop {
            let rem = deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Control Read DATA IN timeout (req=0x{bm_request_type:02x}/0x{b_request:02x} val=0x{w_value:04x})"
                    )
                })?;
            let st = self.exec_cmd(Self::make_cmd(OP_IN, true, addr, 0, 0), rem)?;
            if !st.timeout_err {
                match st.rx_pid {
                    PID_NIB_DATA1 | PID_NIB_DATA0 => {
                        self.last_data_in_pid.set(st.rx_pid);
                        if st.rx_pid == PID_NIB_DATA0 {
                            self.data0_first_count
                                .set(self.data0_first_count.get().wrapping_add(1));
                        }
                        self.read_rx_buf(out, st.rx_len);
                        break st.rx_len;
                    }
                    PID_NIB_NAK => {
                        step_fn();
                        std::thread::sleep(Duration::from_micros(20));
                    }
                    PID_NIB_STALL => {
                        bail!(
                            "Control Read DATA IN STALL (req=0x{bm_request_type:02x}/0x{b_request:02x} val=0x{w_value:04x})"
                        );
                    }
                    other => {
                        bail!("Unexpected PID 0x{other:x} on Control Read DATA IN: {st:?}");
                    }
                }
            } else {
                step_fn();
                std::thread::sleep(Duration::from_micros(50));
            }
        };

        // STATUS OUT ZLP stage (DATA1)
        loop {
            let rem = deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or_else(|| anyhow::anyhow!("Control Read STATUS OUT timeout"))?;
            let st = self.exec_cmd(Self::make_cmd(OP_OUT, true, addr, 0, 0), rem)?;
            if !st.timeout_err {
                match st.rx_pid {
                    PID_NIB_ACK | PID_NIB_NYET => return Ok(rx_len),
                    PID_NIB_NAK => {
                        step_fn();
                        std::thread::sleep(Duration::from_micros(20));
                    }
                    PID_NIB_STALL => bail!("Control Read STATUS OUT STALL"),
                    other => bail!("Unexpected PID 0x{other:x} on STATUS OUT: {st:?}"),
                }
            } else {
                step_fn();
                std::thread::sleep(Duration::from_micros(50));
            }
        }
    }

    pub fn control_write_raw<F: FnMut()>(
        &self,
        addr: u8,
        bm_request_type: u8,
        b_request: u8,
        w_value: u16,
        w_index: u16,
        data: &[u8],
        mut step_fn: F,
        timeout: Duration,
    ) -> Result<()> {
        ensure!(
            (bm_request_type & 0x80) == 0,
            "control_write_raw requires Host-to-Device bmRequestType (got 0x{bm_request_type:02x})"
        );
        ensure!(
            data.len() <= 64,
            "control_write_raw payload len={} exceeds 64 bytes",
            data.len()
        );
        let deadline = Instant::now() + timeout;
        let w_length = data.len() as u16;
        let setup = [
            bm_request_type,
            b_request,
            (w_value & 0xFF) as u8,
            (w_value >> 8) as u8,
            (w_index & 0xFF) as u8,
            (w_index >> 8) as u8,
            (w_length & 0xFF) as u8,
            (w_length >> 8) as u8,
        ];
        self.exec_setup(addr, &setup, &mut step_fn, deadline)?;

        // Optional DATA OUT stage (DATA1)
        if !data.is_empty() {
            self.write_tx_buf(data);
            loop {
                let rem = deadline
                    .checked_duration_since(Instant::now())
                    .filter(|d| !d.is_zero())
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "Control Write DATA OUT timeout (req=0x{bm_request_type:02x}/0x{b_request:02x} val=0x{w_value:04x})"
                        )
                    })?;
                let st = self.exec_cmd(Self::make_cmd(OP_OUT, true, addr, 0, data.len()), rem)?;
                if !st.timeout_err {
                    match st.rx_pid {
                        PID_NIB_ACK | PID_NIB_NYET => break,
                        PID_NIB_NAK => {
                            step_fn();
                            std::thread::sleep(Duration::from_micros(20));
                        }
                        PID_NIB_STALL => {
                            bail!(
                                "Control Write DATA OUT STALL (req=0x{bm_request_type:02x}/0x{b_request:02x} val=0x{w_value:04x})"
                            );
                        }
                        other => {
                            bail!("Unexpected PID 0x{other:x} on Control Write DATA OUT: {st:?}");
                        }
                    }
                } else {
                    bail!(
                        "Ambiguous timeout on Control Write DATA OUT (val=0x{w_value:04x}): {st:?}"
                    );
                }
            }
        }

        // STATUS IN ZLP stage (DATA1)
        loop {
            let rem = deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or_else(|| anyhow::anyhow!("Control Write STATUS IN timeout"))?;
            let st = self.exec_cmd(Self::make_cmd(OP_IN, true, addr, 0, 0), rem)?;
            if !st.timeout_err {
                match st.rx_pid {
                    PID_NIB_DATA1 | PID_NIB_DATA0 => {
                        ensure!(
                            st.rx_len == 0,
                            "Expected 0-byte ZLP in STATUS IN, got {} bytes",
                            st.rx_len
                        );
                        return Ok(());
                    }
                    PID_NIB_NAK => {
                        step_fn();
                        std::thread::sleep(Duration::from_micros(20));
                    }
                    PID_NIB_STALL => {
                        bail!(
                            "Control Write STATUS IN STALL (req=0x{bm_request_type:02x}/0x{b_request:02x} val=0x{w_value:04x})"
                        );
                    }
                    other => bail!("Unexpected PID 0x{other:x} on STATUS IN: {st:?}"),
                }
            } else {
                step_fn();
                std::thread::sleep(Duration::from_micros(50));
            }
        }
    }

    /// Wait for MCU ROM to assert DCON on Device 0, negotiate High-Speed (480 Mbps)
    /// via Chirp K/J, and run full USB 2.0 Chapter 9 + OCP Recovery interface enumeration.
    pub fn wait_and_enumerate<F: FnMut()>(
        &mut self,
        assigned_addr: u8,
        mut step_fn: F,
        timeout: Duration,
    ) -> Result<EnumeratedDevice> {
        ensure!(
            (1..=127).contains(&assigned_addr),
            "invalid USB address {assigned_addr}"
        );
        // Ensure VBUS is asserted (e.g. if `caliptra_fpga_hcd` `cfhcd_stop()`
        // cleared `CTRL` on module unload prior to this test).
        self.write_reg(REG_CTRL, CTRL_VBUS_VALID);
        self.write_reg(REG_TIMEOUT, 200_000);
        let start = Instant::now();
        while !self.status().dev_connected {
            step_fn();
            if start.elapsed() > timeout {
                bail!(
                    "Timed out waiting for Caliptra USB Device 0 DCON: status={:?}, diag={:?}",
                    self.status(),
                    self.diag()
                );
            }
            std::thread::sleep(Duration::from_millis(1));
        }

        self.bus_reset_high_speed(&mut step_fn)?;

        // 1. GET_DESCRIPTOR(Device, 18 bytes) at address 0
        let mut dev_desc = [0u8; 18];
        let n = self.control_read_raw(
            0,
            0x80,
            6,
            0x0100,
            0,
            18,
            &mut dev_desc,
            &mut step_fn,
            Duration::from_secs(2),
        )?;
        ensure!(
            n == 18 && dev_desc[0] == 18 && dev_desc[1] == 1,
            "Invalid Device Descriptor (len={n}): {dev_desc:02x?}"
        );
        ensure!(
            dev_desc[7] == 64,
            "Expected EP0 bMaxPacketSize0=64, got {}",
            dev_desc[7]
        );
        let vendor_id = u16::from_le_bytes([dev_desc[8], dev_desc[9]]);
        let product_id = u16::from_le_bytes([dev_desc[10], dev_desc[11]]);
        let bcd_device = u16::from_le_bytes([dev_desc[12], dev_desc[13]]);

        // 2. SET_ADDRESS(assigned_addr) at address 0
        self.control_write_raw(
            0,
            0x00,
            5,
            u16::from(assigned_addr),
            0,
            &[],
            &mut step_fn,
            Duration::from_secs(2),
        )?;
        // USB 2.0 Sec 9.2.6.3 SetAddress recovery interval (2 ms) so MCU ROM commits DevAddr
        let settle = Instant::now();
        while settle.elapsed() < Duration::from_millis(2) {
            step_fn();
            std::thread::sleep(Duration::from_micros(100));
        }
        self.device_addr = assigned_addr;

        // 3. GET_DESCRIPTOR(Configuration, 64 bytes) at assigned_addr
        let mut cfg_buf = [0u8; 64];
        let cfg_len = self.control_read_raw(
            assigned_addr,
            0x80,
            6,
            0x0200,
            0,
            64,
            &mut cfg_buf,
            &mut step_fn,
            Duration::from_secs(2),
        )?;
        ensure!(
            cfg_len >= 18 && cfg_buf[1] == 2,
            "Invalid Configuration Descriptor (len={cfg_len}): {:02x?}",
            &cfg_buf[..cfg_len]
        );
        let total_len = usize::from(u16::from_le_bytes([cfg_buf[2], cfg_buf[3]]));
        ensure!(
            total_len == cfg_len,
            "wTotalLength={total_len} mismatch with returned {cfg_len}"
        );
        let ocp_interface = parse_ocp_interface(&cfg_buf[..cfg_len])?;

        // 4. Verify High-Speed DeviceQualifier descriptor (type 6, 10 bytes)
        let mut qual_buf = [0u8; 10];
        let qual_len = self.control_read_raw(
            assigned_addr,
            0x80,
            6,
            0x0600,
            0,
            10,
            &mut qual_buf,
            &mut step_fn,
            Duration::from_secs(2),
        )?;
        ensure!(
            qual_len == 10 && qual_buf[1] == 6,
            "Invalid DeviceQualifier descriptor: {:02x?}",
            &qual_buf[..qual_len]
        );

        // 5. SET_CONFIGURATION(1)
        // Note: `test-lpcip-usb-enumeration` calls `test_exit(0)` immediately after
        // servicing `SET_CONFIGURATION(1)`, so `wait_and_enumerate` stops right after
        // `SET_CONFIGURATION(1)`'s STATUS IN handshake completes.
        self.control_write_raw(
            assigned_addr,
            0x00,
            9,
            1,
            0,
            &[],
            &mut step_fn,
            Duration::from_secs(2),
        )?;

        self.ocp_interface = ocp_interface;
        Ok(EnumeratedDevice {
            address: assigned_addr,
            vendor_id,
            product_id,
            bcd_device,
            ocp_interface,
            device_descriptor: dev_desc,
            config_descriptor: cfg_buf[..cfg_len].to_vec(),
        })
    }
}

fn parse_ocp_interface(config: &[u8]) -> Result<u8> {
    let mut offset = 0usize;
    let mut current_ifc: Option<u8> = None;
    let mut found_ocp_ifc: Option<u8> = None;
    let mut found_functional = false;

    while offset < config.len() {
        let len = usize::from(config[offset]);
        ensure!(
            len >= 2 && offset + len <= config.len(),
            "Malformed descriptor in configuration tree at offset {offset}"
        );
        let dtype = config[offset + 1];
        let desc = &config[offset..offset + len];
        if dtype == 4 && len >= 9 {
            // Interface descriptor
            let ifc_num = desc[2];
            let alt = desc[3];
            let class = desc[5];
            let subclass = desc[6];
            let protocol = desc[7];
            if class == 0xEF && subclass == 0x08 && protocol == 0x01 && alt == 0 {
                current_ifc = Some(ifc_num);
                found_ocp_ifc = Some(ifc_num);
            } else {
                current_ifc = None;
            }
        } else if dtype == 0x24 && current_ifc.is_some() {
            ensure!(
                len == 10
                    && desc[2] == 1
                    && desc[3] == 0
                    && u16::from_le_bytes([desc[4], desc[5]]) >= 64
                    && u16::from_le_bytes([desc[6], desc[7]]) >= 64
                    && desc[8..10] == [1, 1],
                "Invalid OCP functional descriptor: {desc:02x?}"
            );
            found_functional = true;
        }
        offset += len;
    }

    match (found_ocp_ifc, found_functional) {
        (Some(ifc), true) => Ok(ifc),
        _ => bail!("No valid OCP Recovery interface (EF/08/01 + functional 0x24) found in {config:02x?}"),
    }
}
