/*++
Licensed under the Apache-2.0 license.
File Name:
    i3c.rs
Abstract:
    File contains I3C peripheral implementation.
--*/

use crate::i3c_protocol::{I3cController, I3cTarget, I3cTcriResponseXfer, ResponseDescriptor};
use crate::{DynamicI3cAddress, I3cIncomingCommandClient, IbiDescriptor, ReguDataTransferCommand};
use caliptra_emu_bus::{Clock, ReadWriteRegister, Timer};
use caliptra_emu_bus::{Device, Event, EventData};
use caliptra_emu_cpu::Irq;
use caliptra_emu_types::RvData;
use emulator_registers_generated::i3c::I3cPeripheral;
use registers_generated::i3c::bits::{
    DeviceStatus0, ExtcapHeader, IndirectFifoCtrl0, IndirectFifoStatus0, InterruptEnable,
    InterruptStatus, RecIntfCfg, StbyCrCapabilities, StbyCrDeviceAddr, TtiQueueSize,
};
use std::collections::VecDeque;
use std::sync::mpsc;
use std::sync::Arc;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use zerocopy::FromBytes;

const I3C_REC_INT_BYPASS_I3C_CORE: u32 = 0x0;
const I3C_REC_INT_BYPASS_AXI_DIRECT: u32 = 0x1;
struct PollScheduler {
    timer: Timer,
}

impl I3cIncomingCommandClient for PollScheduler {
    fn incoming(&self) {
        // trigger interrupt check next tick
        self.timer.schedule_poll_in(1);
    }
}

pub struct I3c {
    /// Timer
    timer: Timer,
    /// I3C target abstraction
    i3c_target: I3cTarget,
    /// RX Command in u32
    tti_rx_desc_queue_raw: VecDeque<u32>,
    /// RX DATA in u8
    tti_rx_data_raw: VecDeque<Vec<u8>>,
    /// RX DATA currently being read from driver
    tti_rx_current: VecDeque<u8>,
    /// TX Command in u32
    tti_tx_desc_queue_raw: VecDeque<u32>,
    /// TX DATA in u8
    tti_tx_data_raw: VecDeque<Vec<u8>>,
    /// IBI buffer
    tti_ibi_buffer: Vec<u8>,
    /// Error interrupt
    _error_irq: Irq,
    /// Notification interrupt
    notif_irq: Irq,

    i3c_ec_sec_fw_recovery_if_prot_cap_2: ReadWriteRegister<u32>,
    i3c_ec_sec_fw_recovery_if_device_status_0:
        ReadWriteRegister<u32, registers_generated::i3c::bits::DeviceStatus0::Register>,
    i3c_ec_sec_fw_recovery_if_recovery_status: ReadWriteRegister<u32>,
    i3c_ec_sec_fw_recovery_if_indirect_fifo_ctrl_0:
        ReadWriteRegister<u32, registers_generated::i3c::bits::IndirectFifoCtrl0::Register>,
    i3c_ec_sec_fw_recovery_if_indirect_fifo_ctrl_1: ReadWriteRegister<u32>,
    i3c_ec_sec_fw_recovery_if_indirect_fifo_status_0:
        ReadWriteRegister<u32, registers_generated::i3c::bits::IndirectFifoStatus0::Register>,
    i3c_ec_sec_fw_recovery_if_indirect_fifo_status_1: ReadWriteRegister<u32>,
    i3c_ec_sec_fw_recovery_if_indirect_fifo_status_2: ReadWriteRegister<u32>,
    i3c_ec_sec_fw_recovery_if_recovery_ctrl:
        ReadWriteRegister<u32, registers_generated::i3c::bits::RecoveryCtrl::Register>,
    i3c_ec_soc_mgmt_if_rec_intf_cfg:
        ReadWriteRegister<u32, registers_generated::i3c::bits::RecIntfCfg::Register>,
    indirect_fifo_data: Vec<u8>,

    interrupt_status: ReadWriteRegister<u32, InterruptStatus::Register>,
    interrupt_enable: ReadWriteRegister<u32, InterruptEnable::Register>,

    // Channel for events going into I3C
    incoming_event_sender: mpsc::Sender<Event>,
    incoming_events: mpsc::Receiver<Event>,

    // Channel for events going out of I3C
    outgoing_event_sender: mpsc::Sender<Event>,
    outgoing_events: Option<mpsc::Receiver<Event>>,
}

impl I3c {
    const HCI_VERSION: u32 = 0x120;
    const HCI_TICKS: u64 = 1000;

    pub fn new(
        clock: &Clock,
        controller: &mut I3cController,
        error_irq: Irq,
        notif_irq: Irq,
    ) -> Self {
        let mut i3c_target = I3cTarget::default();

        controller.attach_target(i3c_target.clone()).unwrap();
        let timer = Timer::new(clock);
        timer.schedule_poll_in(Self::HCI_TICKS);
        let poll_scheduler = PollScheduler {
            timer: timer.clone(),
        };
        i3c_target.set_incoming_command_client(Arc::new(poll_scheduler));
        let (incoming_event_sender, incoming_events) = mpsc::channel::<Event>();
        let (outgoing_event_sender, outgoing_events) = mpsc::channel::<Event>();

        Self {
            i3c_target,
            timer,
            tti_rx_desc_queue_raw: VecDeque::new(),
            tti_rx_data_raw: VecDeque::new(),
            tti_rx_current: VecDeque::new(),
            tti_tx_desc_queue_raw: VecDeque::new(),
            tti_tx_data_raw: VecDeque::new(),
            tti_ibi_buffer: vec![],
            _error_irq: error_irq,
            notif_irq,
            i3c_ec_sec_fw_recovery_if_prot_cap_2: ReadWriteRegister::new(0),
            i3c_ec_sec_fw_recovery_if_device_status_0: ReadWriteRegister::new(0),
            i3c_ec_sec_fw_recovery_if_recovery_status: ReadWriteRegister::new(0),
            i3c_ec_sec_fw_recovery_if_indirect_fifo_ctrl_0: ReadWriteRegister::new(0),
            i3c_ec_sec_fw_recovery_if_indirect_fifo_ctrl_1: ReadWriteRegister::new(0),
            i3c_ec_sec_fw_recovery_if_indirect_fifo_status_0: ReadWriteRegister::new(0),
            i3c_ec_sec_fw_recovery_if_indirect_fifo_status_1: ReadWriteRegister::new(0),
            i3c_ec_sec_fw_recovery_if_indirect_fifo_status_2: ReadWriteRegister::new(0),
            i3c_ec_sec_fw_recovery_if_recovery_ctrl: ReadWriteRegister::new(0),
            i3c_ec_soc_mgmt_if_rec_intf_cfg: ReadWriteRegister::new(0),
            indirect_fifo_data: Vec::new(),
            interrupt_status: ReadWriteRegister::new(0),
            interrupt_enable: ReadWriteRegister::new(0),
            incoming_event_sender,
            incoming_events,
            outgoing_event_sender,
            outgoing_events: Some(outgoing_events),

        }
    }

    pub fn get_event_sender(&self) -> mpsc::Sender<Event> {
        self.incoming_event_sender.clone()
    }

    pub fn get_event_receiver(&mut self) -> Option<mpsc::Receiver<Event>> {
        self.outgoing_events.take()
    }

    pub fn get_dynamic_address(&self) -> Option<DynamicI3cAddress> {
        self.i3c_target.get_address()
    }

    fn write_tx_data_into_target(&mut self) {
        if !self.tti_tx_desc_queue_raw.is_empty() {
            let resp_desc = ResponseDescriptor::read_from_bytes(
                &self.tti_tx_desc_queue_raw[0].to_le_bytes()[..],
            )
            .unwrap();
            let data_size = resp_desc.data_length().into();
            if let Some(_data) = self.tti_tx_data_raw.front() {
                if self.tti_tx_data_raw[0].len() >= data_size {
                    self.tti_tx_desc_queue_raw.pop_front();
                    let resp = I3cTcriResponseXfer {
                        resp: resp_desc,
                        data: self.tti_tx_data_raw.pop_front().unwrap(),
                    };
                    self.i3c_target.set_response(resp);
                }
            }
        }
    }

    fn read_rx_data_into_buffer(&mut self) {
        if let Some(xfer) = self.i3c_target.read_command() {
            let cmd: u64 = xfer.cmd.into();
            let data = xfer.data;
            self.tti_rx_desc_queue_raw
                .push_back((cmd & 0xffff_ffff) as u32);
            self.tti_rx_desc_queue_raw
                .push_back(((cmd >> 32) & 0xffff_ffff) as u32);
            self.tti_rx_data_raw.push_back(data);
        }
    }

    fn check_interrupts(&mut self) {
        // TODO: implement the timeout interrupts

        // Set TxDescStat interrupt if there is a pending Read transaction (i.e., data needs to be written to the tx registers)
        let pending_read = self
            .tti_rx_desc_queue_raw
            .front()
            .map(|x| {
                ReguDataTransferCommand::read_from_bytes(&(*x as u64).to_le_bytes())
                    .unwrap()
                    .rnw()
                    == 1
            })
            .unwrap_or(false);
        self.interrupt_status.reg.modify(if pending_read {
            InterruptStatus::TxDescStat::SET
        } else {
            InterruptStatus::TxDescStat::CLEAR
        });

        // Set RxDescStat interrupt if there is a pending write (i.e., data to read from rx registers)
        self.interrupt_status
            .reg
            .modify(if self.tti_rx_desc_queue_raw.is_empty() {
                InterruptStatus::RxDescStat::CLEAR
            } else {
                InterruptStatus::RxDescStat::SET
            });

        self.notif_irq
            .set_level(self.interrupt_status.reg.any_matching_bits_set(
                InterruptStatus::RxDescStat::SET
                    + InterruptStatus::TxDescStat::SET
                    + InterruptStatus::RxDescTimeout::SET
                    + InterruptStatus::TxDescTimeout::SET,
            ));
    }

    // check if there area valid IBI descriptors and messages
    fn check_ibi_buffer(&mut self) {
        loop {
            if self.tti_ibi_buffer.len() <= 4 {
                return;
            }

            let desc = IbiDescriptor::read_from_bytes(&self.tti_ibi_buffer[0..4]).unwrap();
            let len = desc.data_length() as usize;
            if self.tti_ibi_buffer.len() < len + 4 {
                // wait for more data
                return;
            }
            // we only need the first byte, which is the MDB.
            // TODO: handle more than the MDB?
            // Drain IBI descriptor size + 4 bytes (MDB)
            self.i3c_target.send_ibi(self.tti_ibi_buffer[4]);
            self.tti_ibi_buffer.drain(0..(len + 4).next_multiple_of(4));
        }
    }

    pub fn incoming_caliptra_event(&mut self, event: Event) {
        match &event.event {
            EventData::MemoryRead { start_addr, len } => {
                let mut response = Vec::new();
                for _ in 0..(*len) / std::mem::size_of::<u32>() as u32 {
                    match self
                        .read_recovery_interface(caliptra_emu_types::RvSize::Word, *start_addr)
                    {
                        Ok(data) => {
                            response.extend_from_slice(&data.to_be_bytes());
                        }
                        Err(err) => {
                            println!("[I3C-Emulator] Error reading recovery interface: {:?}", err);
                            return;
                        }
                    }
                }

                self.outgoing_event_sender
                    .send(Event::new(
                        Device::RecoveryIntf,
                        Device::CaliptraCore,
                        EventData::MemoryReadResponse {
                            start_addr: *start_addr,
                            data: response,
                        },
                    ))
                    .unwrap();
            }
            EventData::MemoryWrite { start_addr, data } => {
                self.write_recovery_interface(
                    caliptra_emu_types::RvSize::Word,
                    *start_addr,
                    caliptra_emu_types::RvData::from_le_bytes(data[0..4].try_into().unwrap()),
                )
                .unwrap();
            }
            EventData::RecoveryFifoStatusRequest => {
                // Set the FIFO status to IMAGE_AVAILABLE only if full image is uploaded to the FIFO
                let image_size = self
                    .i3c_ec_sec_fw_recovery_if_indirect_fifo_ctrl_1
                    .reg
                    .get()
                    * std::mem::size_of::<u32>() as u32;
                let status =
                    if image_size == 0 || self.indirect_fifo_data.len() < image_size as usize {
                        0
                    } else {
                        1
                    };

                self.outgoing_event_sender
                    .send(Event::new(
                        Device::RecoveryIntf,
                        Device::CaliptraCore,
                        EventData::RecoveryFifoStatusResponse { status },
                    ))
                    .unwrap();
            }
            _ => {}
        }
    }

    pub fn incoming_mcu_event(&mut self, _event: Event) {
        // do nothing for now
    }

    fn read_recovery_interface(
        &mut self,
        size: caliptra_emu_types::RvSize,
        addr: caliptra_emu_types::RvAddr,
    ) -> Result<caliptra_emu_types::RvData, caliptra_emu_bus::BusError> {
        if addr & 0x3 != 0 || size != caliptra_emu_types::RvSize::Word {
            return Err(caliptra_emu_bus::BusError::LoadAddrMisaligned);
        }
        match addr {
            0x000..0x004 => Ok(caliptra_emu_types::RvData::from(
                self.read_i3c_ec_sec_fw_recovery_if_extcap_header()
                    .reg
                    .get(),
            )),
            0x004..0x008 => Ok(self.read_i3c_ec_sec_fw_recovery_if_prot_cap_0()),
            0x008..0x00c => Ok(self.read_i3c_ec_sec_fw_recovery_if_prot_cap_1()),
            0x00c..0x010 => Ok(caliptra_emu_types::RvData::from(
                self.read_i3c_ec_sec_fw_recovery_if_prot_cap_2().reg.get(),
            )),
            0x010..0x014 => Ok(caliptra_emu_types::RvData::from(
                self.read_i3c_ec_sec_fw_recovery_if_prot_cap_3().reg.get(),
            )),
            0x014..0x018 => Ok(caliptra_emu_types::RvData::from(
                self.read_i3c_ec_sec_fw_recovery_if_device_id_0().reg.get(),
            )),
            0x018..0x01c => Ok(self.read_i3c_ec_sec_fw_recovery_if_device_id_1()),
            0x01c..0x020 => Ok(self.read_i3c_ec_sec_fw_recovery_if_device_id_2()),
            0x020..0x024 => Ok(self.read_i3c_ec_sec_fw_recovery_if_device_id_3()),
            0x024..0x028 => Ok(self.read_i3c_ec_sec_fw_recovery_if_device_id_4()),
            0x028..0x02c => Ok(self.read_i3c_ec_sec_fw_recovery_if_device_id_5()),
            0x02c..0x030 => Ok(self.read_i3c_ec_sec_fw_recovery_if_device_id_reserved()),
            0x030..0x034 => Ok(caliptra_emu_types::RvData::from(
                self.read_i3c_ec_sec_fw_recovery_if_device_status_0()
                    .reg
                    .get(),
            )),
            0x034..0x038 => Ok(caliptra_emu_types::RvData::from(
                self.read_i3c_ec_sec_fw_recovery_if_device_status_1()
                    .reg
                    .get(),
            )),
            0x038..0x03c => Ok(caliptra_emu_types::RvData::from(
                self.read_i3c_ec_sec_fw_recovery_if_device_reset().reg.get(),
            )),
            0x03c..0x040 => Ok(caliptra_emu_types::RvData::from(
                self.read_i3c_ec_sec_fw_recovery_if_recovery_ctrl()
                    .reg
                    .get(),
            )),
            0x040..0x044 => Ok(caliptra_emu_types::RvData::from(
                self.read_i3c_ec_sec_fw_recovery_if_recovery_status()
                    .reg
                    .get(),
            )),
            0x044..0x048 => Ok(caliptra_emu_types::RvData::from(
                self.read_i3c_ec_sec_fw_recovery_if_hw_status().reg.get(),
            )),
            0x048..0x04c => Ok(caliptra_emu_types::RvData::from(
                self.read_i3c_ec_sec_fw_recovery_if_indirect_fifo_ctrl_0()
                    .reg
                    .get(),
            )),
            0x04c..0x050 => Ok(self.read_i3c_ec_sec_fw_recovery_if_indirect_fifo_ctrl_1()),
            0x050..0x054 => Ok(caliptra_emu_types::RvData::from(
                self.read_i3c_ec_sec_fw_recovery_if_indirect_fifo_status_0()
                    .reg
                    .get(),
            )),
            0x054..0x058 => Ok(self.read_i3c_ec_sec_fw_recovery_if_indirect_fifo_status_1()),
            0x058..0x05c => Ok(self.read_i3c_ec_sec_fw_recovery_if_indirect_fifo_status_2()),
            0x05c..0x060 => Ok(self.read_i3c_ec_sec_fw_recovery_if_indirect_fifo_status_3()),
            0x060..0x064 => Ok(self.read_i3c_ec_sec_fw_recovery_if_indirect_fifo_status_4()),
            0x064..0x068 => Ok(self.read_i3c_ec_sec_fw_recovery_if_indirect_fifo_reserved()),
            0x068..0x06c => Ok(self.read_i3c_ec_sec_fw_recovery_if_indirect_fifo_data()),

            _ => Err(caliptra_emu_bus::BusError::LoadAccessFault),
        }
    }

    fn write_recovery_interface(
        &mut self,
        size: caliptra_emu_types::RvSize,
        addr: caliptra_emu_types::RvAddr,
        val: caliptra_emu_types::RvData,
    ) -> Result<(), caliptra_emu_bus::BusError> {
        if addr & 0x3 != 0 || size != caliptra_emu_types::RvSize::Word {
            return Err(caliptra_emu_bus::BusError::StoreAddrMisaligned);
        }
        match addr {
            0x00c..0x010 => {
                self.write_i3c_ec_sec_fw_recovery_if_prot_cap_2(
                    caliptra_emu_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            0x010..0x014 => {
                self.write_i3c_ec_sec_fw_recovery_if_prot_cap_3(
                    caliptra_emu_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            0x014..0x018 => {
                self.write_i3c_ec_sec_fw_recovery_if_device_id_0(
                    caliptra_emu_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            0x018..0x01c => {
                self.write_i3c_ec_sec_fw_recovery_if_device_id_1(val);
                Ok(())
            }
            0x01c..0x020 => {
                self.write_i3c_ec_sec_fw_recovery_if_device_id_2(val);
                Ok(())
            }
            0x020..0x024 => {
                self.write_i3c_ec_sec_fw_recovery_if_device_id_3(val);
                Ok(())
            }
            0x024..0x028 => {
                self.write_i3c_ec_sec_fw_recovery_if_device_id_4(val);
                Ok(())
            }
            0x028..0x02c => {
                self.write_i3c_ec_sec_fw_recovery_if_device_id_5(val);
                Ok(())
            }
            0x030..0x034 => {
                self.write_i3c_ec_sec_fw_recovery_if_device_status_0(
                    caliptra_emu_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            0x034..0x038 => {
                self.write_i3c_ec_sec_fw_recovery_if_device_status_1(
                    caliptra_emu_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            0x038..0x03c => {
                self.write_i3c_ec_sec_fw_recovery_if_device_reset(
                    caliptra_emu_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            0x03c..0x040 => {
                self.write_i3c_ec_sec_fw_recovery_if_recovery_ctrl(
                    caliptra_emu_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            0x040..0x044 => {
                self.write_i3c_ec_sec_fw_recovery_if_recovery_status(
                    caliptra_emu_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            0x044..0x048 => {
                self.write_i3c_ec_sec_fw_recovery_if_hw_status(
                    caliptra_emu_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            0x048..0x04c => {
                self.write_i3c_ec_sec_fw_recovery_if_indirect_fifo_ctrl_0(
                    caliptra_emu_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            0x04c..0x050 => {
                self.write_i3c_ec_sec_fw_recovery_if_indirect_fifo_ctrl_1(val);
                Ok(())
            }
            0x88..0x8c => {
                self.write_piocontrol_tx_data_port(val);
                Ok(())
            }
            _ => Err(caliptra_emu_bus::BusError::StoreAccessFault),
        }
    }
}

impl I3cPeripheral for I3c {
    fn read_i3c_ec_tti_interrupt_enable(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::i3c::bits::InterruptEnable::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(self.interrupt_enable.reg.get())
    }

    fn read_i3c_ec_tti_interrupt_status(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::i3c::bits::InterruptStatus::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(self.interrupt_status.reg.get())
    }

    fn write_i3c_ec_tti_interrupt_status(
        &mut self,

        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            registers_generated::i3c::bits::InterruptStatus::Register,
        >,
    ) {
        let current = self.interrupt_status.reg.get();
        let new = val.reg.get();
        // clear the interrupts that are set
        self.interrupt_status.reg.set(current & !new);
        self.check_interrupts();
    }

    fn write_i3c_ec_tti_interrupt_enable(
        &mut self,

        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            registers_generated::i3c::bits::InterruptEnable::Register,
        >,
    ) {
        self.interrupt_enable.reg.set(val.reg.get());
    }

    fn write_i3c_ec_tti_tti_ibi_port(&mut self, val: RvData) {
        self.tti_ibi_buffer
            .extend_from_slice(val.to_le_bytes().as_ref());
        self.check_ibi_buffer();
    }

    fn read_i3c_ec_stdby_ctrl_mode_stby_cr_capabilities(
        &mut self,
    ) -> ReadWriteRegister<u32, StbyCrCapabilities::Register> {
        ReadWriteRegister::new(StbyCrCapabilities::TargetXactSupport.val(1).value)
    }

    fn read_i3c_ec_stdby_ctrl_mode_stby_cr_device_addr(
        &mut self,
    ) -> ReadWriteRegister<u32, StbyCrDeviceAddr::Register> {
        let val = match self.i3c_target.get_address() {
            Some(addr) => {
                StbyCrDeviceAddr::DynamicAddr.val(addr.into())
                    + StbyCrDeviceAddr::DynamicAddrValid::SET
            }
            None => StbyCrDeviceAddr::StaticAddr.val(0x3d) + StbyCrDeviceAddr::StaticAddrValid::SET,
        };
        ReadWriteRegister::new(val.value)
    }

    fn read_i3c_ec_tti_extcap_header(&mut self) -> ReadWriteRegister<u32, ExtcapHeader::Register> {
        ReadWriteRegister::new(ExtcapHeader::CapId.val(0xc4).value)
    }

    fn read_i3c_ec_tti_rx_desc_queue_port(&mut self) -> u32 {
        if self.tti_rx_desc_queue_raw.len() & 1 == 0 {
            // only replace the data every other read since the descriptor is 64 bits
            self.tti_rx_current = self.tti_rx_data_raw.pop_front().unwrap_or_default().into();
        }
        self.tti_rx_desc_queue_raw.pop_front().unwrap_or(0)
    }

    fn read_i3c_ec_tti_rx_data_port(&mut self) -> u32 {
        let mut data = self.tti_rx_current.pop_front().unwrap_or(0) as u32;
        data |= (self.tti_rx_current.pop_front().unwrap_or(0) as u32) << 8;
        data |= (self.tti_rx_current.pop_front().unwrap_or(0) as u32) << 16;
        data |= (self.tti_rx_current.pop_front().unwrap_or(0) as u32) << 24;
        data
    }

    fn write_i3c_ec_tti_tx_desc_queue_port(&mut self, val: u32) {
        self.tti_tx_desc_queue_raw.push_back(val);
        self.tti_tx_data_raw.push_back(vec![]);
        self.write_tx_data_into_target();
    }

    fn write_i3c_ec_tti_tx_data_port(&mut self, val: u32) {
        let bypass_cfg = self
            .i3c_ec_soc_mgmt_if_rec_intf_cfg
            .reg
            .read(RecIntfCfg::RecIntfBypass);
        if bypass_cfg == I3C_REC_INT_BYPASS_I3C_CORE {
            let to_append = val.to_le_bytes();
            let idx = self.tti_tx_data_raw.len() - 1;
            self.tti_tx_data_raw[idx].extend_from_slice(&to_append);
            self.write_tx_data_into_target();
        } else if bypass_cfg == I3C_REC_INT_BYPASS_AXI_DIRECT {
            let cms = self
                .i3c_ec_sec_fw_recovery_if_indirect_fifo_ctrl_0
                .reg
                .read(IndirectFifoCtrl0::Cms);
            if cms != 0 {
                println!("CMS {cms} not supported");
                return;
            }

            let write_index = self
                .i3c_ec_sec_fw_recovery_if_indirect_fifo_status_1
                .reg
                .get();
            let address = (write_index * 4) as usize;
            self.indirect_fifo_data.resize(
                address + std::mem::size_of::<caliptra_emu_types::RvData>(),
                0,
            );
            self.indirect_fifo_data
                [address..address + std::mem::size_of::<caliptra_emu_types::RvData>()]
                .copy_from_slice(val.to_le_bytes().as_ref());
            // head pointer must be aligned to 4 bytes at the end
            self.i3c_ec_sec_fw_recovery_if_indirect_fifo_status_1
                .reg
                .set(
                    ((address + std::mem::size_of::<caliptra_emu_types::RvData>())
                        .next_multiple_of(std::mem::size_of::<u32>())
                        / std::mem::size_of::<u32>()) as u32,
                );
        } else {
            println!("[I3C-Emulator] Unknown bypass configuration: {bypass_cfg}");
        }
    }

    fn read_i3c_ec_tti_tti_queue_size(&mut self) -> ReadWriteRegister<u32, TtiQueueSize::Register> {
        ReadWriteRegister::new(
            (TtiQueueSize::RxDataBufferSize.val(5)
                + TtiQueueSize::TxDataBufferSize.val(5)
                + TtiQueueSize::RxDescBufferSize.val(5)
                + TtiQueueSize::TxDescBufferSize.val(5))
            .value,
        )
    }

    fn write_i3c_ec_sec_fw_recovery_if_prot_cap_2(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            registers_generated::i3c::bits::ProtCap2::Register,
        >,
    ) {
        // convert the value in the other endianess
        let x = u32::from_be_bytes(val.reg.get().to_le_bytes());

        self.i3c_ec_sec_fw_recovery_if_prot_cap_2.reg.set(x);
    }

    fn read_i3c_ec_sec_fw_recovery_if_prot_cap_2(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<u32, registers_generated::i3c::bits::ProtCap2::Register>
    {
        caliptra_emu_bus::ReadWriteRegister::new(
            self.i3c_ec_sec_fw_recovery_if_prot_cap_2.reg.get(),
        )
    }

    fn write_i3c_ec_sec_fw_recovery_if_device_status_0(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            registers_generated::i3c::bits::DeviceStatus0::Register,
        >,
    ) {
        let current_status = self
            .i3c_ec_sec_fw_recovery_if_device_status_0
            .reg
            .read(DeviceStatus0::DevStatus);
        // DevStatus is 0x3 when the device is ready for a new image
        if val.reg.read(DeviceStatus0::DevStatus) == 0x3 && current_status != 0x3 {
            // Reset the device status, when the device is ready for a new image
            self.indirect_fifo_data.clear();
            self.i3c_ec_sec_fw_recovery_if_indirect_fifo_ctrl_0
                .reg
                .set(0);
            self.i3c_ec_sec_fw_recovery_if_indirect_fifo_status_0
                .reg
                .set(0);
            self.i3c_ec_sec_fw_recovery_if_indirect_fifo_status_1
                .reg
                .set(0);
            self.i3c_ec_sec_fw_recovery_if_indirect_fifo_status_2
                .reg
                .set(0);
        }
        self.i3c_ec_sec_fw_recovery_if_device_status_0
            .reg
            .set(val.reg.get());
    }

    fn read_i3c_ec_sec_fw_recovery_if_device_status_0(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::i3c::bits::DeviceStatus0::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(
            self.i3c_ec_sec_fw_recovery_if_device_status_0.reg.get(),
        )
    }

    fn write_i3c_ec_sec_fw_recovery_if_recovery_status(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            registers_generated::i3c::bits::RecoveryStatus::Register,
        >,
    ) {
        self.i3c_ec_sec_fw_recovery_if_recovery_status
            .reg
            .set(val.reg.get());
    }

    fn read_i3c_ec_sec_fw_recovery_if_recovery_status(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::i3c::bits::RecoveryStatus::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(
            self.i3c_ec_sec_fw_recovery_if_recovery_status.reg.get(),
        )
    }

    fn write_i3c_ec_sec_fw_recovery_if_indirect_fifo_ctrl_0(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            registers_generated::i3c::bits::IndirectFifoCtrl0::Register,
        >,
    ) {
        self.i3c_ec_sec_fw_recovery_if_indirect_fifo_ctrl_0
            .reg
            .set(val.reg.get());
    }

    fn read_i3c_ec_sec_fw_recovery_if_indirect_fifo_ctrl_1(
        &mut self,
    ) -> caliptra_emu_types::RvData {
        caliptra_emu_types::RvData::from(
            self.i3c_ec_sec_fw_recovery_if_indirect_fifo_ctrl_1
                .reg
                .get(),
        )
    }

    fn write_i3c_ec_sec_fw_recovery_if_indirect_fifo_ctrl_1(
        &mut self,
        val: caliptra_emu_types::RvData,
    ) {
        self.indirect_fifo_data.clear();
        self.i3c_ec_sec_fw_recovery_if_indirect_fifo_status_0
            .reg
            .set(0);
        self.i3c_ec_sec_fw_recovery_if_indirect_fifo_status_1
            .reg
            .set(0);
        self.i3c_ec_sec_fw_recovery_if_indirect_fifo_status_2
            .reg
            .set(0);
        self.i3c_ec_sec_fw_recovery_if_indirect_fifo_ctrl_1
            .reg
            .set(val);
    }

    fn read_i3c_ec_sec_fw_recovery_if_indirect_fifo_data(&mut self) -> caliptra_emu_types::RvData {
        let cms = self
            .i3c_ec_sec_fw_recovery_if_indirect_fifo_ctrl_0
            .reg
            .read(IndirectFifoCtrl0::Cms);
        if cms != 0 {
            println!("CMS {cms} not supported");
            return 0xffff_ffff;
        }

        let read_index = self
            .i3c_ec_sec_fw_recovery_if_indirect_fifo_status_2
            .reg
            .get();
        let address = read_index * std::mem::size_of::<u32>() as u32;
        let image_len = self
            .i3c_ec_sec_fw_recovery_if_indirect_fifo_ctrl_1
            .reg
            .get()
            * std::mem::size_of::<u32>() as u32;
        if address >= image_len {
            return 0xffff_ffff;
        };
        if address >= image_len - 4 {
            self.i3c_ec_sec_fw_recovery_if_indirect_fifo_status_0
                .reg
                .modify(IndirectFifoStatus0::Full::SET);
        }

        let address: usize = address.try_into().unwrap();
        let range = address..(address + 4);
        let data = &self.indirect_fifo_data.clone()[range];
        self.i3c_ec_sec_fw_recovery_if_indirect_fifo_status_2
            .reg
            .set(read_index + 1);

        u32::from_be_bytes(data.try_into().unwrap())
    }

    fn read_i3c_ec_sec_fw_recovery_if_indirect_fifo_status_0(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::i3c::bits::IndirectFifoStatus0::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(
            self.i3c_ec_sec_fw_recovery_if_indirect_fifo_status_0
                .reg
                .get(),
        )
    }

    fn read_i3c_ec_sec_fw_recovery_if_indirect_fifo_status_1(
        &mut self,
    ) -> caliptra_emu_types::RvData {
        caliptra_emu_types::RvData::from(
            self.i3c_ec_sec_fw_recovery_if_indirect_fifo_status_1
                .reg
                .get(),
        )
    }

    fn read_i3c_ec_sec_fw_recovery_if_indirect_fifo_status_2(
        &mut self,
    ) -> caliptra_emu_types::RvData {
        caliptra_emu_types::RvData::from(
            self.i3c_ec_sec_fw_recovery_if_indirect_fifo_status_2
                .reg
                .get(),
        )
    }

    fn read_i3c_ec_sec_fw_recovery_if_recovery_ctrl(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::i3c::bits::RecoveryCtrl::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(
            self.i3c_ec_sec_fw_recovery_if_recovery_ctrl.reg.get(),
        )
    }
    fn write_i3c_ec_sec_fw_recovery_if_recovery_ctrl(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            registers_generated::i3c::bits::RecoveryCtrl::Register,
        >,
    ) {
        self.i3c_ec_sec_fw_recovery_if_recovery_ctrl
            .reg
            .set(val.reg.get());
    }
    fn read_i3c_ec_soc_mgmt_if_rec_intf_cfg(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::i3c::bits::RecIntfCfg::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(self.i3c_ec_soc_mgmt_if_rec_intf_cfg.reg.get())
    }
    fn write_i3c_ec_soc_mgmt_if_rec_intf_cfg(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            registers_generated::i3c::bits::RecIntfCfg::Register,
        >,
    ) {
        self.i3c_ec_soc_mgmt_if_rec_intf_cfg.reg.set(val.reg.get());
    }

    fn poll(&mut self) {
        self.check_interrupts();
        self.read_rx_data_into_buffer();
        self.write_tx_data_into_target();
        self.timer.schedule_poll_in(Self::HCI_TICKS);

        while let Ok(event) = self.incoming_events.try_recv() {
            match event.dest {
                Device::RecoveryIntf => {
                    self.incoming_caliptra_event(event);
                }
                _ => {}
            }
        }

        if cfg!(feature = "test-i3c-constant-writes") {
            static mut COUNTER: u32 = 0;
            // ensure there are 10 writes queued
            if self.tti_rx_desc_queue_raw.is_empty() && unsafe { COUNTER } < 10 {
                unsafe {
                    COUNTER += 1;
                }
                self.tti_rx_desc_queue_raw.push_back(100 << 16);
                self.tti_rx_desc_queue_raw.push_back(unsafe { COUNTER });
                self.tti_rx_data_raw.push_back(vec![0xff; 100]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i3c_protocol::{
        DynamicI3cAddress, I3cTcriCommand, I3cTcriCommandXfer, ImmediateDataTransferCommand,
    };
    use caliptra_emu_bus::Bus;
    use caliptra_emu_cpu::Pic;
    use caliptra_emu_types::{RvAddr, RvSize};
    use emulator_registers_generated::root_bus::AutoRootBus;

    const TTI_RX_DESC_QUEUE_PORT: RvAddr = 0x1dc;

    #[test]
    fn receive_i3c_cmd() {
        let clock = Clock::new();
        let pic = Pic::new();
        let error_irq = pic.register_irq(17);
        let notif_irq = pic.register_irq(18);
        let mut i3c_controller = I3cController::default();
        let mut i3c = Box::new(I3c::new(&clock, &mut i3c_controller, error_irq, notif_irq));

        assert_eq!(i3c.read_i3c_base_hci_version(), I3c::HCI_VERSION);

        let cmd_bytes: [u8; 8] = [0x01, 0, 0, 0, 0, 0, 0, 0];
        let cmd = I3cTcriCommandXfer {
            cmd: I3cTcriCommand::Immediate(
                ImmediateDataTransferCommand::read_from_bytes(&cmd_bytes[..]).unwrap(),
            ),
            data: Vec::new(),
        };
        i3c_controller
            .tcri_send(DynamicI3cAddress::new(8).unwrap(), cmd)
            .unwrap();

        let mut bus = AutoRootBus::new(
            vec![],
            None,
            Some(i3c),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        for _ in 0..10000 {
            clock.increment_and_process_timer_actions(1, &mut bus);
        }

        assert_eq!(
            bus.read(
                RvSize::Word,
                registers_generated::i3c::I3C_CSR_ADDR + TTI_RX_DESC_QUEUE_PORT
            )
            .unwrap(),
            1
        );
    }
}
