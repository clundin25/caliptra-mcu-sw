// Licensed under the Apache-2.0 license

use crate::{dma::*, rom};
use crate::flash::flash_api::FlashPartition;
use bitfield::bitfield;
use flash_image::{FlashChecksums, FlashHeader, ImageHeader};
use registers_generated::i3c;
use registers_generated::i3c::bits::{RecIntfCfg, RecoveryCtrl};
use romtime::StaticRef;
use smlang::statemachine;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use zerocopy::FromBytes;

const ACTIVATE_RECOVERY_IMAGE_CMD: u32 = 0xF;
const BYPASS_CFG_USE_I3C: u32 = 0x0;
const BYPASS_CFG_AXI_DIRECT: u32 = 0x1;
const DMA_TRANSFER_BLOCK_SIZE: usize = 256;

statemachine! {
    derive_states: [Clone, Copy, Debug],
    transitions: {
        // syntax: CurrentState Event [guard] / action = NextState

        // start by reading ProtCap to see if the device supports recovery
        *ReadProtCap + ProtCap(ProtCap2) [check_device_status_support] = ReadDeviceStatus,

        // read the device status to see if it needs recovery
        ReadDeviceStatus + DeviceStatus(DeviceStatus0) [check_device_status_healthy] = Done,

        // if the device needs recovery, send the recovery control message
        ReadDeviceStatus + DeviceStatus(DeviceStatus0) [check_device_status_recovery]
             = WaitForRecoveryStatus,

        // send the requested recovery image
        WaitForRecoveryStatus + RecoveryStatus(RecoveryStatus) [check_recovery_status_awaiting]
             = TransferringImage,


        TransferringImage + TransferComplete  = WaitForRecoveryPending,

        // activate the recovery image after it has been processed
        WaitForRecoveryPending + DeviceStatus(DeviceStatus0) [check_device_status_recovery_pending]
             = Activate,

        // check if we need to send another recovery image (if awaiting image is set and running recovery)
        Activate + CheckFwActivation = CheckFwActivation,


        CheckFwActivation + RecoveryStatus(RecoveryStatus) [check_fw_booting_image]
            = ActivateCheckRecoveryStatus,

        ActivateCheckRecoveryStatus + RecoveryStatus(RecoveryStatus) [check_recovery_status_awaiting]
             = ReadDeviceStatus,

        ActivateCheckRecoveryStatus + RecoveryStatus(RecoveryStatus) [check_fw_recovery_success]
             = Done,

    }
}

bitfield! {
    pub struct ProtCap2(u32);
    impl Debug;
    pub identification, set_identification: 0;
    pub forced_recovery, set_forced_recovery: 1;
    pub mgmt_reset, set_mgmt_reset: 2;
    pub device_reset, set_device_reset: 3;
    pub device_status, set_device_status: 4;
    pub recovery_memory_access, set_recovery_memory_access: 5;
    pub local_c_image_support, set_local_c_image_support: 6;
    pub push_c_image_support, set_push_c_image_support: 7;
    pub interface_isolation, set_interface_isolation: 8;
    pub hardware_status, set_hardware_status: 9;
    pub vendors_command, set_vendors_command: 10;
    pub reserved, set_reserved: 31, 11;
}

bitfield! {
    pub struct DeviceStatus0(u32);
    impl Debug;
    pub device_status, set_device_status: 7,0;
    pub protocol_error, set_protocol_error: 15,8;
    pub recovery_reason, set_recovery_reason: 31,16;

}

bitfield! {
    pub struct RecoveryCtrl0(u32);
    impl Debug;
    pub cms, set_cms: 7,0;
    pub rec_img_sel, set_rec_img_sel: 15,8;
    pub activate_rec_image, set_activate_rec_image: 23,16;

}

// Device status codes (Byte 0)
pub mod device_status_code {
    pub const DEVICE_HEALTHY: u8 = 0x1;
    pub const RECOVERY_MODE: u8 = 0x3;
    pub const RECOVERY_PENDING: u8 = 0x4;
}

// RECOVERY_STATUS register (32 bits)
bitfield! {
    #[derive(Clone, Copy)]
    pub struct RecoveryStatus(u32);
    impl Debug;

    // Bits 3:0 - Device recovery status
    pub dev_rec_status, set_dev_rec_status: 3, 0;
    // Bits 7:4 - Recovery image index
    pub rec_img_index, set_rec_img_index: 7, 4;
    // Bits 15:8 - Vendor specific status
    pub vendor_specific_status, set_vendor_specific_status: 15, 8;
    // Bits 31:16 - Reserved (not used, can be added if needed)
}

/// Device Recovery Status codes (Bits 3:0)
pub mod dev_rec_status_code {
    pub const AWAITING_IMAGE: u8 = 0x1;
    pub const BOOTING_IMAGE: u8 = 0x2;
    pub const RECOVERY_SUCCESS: u8 = 0x3;
    // 0x4-0xB: Reserved
}

/// State machine extended variables.
pub(crate) struct Context {
    recovery_image_index: u8,
    image_size: u32,
    flash_offset: u32,
    pub transfer_offset: u32,
}

impl Context {
    pub(crate) fn new() -> Context {
        Context {
            recovery_image_index: 0,
            image_size: 0,
            flash_offset: 0,
            transfer_offset: 0,
        }
    }
}

impl StateMachineContext for Context {
    /// Check that the the protcap supports device status
    fn check_device_status_support(&self, prot_cap: &ProtCap2) -> Result<bool, ()> {
        if prot_cap.device_status() {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Chjeck that the device status is healthy
    fn check_device_status_healthy(&self, status: &DeviceStatus0) -> Result<bool, ()> {
        if status.device_status() == device_status_code::DEVICE_HEALTHY as u32 {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Check that the device status is recovery mode
    fn check_device_status_recovery(&self, status: &DeviceStatus0) -> Result<bool, ()> {
        if status.device_status() == device_status_code::RECOVERY_MODE as u32 {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Check that the recovery status is awaiting a recovery image
    fn check_recovery_status_awaiting(&self, status: &RecoveryStatus) -> Result<bool, ()> {
        if status.dev_rec_status() == dev_rec_status_code::AWAITING_IMAGE as u32 {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn check_fw_recovery_success(&self, status: &RecoveryStatus) -> Result<bool, ()> {
        if status.dev_rec_status() == dev_rec_status_code::RECOVERY_SUCCESS as u32 {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Check that the device status is recovery pending
    fn check_device_status_recovery_pending(&self, status: &DeviceStatus0) -> Result<bool, ()> {
        if status.device_status() == device_status_code::RECOVERY_PENDING as u32 {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn check_fw_booting_image(&self, status: &RecoveryStatus) -> Result<bool, ()> {
        if status.dev_rec_status() == dev_rec_status_code::BOOTING_IMAGE as u32 {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

pub fn get_flash_image_info(id: u32, flash_driver: &mut FlashPartition) -> Result<(u32, u32), ()> {
    // get the maximum size between FlashHeader, Checksums, and ImageHeader
    let mut buf = [0u8; 12];

    // Read the flash header
    flash_driver
        .read(0, &mut buf[..core::mem::size_of::<FlashHeader>()])
        .map_err(|_| ())?;

    let flash_header = FlashHeader::ref_from_prefix(&buf[..core::mem::size_of::<FlashHeader>()])
        .map_err(|_| ())?
        .0;

    let image_count = flash_header.image_count;

    for i in 0..image_count as usize {
        // Read the image header
        let offset = core::mem::size_of::<FlashHeader>()
            + core::mem::size_of::<FlashChecksums>()
            + i * core::mem::size_of::<ImageHeader>();
        flash_driver
            .read(offset, &mut buf[..core::mem::size_of::<ImageHeader>()])
            .map_err(|_| ())?;
        let image_header =
            ImageHeader::ref_from_prefix(&buf[..core::mem::size_of::<ImageHeader>()])
                .map_err(|_| ())?
                .0;

        if image_header.identifier == id {
            return Ok((image_header.offset, image_header.size));
        }
    }

    Err(())
}

pub fn recovery_img_index_to_image_id(recovery_image_index: u32) -> Result<u32, ()> {
    // Convert the recovery image index to the image ID
    match recovery_image_index {
        0 => Ok(0x1), // Caliptra FMC+RT index 0 is image ID 1
        1 => Ok(0x2), // SoC Manifest index 1 is image ID 2
        2 => Ok(0x3), // MCU Runtime index 2 is image ID 3
        _ => Err(()), // Invalid index
    }
}

pub fn load_flash_image_to_recovery(
    i3c_periph: StaticRef<i3c::regs::I3c>,
    flash_driver: &mut FlashPartition,
    dma_driver: Option<&mut dyn Dma>,
) -> Result<(), ()> {
    let context = Context::new();
    let mut state_machine = StateMachine::new(context);

    let mut prev_state = States::ReadProtCap;
    let mut last_percent = 0u32;

    i3c_periph
        .soc_mgmt_if_rec_intf_cfg
        .modify(RecIntfCfg::RecIntfBypass.val(BYPASS_CFG_AXI_DIRECT));
    while *state_machine.state() != States::Done {
        if prev_state != *state_machine.state() {
            romtime::println!(
                "[mcu-rom] Transitioning from {:?} to {:?}",
                prev_state,
                state_machine.state()
            );
            prev_state = *state_machine.state();
        };

        match *state_machine.state() {
            States::ReadProtCap => {
                // Read the ProtCap2 register
                let prot_cap = i3c_periph.sec_fw_recovery_if_prot_cap_2.get();
                let _ = state_machine.process_event(Events::ProtCap(ProtCap2(prot_cap)));
            }

            States::ReadDeviceStatus => {
                // Read the Device Status register
                let device_status = i3c_periph.sec_fw_recovery_if_device_status_0.get();
                let _ =
                    state_machine.process_event(Events::DeviceStatus(DeviceStatus0(device_status)));
            }

            States::WaitForRecoveryStatus => {
                // Read the Recovery Status register
                let recovery_status =
                    RecoveryStatus(i3c_periph.sec_fw_recovery_if_recovery_status.get());
                let res = state_machine.process_event(Events::RecoveryStatus(recovery_status));
                if res.is_ok() {
                    state_machine.context_mut().recovery_image_index =
                        recovery_status.rec_img_index() as u8;
                    romtime::println!(
                        "[mcu-rom] Starting recovery with image index {}",
                        state_machine.context().recovery_image_index
                    );
                    let image_info = get_flash_image_info(
                        recovery_img_index_to_image_id(
                            state_machine.context().recovery_image_index as u32,
                        )?,
                        flash_driver,
                    )?;
                    state_machine.context_mut().flash_offset = image_info.0;
                    state_machine.context_mut().image_size = image_info.1;
                    state_machine.context_mut().transfer_offset = 0;
                    i3c_periph
                        .sec_fw_recovery_if_indirect_fifo_ctrl_1
                        .set(state_machine.context().image_size / 4);
                }
            }

            States::TransferringImage => {
                if (state_machine.context().transfer_offset * 100
                    / state_machine.context().image_size)
                    / 10
                    != last_percent
                {
                    romtime::println!(
                        "[mcu-rom] Transferring image data at offset {} out of {}",
                        state_machine.context().transfer_offset,
                        state_machine.context().image_size
                    );
                    last_percent = (state_machine.context().transfer_offset * 100
                        / state_machine.context().image_size)
                        / 10;
                }

                if state_machine.context().transfer_offset >= state_machine.context().image_size {
                    // If the transfer is complete, we can move to the next state
                    let _ = state_machine.process_event(Events::TransferComplete);
                } else {
                    romtime::println!("1");
                    if let Some(dma_driver) = dma_driver.as_ref () {
                        // Use DMA to transfer data
                        
                        let bytes_to_transfer = core::cmp::min(
                            state_machine.context().image_size
                                - state_machine.context().transfer_offset,
                            DMA_TRANSFER_BLOCK_SIZE as u32,
                        );
                        let mut buf = [0u8; DMA_TRANSFER_BLOCK_SIZE];
                        romtime::println!("2");
                        // print the address of buf

                        flash_driver
                            .read(
                                (state_machine.context().flash_offset
                                    + state_machine.context().transfer_offset) as usize,
                                &mut buf[..bytes_to_transfer as usize],
                            )
                            .map_err(|_| ())?;
                                                romtime::println!("Buffer address: {:p}", &buf);
                        // dump the buffer in hex
                        for byte in &buf {
                            romtime::print!("{:02x} ", byte);
                        }
                        romtime::println!();

                        romtime::println!("4");

                        dma_driver.write_fifo(&buf[..bytes_to_transfer as usize])
                            .map_err(|_| ())?;
                        romtime::println!("5");

                        state_machine.context_mut().transfer_offset += bytes_to_transfer;
                        romtime::println!("6");

                    } else {
                        // Fallback to direct read if DMA is not available
                        let mut data = [0u8; 4];
                        flash_driver
                            .read(
                                (state_machine.context().flash_offset
                                    + state_machine.context().transfer_offset)
                                    as usize,
                                &mut data,
                            )
                            .map_err(|_| ())?;
                        i3c_periph.tti_tx_data_port.set(u32::from_be_bytes(data));
                        state_machine.context_mut().transfer_offset += 4;
                    }

                }
            }

            States::WaitForRecoveryPending => {
                let device_status = i3c_periph.sec_fw_recovery_if_device_status_0.get();
                let _ =
                    state_machine.process_event(Events::DeviceStatus(DeviceStatus0(device_status)));
            }

            States::Activate => {
                // Activate the recovery image
                i3c_periph
                    .sec_fw_recovery_if_recovery_ctrl
                    .modify(RecoveryCtrl::ActivateRecImg.val(ACTIVATE_RECOVERY_IMAGE_CMD));
                let _ = state_machine.process_event(Events::CheckFwActivation);
            }

            States::CheckFwActivation => {
                // Check if the device is running recovery
                let recovery_status =
                    RecoveryStatus(i3c_periph.sec_fw_recovery_if_recovery_status.get());
                let _ = state_machine.process_event(Events::RecoveryStatus(recovery_status));
            }

            States::ActivateCheckRecoveryStatus => {
                // Check the recovery status after activation
                let recovery_status =
                    RecoveryStatus(i3c_periph.sec_fw_recovery_if_recovery_status.get());
                let _ = state_machine.process_event(Events::RecoveryStatus(recovery_status));
            }

            _ => {}
        }
    }
    i3c_periph
        .soc_mgmt_if_rec_intf_cfg
        .modify(RecIntfCfg::RecIntfBypass.val(BYPASS_CFG_USE_I3C));

    Ok(())
}
