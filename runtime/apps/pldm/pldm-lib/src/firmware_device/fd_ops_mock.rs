// Licensed under the Apache-2.0 license

extern crate alloc;
use crate::firmware_device::fd_ops::{ComponentOperation, FdOps, FdOpsError};
use alloc::boxed::Box;
use async_trait::async_trait;
use core::cell::RefCell;
use libtock_platform::Syscalls;
use pldm_common::message::firmware_update::apply_complete::ApplyResult;
use pldm_common::message::firmware_update::get_status::ProgressPercent;
use pldm_common::message::firmware_update::transfer_complete::TransferResult;
use pldm_common::message::firmware_update::verify_complete::VerifyResult;
use pldm_common::util::fw_component::FirmwareComponent;
use pldm_common::{
    message::firmware_update::get_fw_params::FirmwareParameters,
    protocol::firmware_update::{
        ComponentResponseCode, Descriptor, PldmFdTime, PLDM_FWUP_BASELINE_TRANSFER_SIZE,
        PLDM_FWUP_MAX_PADDING_SIZE,
    },
};

pub struct FdOpsObject<S: Syscalls> {
    download_ctx: RefCell<DownloadCtx>,
    _marker: core::marker::PhantomData<S>,
}

pub struct DownloadCtx {
    pub offset: usize,
    pub length: usize,
}

impl<S: Syscalls> Default for FdOpsObject<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Syscalls> FdOpsObject<S> {
    pub fn new() -> Self {
        Self {
            download_ctx: RefCell::new(DownloadCtx {
                offset: 0,
                length: 0,
            }),
            _marker: core::marker::PhantomData,
        }
    }
}

#[async_trait(?Send)]
impl<S: Syscalls> FdOps for FdOpsObject<S> {
    async fn get_device_identifiers(
        &self,
        device_identifiers: &mut [Descriptor],
    ) -> Result<usize, FdOpsError> {
        let dev_id = crate::config::DESCRIPTORS.get();
        if device_identifiers.len() < dev_id.len() {
            Err(FdOpsError::DeviceIdentifiersError)
        } else {
            device_identifiers[..dev_id.len()].copy_from_slice(dev_id);
            Ok(dev_id.len())
        }
    }

    async fn get_firmware_parms(
        &self,
        firmware_params: &mut FirmwareParameters,
    ) -> Result<(), FdOpsError> {
        let fw_params = crate::config::FIRMWARE_PARAMS.get();
        *firmware_params = (*fw_params).clone();
        Ok(())
    }

    async fn get_xfer_size(&self, ua_transfer_size: usize) -> Result<usize, FdOpsError> {
        Ok(PLDM_FWUP_BASELINE_TRANSFER_SIZE
            .max(ua_transfer_size.min(crate::config::FD_MAX_XFER_SIZE)))
    }

    async fn handle_component(
        &self,
        component: &FirmwareComponent,
        fw_params: &FirmwareParameters,
        op: ComponentOperation,
    ) -> Result<ComponentResponseCode, FdOpsError> {
        let comp_resp_code = component.evaluate_update_eligibility(fw_params);

        // If it is update component operation, reset download context
        if op == ComponentOperation::UpdateComponent {
            let mut download_ctx = self.download_ctx.borrow_mut();
            download_ctx.offset = 0;
            download_ctx.length = 0;
        }

        Ok(comp_resp_code)
    }

    async fn query_download_offset_and_length(
        &self,
        component: &FirmwareComponent,
    ) -> Result<(usize, usize), FdOpsError> {
        let download_ctx = self.download_ctx.borrow();
        match component.comp_image_size {
            Some(image_size) => {
                let offset = download_ctx.offset;
                let length = (image_size as usize - offset).min(64); // Example transfer size limit
                Ok((offset, length))
            }
            None => Err(FdOpsError::ComponentError),
        }
    }

    async fn download_fw_data(
        &self,
        offset: usize,
        data: &[u8],
        component: &FirmwareComponent,
    ) -> Result<TransferResult, FdOpsError> {
        let component_image_size = component
            .comp_image_size
            .ok_or(FdOpsError::FwDownloadError)? as usize;

        let max_allowed_size = component_image_size + PLDM_FWUP_MAX_PADDING_SIZE as usize;
        let mut download_ctx = self.download_ctx.borrow_mut();

        if offset != download_ctx.offset || offset + data.len() > max_allowed_size {
            // reset download context if offset is not as expected
            download_ctx.offset = 0;
            download_ctx.length = 0;
            return Err(FdOpsError::FwDownloadError);
        }

        download_ctx.offset += data.len();
        download_ctx.length += data.len();

        Ok(TransferResult::TransferSuccess)
    }

    async fn is_download_complete(&self, component: &FirmwareComponent) -> bool {
        let download_ctx = self.download_ctx.borrow();
        if let Some(image_size) = component.comp_image_size {
            download_ctx.length >= image_size as usize
        } else {
            false
        }
    }

    async fn verify(
        &self,
        _component: &FirmwareComponent,
        progress_percent: &mut ProgressPercent,
    ) -> Result<VerifyResult, FdOpsError> {
        static mut CALL_COUNT: usize = 0;
        unsafe {
            CALL_COUNT += 1;
            let new_value = if CALL_COUNT == 1 { 40 } else { 100 };
            progress_percent.set_value(new_value).ok();
            Ok(VerifyResult::VerifySuccess)
        }
    }

    async fn apply(
        &self,
        _component: &FirmwareComponent,
        progress_percent: &mut ProgressPercent,
    ) -> Result<ApplyResult, FdOpsError> {
        static mut CALL_COUNT: usize = 0;
        unsafe {
            CALL_COUNT += 1;
            let new_value = if CALL_COUNT == 1 { 40 } else { 100 };
            progress_percent.set_value(new_value).ok();
            Ok(ApplyResult::ApplySuccess)
        }
    }

    async fn activate(
        &self,
        self_contained_activation: u8,
        estimated_time: &mut u16,
    ) -> Result<u8, FdOpsError> {
        if self_contained_activation == 1 {
            *estimated_time = crate::config::TEST_SELF_ACTIVATION_MAX_TIME_IN_SECONDS;
        }
        Ok(0) // PLDM completion code for success
    }

    async fn now(&self) -> PldmFdTime {
        crate::timer::AsyncAlarm::<S>::get_milliseconds().unwrap()
    }
}
