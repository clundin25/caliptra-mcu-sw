// Licensed under the Apache-2.0 license

use crate::cmd_interface::generate_failure_response;
use crate::error::MsgHandlerError;
use crate::firmware_device::fd_internal::{FdInternal, FdReqState};
use crate::firmware_device::fd_ops::{ComponentOperation, FdOps, FdOpsObject};
use libtock_platform::Syscalls;
use pldm_common::codec::PldmCodec;
use pldm_common::message::firmware_update::get_fw_params::{
    FirmwareParameters, GetFirmwareParametersRequest, GetFirmwareParametersResponse,
};
use pldm_common::message::firmware_update::pass_component::{
    PassComponentTableRequest, PassComponentTableResponse,
};
use pldm_common::message::firmware_update::query_devid::{
    QueryDeviceIdentifiersRequest, QueryDeviceIdentifiersResponse,
};
use pldm_common::message::firmware_update::request_update::{
    RequestUpdateRequest, RequestUpdateResponse,
};
use pldm_common::message::firmware_update::update_component::{
    UpdateComponentRequest, UpdateComponentResponse,
};

use pldm_common::message::firmware_update::request_fw_data::{
    RequestFirmwareDataRequest, RequestFirmwareDataResponse,
};

use pldm_common::protocol::base::{PldmBaseCompletionCode, PldmMsgType, TransferRespFlag};
use pldm_common::protocol::firmware_update::{
    ComponentCompatibilityResponse, ComponentCompatibilityResponseCode, ComponentResponse,
    ComponentResponseCode, Descriptor, FirmwareDeviceState, FwUpdateCompletionCode,
    PldmFirmwareString, UpdateOptionFlags, MAX_DESCRIPTORS_COUNT, PLDM_FWUP_BASELINE_TRANSFER_SIZE,
};
use pldm_common::util::fw_component::FirmwareComponent;

// Debug usage
use core::fmt::Write;
use libtock_console::Console;
use libtock_console::ConsoleWriter;

pub struct FirmwareDeviceContext<S: Syscalls> {
    ops: FdOpsObject<S>,
    internal: FdInternal,
}

impl<S: Syscalls> FirmwareDeviceContext<S> {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            ops: FdOpsObject::new(),
            internal: FdInternal::default(),
        }
    }

    pub async fn query_devid_rsp(&self, payload: &mut [u8]) -> Result<usize, MsgHandlerError> {
        // Decode the request message
        let req = QueryDeviceIdentifiersRequest::decode(payload).map_err(MsgHandlerError::Codec)?;

        let mut device_identifiers: [Descriptor; MAX_DESCRIPTORS_COUNT] =
            [Descriptor::default(); MAX_DESCRIPTORS_COUNT];

        // Get the device identifiers
        let descriptor_cnt = self
            .ops
            .get_device_identifiers(&mut device_identifiers)
            .await
            .map_err(MsgHandlerError::FdOps)?;

        // Create the response message
        let resp = QueryDeviceIdentifiersResponse::new(
            req.hdr.instance_id(),
            PldmBaseCompletionCode::Success as u8,
            &device_identifiers[0],
            device_identifiers.get(1..descriptor_cnt),
        )
        .map_err(MsgHandlerError::PldmCommon)?;

        match resp.encode(payload) {
            Ok(bytes) => Ok(bytes),
            Err(_) => {
                generate_failure_response(payload, PldmBaseCompletionCode::InvalidLength as u8)
            }
        }
    }

    pub async fn get_firmware_parameters_rsp(
        &self,
        payload: &mut [u8],
    ) -> Result<usize, MsgHandlerError> {
        // Decode the request message
        let req = GetFirmwareParametersRequest::decode(payload).map_err(MsgHandlerError::Codec)?;

        let mut firmware_params = FirmwareParameters::default();
        self.ops
            .get_firmware_parms(&mut firmware_params)
            .await
            .map_err(MsgHandlerError::FdOps)?;

        // Construct response
        let resp = GetFirmwareParametersResponse::new(
            req.hdr.instance_id(),
            PldmBaseCompletionCode::Success as u8,
            &firmware_params,
        );

        match resp.encode(payload) {
            Ok(bytes) => Ok(bytes),
            Err(_) => {
                generate_failure_response(payload, PldmBaseCompletionCode::InvalidLength as u8)
            }
        }
    }

    pub async fn request_update_rsp(&self, payload: &mut [u8]) -> Result<usize, MsgHandlerError> {
        // Check if FD is in idle state. Otherwise returns 'ALREADY_IN_UPDATE_MODE' completion code
        if self.internal.is_update_mode().await {
            return generate_failure_response(
                payload,
                FwUpdateCompletionCode::AlreadyInUpdateMode as u8,
            );
        }

        // Set timestamp for FD T1 timeout
        self.set_fd_t1_ts().await;

        // Decode the request message
        let req = RequestUpdateRequest::decode(payload).map_err(MsgHandlerError::Codec)?;
        let ua_transfer_size = req.fixed.max_transfer_size as usize;
        if ua_transfer_size < PLDM_FWUP_BASELINE_TRANSFER_SIZE {
            return generate_failure_response(
                payload,
                FwUpdateCompletionCode::InvalidTransferLength as u8,
            );
        }

        // Get the transfer size for the firmware update operation
        let fd_transfer_size = self
            .ops
            .get_xfer_size(ua_transfer_size)
            .await
            .map_err(MsgHandlerError::FdOps)?;

        // Set transfer size to the internal state
        self.internal.set_xfer_size(fd_transfer_size).await;

        // Construct response, no metadata or package data.
        let resp = RequestUpdateResponse::new(
            req.fixed.hdr.instance_id(),
            PldmBaseCompletionCode::Success as u8,
            0,
            0,
            None,
        );

        match resp.encode(payload) {
            Ok(bytes) => {
                // Move FD state to 'LearnComponents'
                self.internal
                    .set_fd_state(FirmwareDeviceState::LearnComponents)
                    .await;
                Ok(bytes)
            }
            Err(_) => {
                generate_failure_response(payload, PldmBaseCompletionCode::InvalidLength as u8)
            }
        }
    }

    pub async fn pass_component_rsp(&self, payload: &mut [u8]) -> Result<usize, MsgHandlerError> {
        // Check if FD is in 'LearnComponents' state. Otherwise returns 'INVALID_STATE' completion code
        if self.internal.get_fd_state().await != FirmwareDeviceState::LearnComponents {
            return generate_failure_response(
                payload,
                FwUpdateCompletionCode::InvalidStateForCommand as u8,
            );
        }

        // Set timestamp for FD T1 timeout
        self.set_fd_t1_ts().await;

        // Decode the request message
        let req = PassComponentTableRequest::decode(payload).map_err(MsgHandlerError::Codec)?;
        let transfer_flag = match TransferRespFlag::try_from(req.fixed.transfer_flag) {
            Ok(flag) => flag,
            Err(_) => {
                return generate_failure_response(
                    payload,
                    PldmBaseCompletionCode::InvalidData as u8,
                )
            }
        };

        // Construct temporary storage for the component
        let pass_comp = FirmwareComponent::new(
            req.fixed.comp_classification,
            req.fixed.comp_identifier,
            req.fixed.comp_classification_index,
            req.fixed.comp_comparison_stamp,
            PldmFirmwareString {
                str_type: req.fixed.comp_ver_str_type,
                str_len: req.fixed.comp_ver_str_len,
                str_data: req.comp_ver_str,
            },
            None,
            None,
        );

        let mut firmware_params = FirmwareParameters::default();
        self.ops
            .get_firmware_parms(&mut firmware_params)
            .await
            .map_err(MsgHandlerError::FdOps)?;

        let comp_resp_code = self
            .ops
            .handle_component(
                &pass_comp,
                &firmware_params,
                ComponentOperation::PassComponent,
            )
            .await
            .map_err(MsgHandlerError::FdOps)?;

        // Construct response
        let resp = PassComponentTableResponse::new(
            req.fixed.hdr.instance_id(),
            PldmBaseCompletionCode::Success as u8,
            if comp_resp_code == ComponentResponseCode::CompCanBeUpdated {
                ComponentResponse::CompCanBeUpdated
            } else {
                ComponentResponse::CompCannotBeUpdated
            },
            comp_resp_code,
        );

        match resp.encode(payload) {
            Ok(bytes) => {
                // Move FD state to 'ReadyTransfer' when the last component is passed
                if transfer_flag == TransferRespFlag::End
                    || transfer_flag == TransferRespFlag::StartAndEnd
                {
                    self.internal
                        .set_fd_state(FirmwareDeviceState::ReadyXfer)
                        .await;
                }
                Ok(bytes)
            }
            Err(_) => {
                generate_failure_response(payload, PldmBaseCompletionCode::InvalidLength as u8)
            }
        }
    }

    pub async fn update_component_rsp(&self, payload: &mut [u8]) -> Result<usize, MsgHandlerError> {
        // Check if FD is in 'ReadyTransfer' state. Otherwise returns 'INVALID_STATE' completion code
        if self.internal.get_fd_state().await != FirmwareDeviceState::ReadyXfer {
            return generate_failure_response(
                payload,
                FwUpdateCompletionCode::InvalidStateForCommand as u8,
            );
        }

        // Set timestamp for FD T1 timeout
        self.set_fd_t1_ts().await;

        // Decode the request message
        let req = UpdateComponentRequest::decode(payload).map_err(MsgHandlerError::Codec)?;

        // Construct temporary storage for the component
        let update_comp = FirmwareComponent::new(
            req.fixed.comp_classification,
            req.fixed.comp_identifier,
            req.fixed.comp_classification_index,
            req.fixed.comp_comparison_stamp,
            PldmFirmwareString {
                str_type: req.fixed.comp_ver_str_type,
                str_len: req.fixed.comp_ver_str_len,
                str_data: req.comp_ver_str,
            },
            Some(req.fixed.comp_image_size),
            Some(UpdateOptionFlags(req.fixed.update_option_flags)),
        );

        // Store the component info into the internal state.
        self.internal.set_component(&update_comp).await;

        // Adjust the update flags based on the device's capabilities if needed. Currently, the flags are set as received from the UA.
        self.internal
            .set_update_flags(UpdateOptionFlags(req.fixed.update_option_flags))
            .await;

        let mut firmware_params = FirmwareParameters::default();
        self.ops
            .get_firmware_parms(&mut firmware_params)
            .await
            .map_err(MsgHandlerError::FdOps)?;

        let comp_resp_code = self
            .ops
            .handle_component(
                &update_comp,
                &firmware_params,
                ComponentOperation::UpdateComponent, /* This indicates this is an update request */
            )
            .await
            .map_err(MsgHandlerError::FdOps)?;

        // Construct response
        let resp = UpdateComponentResponse::new(
            req.fixed.hdr.instance_id(),
            PldmBaseCompletionCode::Success as u8,
            if comp_resp_code == ComponentResponseCode::CompCanBeUpdated {
                ComponentCompatibilityResponse::CompCanBeUpdated
            } else {
                ComponentCompatibilityResponse::CompCannotBeUpdated
            },
            ComponentCompatibilityResponseCode::try_from(comp_resp_code as u8).unwrap(),
            UpdateOptionFlags(req.fixed.update_option_flags),
            0,
            None,
        );

        match resp.encode(payload) {
            Ok(bytes) => {
                if comp_resp_code == ComponentResponseCode::CompCanBeUpdated {
                    // Set up the req for download.
                    self.internal
                        .set_fd_req(FdReqState::Ready, false, None, None, None, None)
                        .await;
                    // Move FD state machine to download state.
                    self.internal
                        .set_fd_state(FirmwareDeviceState::Download)
                        .await;
                }
                Ok(bytes)
            }
            Err(_) => {
                generate_failure_response(payload, PldmBaseCompletionCode::InvalidLength as u8)
            }
        }
    }

    pub async fn set_fd_t1_ts(&self) {
        self.internal
            .set_fd_t1_update_ts(self.ops.now().await)
            .await;
    }

    pub async fn fd_progress(&self, payload: &mut [u8]) -> Result<usize, MsgHandlerError> {
        // Get fd state
        let fd_state = self.internal.get_fd_state().await;

        let ret = match fd_state {
            FirmwareDeviceState::Download => self.fd_progress_download(payload).await,
            FirmwareDeviceState::Verify => self.pldm_fd_progress_verify(payload).await,
            FirmwareDeviceState::Apply => self.pldm_fd_progress_apply(payload).await,
            _ => {
                //writeln!(Console::<S>::writer(), "[xs debug]fd_progress: Invalid state").unwrap();
                return Err(MsgHandlerError::FdInitiatorModeError);
            }
        };

        // Cancel update if expected UA message isn't received within timeout
        let ua_timeout_check = match fd_state {
            FirmwareDeviceState::Download
            | FirmwareDeviceState::Verify
            | FirmwareDeviceState::Apply => {
                self.internal.get_fd_req().await.state == FdReqState::Sent
            }
            FirmwareDeviceState::Idle => false,
            _ => true,
        };

        if ua_timeout_check
            && self.ops.now().await - self.internal.get_fd_t1_update_ts().await
                > self.internal.get_fd_t1_timeout().await
        {
            //TODO: Implement the cancel component and idle timeout logic

            // pldm_fd_maybe_cancel_component(fd);
            // pldm_fd_idle_timeout(fd);
            return Ok(0);
        }

        ret
    }

    pub async fn handle_response(&self, _payload: &mut [u8]) -> Result<usize, MsgHandlerError> {
        // responder mode request

        Ok(0)
    }

    async fn fd_progress_download(&self, payload: &mut [u8]) -> Result<usize, MsgHandlerError> {
        let mut cw = Console::<S>::writer(); // Debug usage
        writeln!(cw, "[xs debug]fd_progress_download start").unwrap();
        let instance_id = 1;
        let offset = 0;
        let length = 32;
        let request_fw_data_req =
            RequestFirmwareDataRequest::new(instance_id, PldmMsgType::Request, offset, length);

        // Encode the request into payload
        let msg_len = request_fw_data_req
            .encode(payload)
            .map_err(MsgHandlerError::Codec)?;

        Ok(msg_len)
    }

    async fn pldm_fd_progress_verify(&self, _payload: &mut [u8]) -> Result<usize, MsgHandlerError> {
        Ok(0)
    }

    async fn pldm_fd_progress_apply(&self, _payload: &mut [u8]) -> Result<usize, MsgHandlerError> {
        Ok(0)
    }
}
