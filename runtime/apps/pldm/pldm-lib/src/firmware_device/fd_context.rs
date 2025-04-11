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
use pldm_common::message::firmware_update::transfer_complete::{
    TransferCompleteRequest, TransferResult,
};
use pldm_common::message::firmware_update::update_component::{
    UpdateComponentRequest, UpdateComponentResponse,
};

use pldm_common::message::firmware_update::request_fw_data::{
    RequestFirmwareDataRequest, RequestFirmwareDataResponseFixed,
};

use pldm_common::codec::PldmCodecError; // Added import for PldmCodecError
use pldm_common::protocol::base::{
    PldmBaseCompletionCode, PldmMsgHeader, PldmMsgType, TransferRespFlag,
};
use pldm_common::protocol::firmware_update::{
    ComponentCompatibilityResponse, ComponentCompatibilityResponseCode, ComponentResponse,
    ComponentResponseCode, Descriptor, FirmwareDeviceState, FwUpdateCmd, FwUpdateCompletionCode,
    PldmFirmwareString, UpdateOptionFlags, MAX_DESCRIPTORS_COUNT, PLDM_FWUP_BASELINE_TRANSFER_SIZE,
};
use pldm_common::util::fw_component::FirmwareComponent;

// Debug usage
use core::fmt::Write;
use libtock_console::Console;

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

    pub async fn is_start_initiator_mode(&self) -> bool {
        self.internal.get_fd_state().await == FirmwareDeviceState::Download
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
                self.internal.get_fd_req_state().await == FdReqState::Sent
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

    pub async fn handle_response(&self, payload: &mut [u8]) -> Result<(), MsgHandlerError> {
        // responder mode request
        let rsp_header: PldmMsgHeader<[u8; 3]> =
            PldmMsgHeader::decode(payload).map_err(MsgHandlerError::Codec)?;
        let cmd_code = rsp_header.cmd_code();
        let instance_id = rsp_header.instance_id();

        let fd_req = self.internal.get_fd_req().await;

        if fd_req.state != FdReqState::Sent
            || fd_req.instance_id != Some(instance_id)
            || fd_req.command != Some(cmd_code)
        {
            // No response was expected
            return Err(MsgHandlerError::FdInitiatorModeError);
        }

        let timestamp = self.ops.now().await;
        self.internal.set_fd_t1_update_ts(timestamp).await;

        match FwUpdateCmd::try_from(cmd_code) {
            Ok(FwUpdateCmd::RequestFirmwareData) => self.process_request_fw_data_rsp(payload).await,
            // Add more response handler here
            _ => Err(MsgHandlerError::FdInitiatorModeError),
        }
    }

    /* Reference code: Handle response

    LIBPLDM_CC_NONNULL
    static int pldm_fd_handle_fwdata_resp(struct pldm_fd *fd,
                          const struct pldm_msg *resp,
                          size_t resp_payload_len)
    {
        struct pldm_fd_download *dl;
        uint32_t fwdata_size;
        uint8_t res;

        if (fd->state != PLDM_FD_STATE_DOWNLOAD) {
            return -EPROTO;
        }

        if (fd->req.state != PLDM_FD_REQ_SENT) {
            /* Not waiting for a response, ignore it */
            return -EPROTO;
        }

        dl = &fd->specific.download;
        if (fd->req.complete) {
            /* Received data after completion */
            return -EPROTO;
        }

        switch (resp->payload[0]) {
        case PLDM_SUCCESS:
            break;
        case PLDM_FWUP_RETRY_REQUEST_FW_DATA:
            /* Just return, let the retry timer send another request later */
            return 0;
        default:
            /* Send a TransferComplete failure */
            fd->req.state = PLDM_FD_REQ_READY;
            fd->req.complete = true;
            fd->req.result = PLDM_FWUP_FD_ABORTED_TRANSFER;
            return 0;
        }

        /* Handle the received data */

        fwdata_size = pldm_fd_fwdata_size(fd);
        if (resp_payload_len != fwdata_size + 1) {
            /* Data is incorrect size. Could indicate MCTP corruption, drop it
             * and let retry timer handle it */
            return -EOVERFLOW;
        }

        /* Check pldm_fd_fwdata_size calculation, should not fail */
        if (dl->offset + fwdata_size < dl->offset ||
            dl->offset + fwdata_size > fd->update_comp.comp_image_size) {
            assert(false);
            return -EINVAL;
        }

        /* Provide the data chunk to the device */
        res = fd->ops->firmware_data(fd->ops_ctx, dl->offset, &resp->payload[1],
                         fwdata_size, &fd->update_comp);

        fd->req.state = PLDM_FD_REQ_READY;
        if (res == PLDM_FWUP_TRANSFER_SUCCESS) {
            /* Move to next offset */
            dl->offset += fwdata_size;
            if (dl->offset == fd->update_comp.comp_image_size) {
                /* Mark as complete, next progress() call will send the TransferComplete request */
                fd->req.complete = true;
                fd->req.result = PLDM_FWUP_TRANSFER_SUCCESS;
            }
        } else {
            /* Pass the callback error as the TransferResult */
            fd->req.complete = true;
            fd->req.result = res;
        }

        return 0;
    }

         */
    async fn process_request_fw_data_rsp(&self, payload: &mut [u8]) -> Result<(), MsgHandlerError> {
        let mut cw = Console::<S>::writer(); // Debug usage
        writeln!(cw, "[xs debug]process_request_fw_data_rsp start").unwrap();

        // Get fd device state
        let fd_state = self.internal.get_fd_state().await;
        if fd_state != FirmwareDeviceState::Download {
            return Err(MsgHandlerError::FdInitiatorModeError);
        }

        let fd_req = self.internal.get_fd_req().await;
        if fd_req.complete {
            // Received data after completion
            return Err(MsgHandlerError::FdInitiatorModeError);
        }

        // Decode the response message fixed
        let fw_data_rsp_fixed: RequestFirmwareDataResponseFixed =
            RequestFirmwareDataResponseFixed::decode(payload).map_err(MsgHandlerError::Codec)?;

        let completion_code = fw_data_rsp_fixed.completion_code;
        if completion_code == PldmBaseCompletionCode::Success as u8 {
            // Success case, do nothing
        } else if completion_code == FwUpdateCompletionCode::RetryRequestFwData as u8 {
            // Just return, let the retry timer send another request later
            return Ok(());
        } else {
            // Send a TransferComplete failure
            self.internal
                .set_fd_req(
                    FdReqState::Ready,
                    true,
                    Some(TransferResult::FdAbortedTransfer as u8),
                    None,
                    None,
                    None,
                )
                .await;
            return Ok(());
        }

        // Handle the received data
        let (dl_offset, dl_length) = self.internal.get_fd_dowload_info().await.unwrap();

        // Retrieve fw data from the payload buffer
        let data_offset = core::mem::size_of::<RequestFirmwareDataResponseFixed>();
        if data_offset + dl_length as usize > payload.len() {
            return Err(MsgHandlerError::Codec(PldmCodecError::BufferTooShort));
        }

        let data: &[u8] = &payload[data_offset..data_offset + dl_length as usize];
        let res = self
            .ops
            .download_fw_data(
                dl_offset as usize,
                data,
                &self.internal.get_component().await,
            )
            .await
            .map_err(MsgHandlerError::FdOps)?;


        /*
            if (res == PLDM_FWUP_TRANSFER_SUCCESS) {
            /* Move to next offset */
            dl->offset += fwdata_size;
            if (dl->offset == fd->update_comp.comp_image_size) {
                /* Mark as complete, next progress() call will send the TransferComplete request */
                fd->req.complete = true;
                fd->req.result = PLDM_FWUP_TRANSFER_SUCCESS;
            }
        } else {
            /* Pass the callback error as the TransferResult */
            fd->req.complete = true;
            fd->req.result = res;
        }

         */
        if res == TransferResult::TransferSuccess {
            let dl_offset = dl_offset + dl_length;
            // Move to next offset
            self.internal
                .set_fd_dl_offset(dl_offset)
                .await;

            if dl_offset == self.internal.get_component().await.comp_image_size.unwrap() {
                // Mark as complete, next progress() call will send the TransferComplete request
                self.internal
                    .set_fd_req(FdReqState::Ready, true, Some(TransferResult::TransferSuccess as u8), None, None, None)
                    .await;
            }
        } else {
            // Pass the callback error as the TransferResult
            self.internal
                .set_fd_req(FdReqState::Ready, true, Some(res as u8), None, None, None)
                .await;
        }
        writeln!(cw, "[xs debug]process_request_fw_data_rsp end").unwrap();

        Ok(())
    }

    async fn fd_progress_download(&self, payload: &mut [u8]) -> Result<usize, MsgHandlerError> {
        let mut cw = Console::<S>::writer(); // Debug usage
        writeln!(cw, "[xs debug]fd_progress_download start").unwrap();

        // Check if the request is ready to send
        if !self.should_send_fd_request().await {
            return Err(MsgHandlerError::FdInitiatorModeError);
        }

        // Allocate the next instance ID
        let instance_id = self.internal.alloc_next_instance_id().await.unwrap();
        let mut msg_len = 0;

        // If the request is complete, send TransferComplete
        if self.internal.is_fd_req_complete().await {
            let result = self
                .internal
                .get_fd_req_result()
                .await
                .ok_or(MsgHandlerError::FdInitiatorModeError)?;

            msg_len = TransferCompleteRequest::new(
                instance_id,
                PldmMsgType::Request,
                TransferResult::try_from(result).unwrap(),
            )
            .encode(payload)
            .map_err(MsgHandlerError::Codec)?;

            // Set fd req state to sent
            let req_sent_timestamp = self.ops.now().await;
            self.internal
                .set_fd_req(
                    FdReqState::Sent,
                    false,
                    None,
                    Some(instance_id),
                    Some(FwUpdateCmd::TransferComplete as u8),
                    Some(req_sent_timestamp),
                )
                .await;

            writeln!(
                cw,
                "[xs debug]fd_progress_download: issuing transfer complete"
            )
            .unwrap();
        } else {
            if let Some((offset, length)) = self.internal.get_fd_dowload_info().await {
                msg_len = RequestFirmwareDataRequest::new(
                    instance_id,
                    PldmMsgType::Request,
                    offset,
                    length,
                )
                .encode(payload)
                .map_err(MsgHandlerError::Codec)?;

                // Set fd req state to sent
                let req_sent_timestamp = self.ops.now().await;
                self.internal
                    .set_fd_req(
                        FdReqState::Sent,
                        false,
                        None,
                        Some(instance_id),
                        Some(FwUpdateCmd::RequestFirmwareData as u8),
                        Some(req_sent_timestamp),
                    )
                    .await;

                writeln!(cw, "[xs debug]fd_progress_download: requesting fw data: offset={:02x}, length = {:02x}", offset, length).unwrap();
            } else {
                return Err(MsgHandlerError::FdInitiatorModeError);
            }
        }

        Ok(msg_len)
    }

    async fn pldm_fd_progress_verify(&self, _payload: &mut [u8]) -> Result<usize, MsgHandlerError> {
        Ok(0)
    }

    async fn pldm_fd_progress_apply(&self, _payload: &mut [u8]) -> Result<usize, MsgHandlerError> {
        Ok(0)
    }

    async fn should_send_fd_request(&self) -> bool {
        let now = self.ops.now().await;

        let fd_req_state = self.internal.get_fd_req_state().await;
        match fd_req_state {
            FdReqState::Unused => false,
            FdReqState::Ready => true,
            FdReqState::Failed => false,
            FdReqState::Sent => {
                let fd_req_sent_time = self.internal.get_fd_sent_time().await.unwrap();
                if now < fd_req_sent_time {
                    // Time went backwards
                    return false;
                }

                // Send if retry time has elapsed
                return (now - fd_req_sent_time) >= self.internal.get_fd_t2_retry_time().await;
            }
        }
    }
}
