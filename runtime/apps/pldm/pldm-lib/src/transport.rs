// Licensed under the Apache-2.0 license

use libsyscall_caliptra::mctp::{Mctp, MessageInfo};
use libtock_platform::Syscalls;
use pldm_common::util::mctp_transport::{
    MctpCommonHeader, MCTP_COMMON_HEADER_OFFSET, MCTP_PLDM_MSG_TYPE,
};

use libtock_console::Console;
//use libtock_console::ConsoleWriter;
use core::fmt::Write;


pub enum PldmTransportType {
    Mctp,
}

#[derive(Debug)]
pub enum TransportError {
    DriverError,
    BufferTooSmall,
    UnexpectedMessageType,
    ReceiveError,
    SendError,
    ResponseNotExpected,
    NoRequestInFlight,
}

pub struct MctpTransport<S: Syscalls> {
    mctp: Mctp<S>,
    cur_resp_ctx: Option<MessageInfo>,
    cur_req_ctx: Option<u8>,
}

impl<S: Syscalls> MctpTransport<S> {
    pub fn new(drv_num: u32) -> Self {
        Self {
            mctp: Mctp::<S>::new(drv_num),
            cur_resp_ctx: None,
            cur_req_ctx: None,
        }
    }

    pub async fn send_request<'a>(
        &mut self,
        dest_eid: u8,
        req: &'a [u8],
    ) -> Result<(), TransportError> {
        let mctp_hdr = MctpCommonHeader(req[MCTP_COMMON_HEADER_OFFSET]);
        if mctp_hdr.ic() != 0 || mctp_hdr.msg_type() != MCTP_PLDM_MSG_TYPE {
            Err(TransportError::UnexpectedMessageType)?;
        }

        let tag = self
            .mctp
            .send_request(dest_eid, req)
            .await
            .map_err(|_| TransportError::SendError)?;

        self.cur_req_ctx = Some(tag);

        Ok(())
    }

    pub async fn receive_response<'a>(&mut self, rsp: &'a mut [u8]) -> Result<(), TransportError> {
        // Reset msg buffer
        rsp.fill(0);

        writeln!(Console::<S>::writer(), "[xs debug]pldm_mctp_transport: receive response start").unwrap();

        let (rsp_len, _msg_info) = if let Some(tag) = self.cur_req_ctx {
            self.mctp
                .receive_response(rsp, tag)
                .await
                .map_err(|_| TransportError::ReceiveError)
        } else {
            writeln!(Console::<S>::writer(), "[xs debug]pldm_mctp_transport ERROR: ResponseNoteExpected").unwrap();
            Err(TransportError::ResponseNotExpected)
        }?;

        writeln!(Console::<S>::writer(), "[xs debug]pldm_mctp_transport: receive response: :rsp_len = {}", rsp_len).unwrap();

        if rsp_len == 0 {
            Err(TransportError::BufferTooSmall)?;
        }

        // Check common header
        let mctp_hdr = MctpCommonHeader(rsp[MCTP_COMMON_HEADER_OFFSET]);
        if mctp_hdr.ic() != 0 || mctp_hdr.msg_type() != MCTP_PLDM_MSG_TYPE {
            Err(TransportError::UnexpectedMessageType)?;
        }

        self.cur_req_ctx = None;
        Ok(())
    }

    pub async fn receive_request<'a>(&mut self, req: &'a mut [u8]) -> Result<(), TransportError> {
        // Reset msg buffer
        req.fill(0);
        let (req_len, msg_info) = self
            .mctp
            .receive_request(req)
            .await
            .map_err(|_| TransportError::ReceiveError)?;

        if req_len == 0 {
            Err(TransportError::BufferTooSmall)?;
        }

        // Check common header
        let mctp_hdr = MctpCommonHeader(req[MCTP_COMMON_HEADER_OFFSET]);
        if mctp_hdr.ic() != 0 || mctp_hdr.msg_type() != MCTP_PLDM_MSG_TYPE {
            Err(TransportError::UnexpectedMessageType)?;
        }

        self.cur_resp_ctx = Some(msg_info);

        Ok(())
    }

    pub async fn send_response<'a>(&mut self, resp: &'a [u8]) -> Result<(), TransportError> {
        let mctp_hdr = MctpCommonHeader(resp[MCTP_COMMON_HEADER_OFFSET]);
        if mctp_hdr.ic() != 0 || mctp_hdr.msg_type() != MCTP_PLDM_MSG_TYPE {
            Err(TransportError::UnexpectedMessageType)?;
        }

        if let Some(msg_info) = self.cur_resp_ctx.clone() {
            self.mctp
                .send_response(resp, msg_info)
                .await
                .map_err(|_| TransportError::SendError)?
        } else {
            Err(TransportError::NoRequestInFlight)?;
        }

        self.cur_resp_ctx = None;

        Ok(())
    }
}
