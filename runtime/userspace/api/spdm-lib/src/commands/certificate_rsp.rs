// Licensed under the Apache-2.0 license

use crate::codec::{Codec, CodecError, CodecResult, CommonCodec, DataKind, MessageBuf};
use crate::commands::error_rsp::ErrorCode;
// use crate::config::MAX_SPDM_CERT_PORTION_LEN;
use crate::cert_store::{CertChain, SpdmCertStore, SPDM_MAX_CERT_CHAIN_PORTION_LEN};
use crate::context::SpdmContext;
use crate::error::{CommandError, CommandResult, SpdmError, SpdmResult};
use crate::protocol::common::SpdmMsgHdr;
use crate::protocol::version::SpdmVersion;
use crate::protocol::SPDM_MAX_CERT_SLOTS;
use crate::state::ConnectionState;
use bitfield::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes};

const GET_CERTIFICATE_REQUEST_ATTRIBUTES_SLOT_SIZE_REQUESTED: u8 = 0x01;

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
pub struct GetCertificateReq {
    pub slot_id: SlotId,
    pub param2: CertificateReqAttributes,
    pub offset: u16,
    pub length: u16,
}

bitfield! {
    #[derive(FromBytes, IntoBytes, Immutable)]
    #[repr(C)]
    pub struct SlotId(u8);
    impl Debug;
    u8;
    pub slot_id, set_slot_id: 3,0;
    reserved, _: 7,4;
}

bitfield! {
    #[derive(FromBytes, IntoBytes, Immutable)]
    #[repr(C)]
    pub struct CertificateReqAttributes(u8);
    impl Debug;
    u8;
    pub slot_size_requested, set_slot_size_requested: 0,0;
    reserved, _: 7,1;
}

// impl GetCertificateReq {
//     pub fn new(slot_id: SlotId, param2: CertificateReqAttributes, offset: u16, length: u16) -> Self {
//         Self {
//             slot_id,
//             param2,
//             offset,
//             length,
//         }
//     }
// }

impl CommonCodec for GetCertificateReq {
    const DATA_KIND: DataKind = DataKind::Payload;
}

#[derive(IntoBytes, FromBytes, Immutable)]
#[repr(packed)]
pub struct CertificateRespCommon {
    pub slot_id: SlotId,
    pub param2: CertificateRespAttributes,
    pub portion_length: u16,
    pub remainder_length: u16,
}

impl CommonCodec for CertificateRespCommon {
    const DATA_KIND: DataKind = DataKind::Payload;
}

impl CertificateRespCommon {
    pub fn new(
        slot_id: SlotId,
        param2: CertificateRespAttributes,
        portion_length: u16,
        remainder_length: u16,
    ) -> Self {
        Self {
            slot_id,
            param2,
            portion_length,
            remainder_length,
        }
    }
}

bitfield! {
    #[derive(FromBytes, IntoBytes, Immutable)]
    #[repr(C)]
    pub struct CertificateRespAttributes(u8);
    impl Debug;
    u8;
    pub certificate_info, set_certificate_info: 2,0;
    reserved, _: 7,3;
}

impl Default for CertificateRespAttributes {
    fn default() -> Self {
        Self(0)
    }
}

// pub struct GetCertificateResp<'a> {
//     pub common: CertificateRespCommon,
//     pub cert_chain_portion: &'a [u8],
// }

// impl<'a> GetCertificateResp<'a> {
//     pub fn new(
//         slot_id: SlotId,
//         param2: CertificateRespAttributes,
//         cert_chain_portion: &'a [u8],
//         remainder_length: u16,
//     ) -> SpdmResult<Self> {
//         if cert_chain_portion.len() > MAX_SPDM_CERT_PORTION_LEN {
//             return Err(SpdmError::InvalidParam);
//         }

//         let common = CertificateRespCommon {
//             slot_id,
//             param2,
//             portion_length: cert_chain_portion.len() as u16,
//             remainder_length,
//         };
//         Ok(Self {
//             common,
//             cert_chain_portion,
//         })
//     }
// }

// impl<'a> Codec for GetCertificateResp<'a> {
//     fn encode(&self, buffer: &mut MessageBuf) -> CodecResult<usize> {
//         let mut len = 0;
//         len += self.common.encode(buffer)?;

//         let portion_length =
//             (self.common.portion_length as usize).min(self.cert_chain_portion.len());
//         buffer.put_data(portion_length)?;

//         let payload = buffer.data_mut(portion_length)?;
//         self.cert_chain_portion[..portion_length]
//             .write_to(payload)
//             .map_err(|_| CodecError::WriteError)?;

//         buffer.pull_data(portion_length)?;
//         len += portion_length;

//         Ok(len)
//     }

//     fn decode(_data: &mut MessageBuf) -> CodecResult<Self> {
//         // Decoding is not required for SPDM responder
//         unimplemented!()
//     }
// }

pub(crate) async fn handle_certificates<'a>(
    ctx: &mut SpdmContext<'a>,
    spdm_hdr: SpdmMsgHdr,
    req_payload: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    // Validate the state
    if ctx.state.connection_info.state() < ConnectionState::AlgorithmsNegotiated {
        Err(ctx.generate_error_response(req_payload, ErrorCode::UnexpectedRequest, 0, None))?;
    }

    // Validate the version
    let connection_version = ctx.state.connection_info.version_number();
    if spdm_hdr.version().ok() != Some(connection_version) {
        Err(ctx.generate_error_response(req_payload, ErrorCode::VersionMismatch, 0, None))?;
    }

    // Check if the certificate capability is supported.
    if ctx.local_capabilities.flags.cert_cap() == 0 {
        Err(ctx.generate_error_response(req_payload, ErrorCode::UnsupportedRequest, 0, None))?;
    }

    let req = GetCertificateReq::decode(req_payload).map_err(|_| {
        ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None)
    })?;

    let slot_id = req.slot_id.slot_id();
    if slot_id >= SPDM_MAX_CERT_SLOTS as u8 {
        return Err(ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None));
    }

    // Check if the slot is provisioned. Otherwise, return an InvalidRequest error.
    let slot_mask = 1 << slot_id;
    let (_, provisioned_slot_mask) = ctx.device_certs_store.cert_slot_mask();

    if provisioned_slot_mask & slot_mask == 0
        || ctx.device_certs_store.cert_chain[slot_id as usize].is_none()
    {
        return Err(ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None));
    }

    let hash_type = ctx
        .selected_hash_algo()
        .map_err(|_| ctx.generate_error_response(req_payload, ErrorCode::Unspecified, 0, None))?;

    let mut offset = req.offset;
    let mut length = req.length;

    // When SlotSizeRequested=1b in the GET_CERTIFICATE request, the Responder shall return
    // the number of bytes available for certificate chain storage in the RemainderLength field of the response.
    if connection_version >= SpdmVersion::V13 && req.param2.slot_size_requested() != 0 {
        offset = 0;
        length = 0;
    }

    // Prepare response buffer
    ctx.prepare_response_buffer(req_payload)?;

    // Fill the response with the certificate chain portion
    fill_certificate_response(
        ctx,
        connection_version,
        slot_id,
        offset,
        length,
        req_payload,
    )
    .await?;

    // TODO: transcript manager and session support

    // Set the connection state to AfterCertificate
    if ctx.state.connection_info.state() < ConnectionState::AfterCertificate {
        ctx.state
            .connection_info
            .set_state(ConnectionState::AfterCertificate);
    }

    Ok(())
}

async fn fill_certificate_response<'a>(
    ctx: &mut SpdmContext<'a>,
    connection_version: SpdmVersion,
    slot_id: u8,
    offset: u16,
    length: u16,
    rsp: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    let mut resp_attr = CertificateRespAttributes::default();
    if connection_version >= SpdmVersion::V13 && ctx.state.connection_info.multi_key_conn_rsp() {
        if let Some(cert_chain) = ctx.device_certs_store.cert_chain[slot_id as usize].as_mut() {
            let cert_model = cert_chain.cert_info().unwrap_or_default().cert_model();
            resp_attr.set_certificate_info(cert_model);
        }
    }

    let hash_algo_sel = ctx
        .selected_hash_algo()
        .map_err(|_| ctx.generate_error_response(rsp, ErrorCode::Unspecified, 0, None))?;

    let mut remainder_len = ctx
        .device_certs_store
        .remainder_cert_chain_len(hash_algo_sel, slot_id, offset)
        .await
        .map_err(|_| ctx.generate_error_response(rsp, ErrorCode::InvalidRequest, 0, None))?;

    let portion_len = if length > SPDM_MAX_CERT_CHAIN_PORTION_LEN as u16
        && ctx.local_capabilities.flags.chunk_cap() == 0
    {
        (SPDM_MAX_CERT_CHAIN_PORTION_LEN as u16).min(remainder_len)
    } else {
        length
    };

    remainder_len = remainder_len.saturating_sub(portion_len);

    let slot_id_struct = SlotId(slot_id);

    let certificate_rsp_common =
        CertificateRespCommon::new(slot_id_struct, resp_attr, portion_len, remainder_len);

    certificate_rsp_common
        .encode(rsp)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    if portion_len > 0 {
        rsp.put_data(portion_len as usize)
            .map_err(|e| (false, CommandError::Codec(e)))?;
    }

    let cert_chain_buf = rsp
        .data_mut(portion_len as usize)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    ctx.device_certs_store
        .read_cert_chain(slot_id, hash_algo_sel, offset as usize, cert_chain_buf)
        .await
        .map_err(|e| (false, CommandError::CertStore(e)))?;

    Ok(())
}

// async fn fill_certificate_response(
//     ctx: &SpdmContext,
//     slot_id: u8,
//     param2: u8,
//     cert_chain_portion: &[u8],
//     remainder_length: u16,
//     rsp: &mut MessageBuf,
// ) -> CommandResult<()> {
//     // Construct the response
//     let resp = GetCertificateResp::new(slot_id, param2, cert_chain_portion, remainder_length)
//         .map_err(|_| (false, CommandError::BufferTooSmall))?;
//     let payload_len = resp
//         .encode(rsp)
//         .map_err(|_| ctx.generate_error_response(rsp, ErrorCode::InvalidRequest, 0, None))?;

//     // Push data offset up by total payload length
//     rsp.push_data(payload_len)
//         .map_err(|_| (false, CommandError::BufferTooSmall))?;

//     Ok(())
// }

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn test_encode_get_cert_chain_resp() {
//         let cert_chain_portion = [0xaau8; MAX_SPDM_CERT_PORTION_LEN];
//         let remainder_length = 0;
//         let slot_id = 0;

//         let resp =
//             GetCertificateResp::new(slot_id, 0, &cert_chain_portion, remainder_length).unwrap();
//         let mut bytes = [0u8; 1024];
//         let mut buffer = MessageBuf::new(&mut bytes);
//         let encoded_len = resp.encode(&mut buffer).unwrap();

//         assert_eq!(
//             encoded_len,
//             core::mem::size_of::<CertificateRespCommon>() + cert_chain_portion.len() as usize
//         );
//         assert_eq!(encoded_len, buffer.msg_len());
//         assert_eq!(encoded_len, buffer.data_offset());

//         // Verify the encoded data
//         assert_eq!(buffer.total_message()[0], resp.common.slot_id);
//         assert_eq!(buffer.total_message()[1], resp.common.param2);
//         assert_eq!(
//             buffer.total_message()[2..4],
//             resp.common.portion_length.to_le_bytes()
//         );
//         assert_eq!(
//             buffer.total_message()[4..6],
//             resp.common.remainder_length.to_le_bytes()
//         );
//         assert_eq!(
//             buffer.total_message()[core::mem::size_of::<CertificateRespCommon>()..],
//             cert_chain_portion
//         );
//     }
// }
