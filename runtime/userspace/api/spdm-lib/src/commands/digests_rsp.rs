// Licensed under the Apache-2.0 license

// use crate::cert_mgr::{SPDM_MAX_CERT_CHAIN_SLOTS, SPDM_MAX_HASH_SIZE};
use crate::codec::{Codec, CodecError, CodecResult, CommonCodec, DataKind, MessageBuf};
use crate::commands::error_rsp::ErrorCode;
use crate::context::SpdmContext;
use crate::error::{CommandError, CommandResult};
use crate::protocol::common::SpdmMsgHdr;
use crate::protocol::{
    CertificateInfo, KeyPairID, KeyUsageMask, ProvisionedSlotMask, SpdmVersion, SupportedSlotMask,
    SPDM_MAX_CERT_SLOTS,
};
use crate::state::ConnectionState;
use core::mem::{offset_of, size_of};
use libapi_caliptra::crypto::hash::HashAlgoType;
use zerocopy::{FromBytes, Immutable, IntoBytes};

#[derive(IntoBytes, FromBytes, Immutable, Default)]
#[repr(C)]
pub struct GetDigestsReq {
    param1: u8,
    param2: u8,
}

impl CommonCodec for GetDigestsReq {
    const DATA_KIND: DataKind = DataKind::Payload;
}

#[derive(IntoBytes, FromBytes, Immutable, Default)]
#[repr(C)]
pub struct GetDigestsRespCommon {
    pub supported_slot_mask: SupportedSlotMask, // param1: introduced in v13
    pub provisioned_slot_mask: ProvisionedSlotMask, // param2
}

impl CommonCodec for GetDigestsRespCommon {
    const DATA_KIND: DataKind = DataKind::Payload;
}

pub(crate) async fn handle_digests<'a>(
    ctx: &mut SpdmContext<'a>,
    spdm_hdr: SpdmMsgHdr,
    req_payload: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    // Validate the connection state
    if ctx.state.connection_info.state() < ConnectionState::AlgorithmsNegotiated {
        Err(ctx.generate_error_response(req_payload, ErrorCode::UnexpectedRequest, 0, None))?;
    }

    // Validate the version
    let connection_version = ctx.state.connection_info.version_number();
    match spdm_hdr.version() {
        Ok(version) if version == connection_version => {}
        _ => Err(ctx.generate_error_response(req_payload, ErrorCode::VersionMismatch, 0, None))?,
    }

    let req = GetDigestsReq::decode(req_payload).map_err(|_| {
        ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None)
    })?;

    // Reserved fields must be zero - or unexpected request error
    if req.param1 != 0 || req.param2 != 0 {
        Err(ctx.generate_error_response(req_payload, ErrorCode::UnexpectedRequest, 0, None))?;
    }

    // Check if the certificate capability is supported
    if ctx.local_capabilities.flags.cert_cap() == 0 {
        Err(ctx.generate_error_response(req_payload, ErrorCode::UnsupportedRequest, 0, None))?;
    }

    // TODO: transcript manager and session support

    // Prepare the response buffer
    ctx.prepare_response_buffer(req_payload)?;

    // Fill the response buffer
    fill_digests_response(ctx, connection_version, req_payload).await?;

    if ctx.state.connection_info.state() < ConnectionState::AfterDigest {
        ctx.state
            .connection_info
            .set_state(ConnectionState::AfterDigest);
    }

    Ok(())
}

async fn fill_digests_response<'a>(
    ctx: &mut SpdmContext<'a>,
    connection_version: SpdmVersion,
    rsp: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    let hash_algo_sel = ctx
        .selected_hash_algo()
        .map_err(|_| ctx.generate_error_response(rsp, ErrorCode::Unspecified, 0, None))?;

    // Get the supported and provisioned slot masks.
    let (supported_slot_mask, provisioned_slot_mask) = ctx.device_certs_store.cert_slot_mask();

    // No slots provisioned with certificates
    let slot_cnt = provisioned_slot_mask.count_ones() as usize;
    if slot_cnt == 0 {
        Err(ctx.generate_error_response(rsp, ErrorCode::Unspecified, 0, None))?;
    }

    let hash_algo: HashAlgoType = hash_algo_sel
        .try_into()
        .map_err(|_| ctx.generate_error_response(rsp, ErrorCode::Unspecified, 0, None))?;

    let hash_size = hash_algo.hash_size() as u8;

    let dgsts_size = slot_cnt * hash_size as usize;

    let mut exp_payload_len = 2 + dgsts_size;

    if connection_version >= SpdmVersion::V13 && ctx.state.connection_info.multi_key_conn_rsp() {
        let key_pair_ids_size = size_of::<KeyPairID>() * slot_cnt;
        let cert_infos_size = size_of::<CertificateInfo>() * slot_cnt;
        let key_usage_masks_size = size_of::<KeyUsageMask>() * slot_cnt;
        exp_payload_len += key_pair_ids_size + cert_infos_size + key_usage_masks_size;
    }

    let mut payload_len = 0;

    // Fill the response header with param1 and param2
    let dgst_rsp_common = GetDigestsRespCommon {
        supported_slot_mask,
        provisioned_slot_mask,
    };

    payload_len += dgst_rsp_common
        .encode(rsp)
        .map_err(|_| (false, CommandError::BufferTooSmall))?;

    // Make space for digests of all provisioned slots
    rsp.put_data(dgsts_size)
        .map_err(|_| (false, CommandError::BufferTooSmall))?;

    let dgsts_buf = rsp
        .data_mut(dgsts_size)
        .map_err(|_| (false, CommandError::BufferTooSmall))?;
    dgsts_buf.fill(0);

    let mut offset = 0;
    // Fill the digests in the increasing order of provisioned slot IDs
    for slot_id in 0..SPDM_MAX_CERT_SLOTS {
        if (provisioned_slot_mask & (1 << slot_id)) == 1
            && ctx.device_certs_store.cert_chain[slot_id].is_some()
        {
            let dgst_len_filled = ctx
                .device_certs_store
                .cert_chain_hash(slot_id as u8, hash_algo_sel, &mut dgsts_buf[offset..])
                .await
                .map_err(|e| (false, CommandError::CertStore(e)))?;

            if dgst_len_filled != hash_size as usize {
                Err((false, CommandError::Codec(CodecError::BufferOverflow)))?;
            }

            offset += dgst_len_filled
        }
    }

    rsp.pull_data(offset)
        .map_err(|e| (false, CommandError::Codec(e)))?;
    payload_len += offset;

    // Fill the multi-key connection response data if applicable
    if connection_version >= SpdmVersion::V13 && ctx.state.connection_info.multi_key_conn_rsp() {
        payload_len += fill_multi_key_conn_rsp_data(ctx, rsp)?;
    }

    // Push data offset up by total payload length
    rsp.push_data(payload_len)
        .map_err(|_| (false, CommandError::BufferTooSmall))?;

    if exp_payload_len != payload_len {
        Err(ctx.generate_error_response(rsp, ErrorCode::Unspecified, 0, None))?;
    }

    Ok(())
}

fn fill_multi_key_conn_rsp_data(
    ctx: &mut SpdmContext,
    rsp: &mut MessageBuf,
) -> CommandResult<usize> {
    let provisioned_slot_mask = ctx.device_certs_store.cert_slot_mask().1;
    let slot_cnt = provisioned_slot_mask.count_ones() as usize;

    let key_pair_ids_size = size_of::<KeyPairID>() * slot_cnt;
    let cert_infos_size = size_of::<CertificateInfo>() * slot_cnt;
    let key_usage_masks_size = size_of::<KeyUsageMask>() * slot_cnt;
    let total_size = key_pair_ids_size + cert_infos_size + key_usage_masks_size;

    rsp.put_data(total_size)
        .map_err(|_| (false, CommandError::BufferTooSmall))?;
    let data_buf = rsp
        .data_mut(total_size)
        .map_err(|_| (false, CommandError::BufferTooSmall))?;
    data_buf.fill(0);

    let (key_pair_buf, rest) = data_buf.split_at_mut(key_pair_ids_size);
    let (cert_info_buf, key_usage_mask_buf) = rest.split_at_mut(cert_infos_size);

    let mut key_pair_offset = 0;
    let mut key_usage_offset = 0;
    let mut cert_info_offset = 0;

    for slot_id in 0..SPDM_MAX_CERT_SLOTS {
        if (provisioned_slot_mask & (1 << slot_id)) == 1 {
            if let Some(slot_cert_chain) = &mut ctx.device_certs_store.cert_chain[slot_id] {
                let key_pair_id = slot_cert_chain.key_pair_id().unwrap_or_default();
                let cert_info = slot_cert_chain.cert_info().unwrap_or_default();
                let key_usage_mask = slot_cert_chain.key_usage_mask().unwrap_or_default();

                // Fill the KeyPairIDs
                key_pair_buf[key_pair_offset..key_pair_offset + size_of::<KeyPairID>()]
                    .copy_from_slice(key_pair_id.as_bytes());
                key_pair_offset += size_of::<KeyPairID>();

                // Fill the CertificateInfos
                cert_info_buf[cert_info_offset..cert_info_offset + size_of::<CertificateInfo>()]
                    .copy_from_slice(cert_info.as_bytes());
                cert_info_offset += size_of::<CertificateInfo>();

                // Fill the KeyUsageMasks
                key_usage_mask_buf[key_usage_offset..key_usage_offset + size_of::<KeyUsageMask>()]
                    .copy_from_slice(key_usage_mask.as_bytes());
                key_usage_offset += size_of::<KeyUsageMask>();
            }
        }
    }
    rsp.pull_data(total_size)
        .map_err(|_| (false, CommandError::BufferTooSmall))?;

    Ok(total_size)
}

// #[cfg(test)]
// mod test {
//     use super::*;

//     #[test]
//     fn test_get_encode_digests_response() {
//         let slot_mask = 0b00000011; // Two slots enabled
//         let digest1 = SpdmDigest::new(&[0xAA; SPDM_MAX_HASH_SIZE]);
//         let digest2 = SpdmDigest::new(&[0xBB; SPDM_MAX_HASH_SIZE]);
//         let digests = [digest1, digest2];

//         let resp = GetDigestsResp::new(slot_mask, slot_mask, &digests);
//         let mut bytes = [0u8; 1024];
//         let mut buffer = MessageBuf::new(&mut bytes);
//         let encode_result = resp.encode(&mut buffer);

//         assert!(encode_result.is_ok());
//         let encoded_len = encode_result.unwrap();
//         assert_eq!(encoded_len, buffer.msg_len());
//         assert_eq!(encoded_len, buffer.data_offset());

//         // Verify the encoded data
//         let expected_len = 2 + (SPDM_MAX_HASH_SIZE * 2);
//         assert_eq!(encoded_len, expected_len);

//         // Verify the contents in the message buffer
//         assert_eq!(buffer.total_message()[0], slot_mask); // param1
//         assert_eq!(buffer.total_message()[1], slot_mask); // slot_mask
//         assert_eq!(
//             buffer.total_message()[2..2 + SPDM_MAX_HASH_SIZE],
//             [0xAA; SPDM_MAX_HASH_SIZE]
//         ); // digest1
//         assert_eq!(
//             buffer.total_message()[2 + SPDM_MAX_HASH_SIZE..],
//             [0xBB; SPDM_MAX_HASH_SIZE]
//         ); // digest2
//     }
// }
