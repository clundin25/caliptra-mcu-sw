// Licensed under the Apache-2.0 license

use crate::error::PldmError;
use crate::protocol::base::{
    InstanceId, PldmMsgHeader, PldmMsgType, PldmSupportedType, PLDM_MSG_HEADER_LEN,
};
use crate::protocol::firmware_update::{ComponentActivationMethods, FwUpdateCmd};
use zerocopy::{FromBytes, Immutable, IntoBytes};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ApplyResult {
    ApplySuccess = 0x00,
    ApplySuccessWithActivationMethod = 0x01,
    ApplyFailureMemoryIssue = 0x02,
    //ApplyTimeOut = 0x09,
    //ApplyGenericError = 0x0a,
    VendorDefined,
}

impl TryFrom<u8> for ApplyResult {
    type Error = PldmError;

    fn try_from(value: u8) -> Result<Self, PldmError> {
        match value {
            0x00 => Ok(ApplyResult::ApplySuccess),
            0x01 => Ok(ApplyResult::ApplySuccessWithActivationMethod),
            0x02 => Ok(ApplyResult::ApplyFailureMemoryIssue),
            //0x09 => Ok(ApplyResult::ApplyTimeOut),
            //0x0a => Ok(ApplyResult::ApplyGenericError),
            0xb0..=0xcf => Ok(ApplyResult::VendorDefined),
            _ => Err(PldmError::InvalidApplyResult),
        }
    }
}

#[derive(Debug, Clone, FromBytes, IntoBytes, Immutable, PartialEq)]
#[repr(C, packed)]
pub struct ApplyCompleteRequest {
    pub hdr: PldmMsgHeader<[u8; PLDM_MSG_HEADER_LEN]>,
    pub apply_result: u8,
    pub comp_activation_methods_modification: u16,
}

impl ApplyCompleteRequest {
    pub fn new(
        instance_id: InstanceId,
        msg_type: PldmMsgType,
        apply_result: ApplyResult,
        comp_activation_methods: ComponentActivationMethods,
    ) -> Self {
        ApplyCompleteRequest {
            hdr: PldmMsgHeader::new(
                instance_id,
                msg_type,
                PldmSupportedType::FwUpdate,
                FwUpdateCmd::ApplyComplete as u8,
            ),
            apply_result: apply_result as u8,
            comp_activation_methods_modification: comp_activation_methods.0,
        }
    }
}

#[derive(Debug, Clone, FromBytes, IntoBytes, Immutable, PartialEq)]
#[repr(C, packed)]
pub struct ApplyCompleteResponse {
    pub hdr: PldmMsgHeader<[u8; PLDM_MSG_HEADER_LEN]>,
    pub completion_code: u8,
}

impl ApplyCompleteResponse {
    pub fn new(instance_id: InstanceId, completion_code: u8) -> ApplyCompleteResponse {
        ApplyCompleteResponse {
            hdr: PldmMsgHeader::new(
                instance_id,
                PldmMsgType::Response,
                PldmSupportedType::FwUpdate,
                FwUpdateCmd::ApplyComplete as u8,
            ),
            completion_code,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::PldmCodec;

    #[test]
    fn test_apply_complete_request() {
        let request = ApplyCompleteRequest::new(
            1,
            PldmMsgType::Request,
            ApplyResult::ApplySuccess,
            ComponentActivationMethods(0x0001),
        );

        let mut buffer = [0u8; 64];
        let bytes_written = request.encode(&mut buffer).unwrap();
        assert_eq!(bytes_written, core::mem::size_of::<ApplyCompleteRequest>());
        let decoded_request = ApplyCompleteRequest::decode(&buffer[..bytes_written]).unwrap();
        assert_eq!(request, decoded_request);
    }

    #[test]
    fn test_apply_complete_response() {
        let response = ApplyCompleteResponse::new(1, 0);
        let mut buffer = [0u8; 64];
        let bytes_written = response.encode(&mut buffer).unwrap();
        assert_eq!(bytes_written, core::mem::size_of::<ApplyCompleteResponse>());
        let decoded_response = ApplyCompleteResponse::decode(&buffer[..bytes_written]).unwrap();
        assert_eq!(response, decoded_response);
    }
}
