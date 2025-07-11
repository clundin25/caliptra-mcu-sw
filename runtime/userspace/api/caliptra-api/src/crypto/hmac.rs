// Licensed under the Apache-2.0 license

use crate::error::{CaliptraApiError, CaliptraApiResult};
use crate::mailbox_api::execute_mailbox_cmd;
use caliptra_api::mailbox::{CmHashAlgorithm, CmHmacReq, CmHmacResp, Cmk, Request};
use libsyscall_caliptra::mailbox::Mailbox;
use zerocopy::IntoBytes;

pub struct Hmac;

impl Hmac {
    pub async fn hmac(cmk: &Cmk, data: &[u8]) -> CaliptraApiResult<CmHmacResp> {
        let mailbox = Mailbox::new();

        let mut req = CmHmacReq {
            hash_algorithm: CmHashAlgorithm::Sha384 as u32,
            data_size: data.len() as u32,
            ..Default::default()
        };
        req.cmk.0.copy_from_slice(&cmk.0);
        if data.len() > req.data.len() {
            return Err(CaliptraApiError::InvalidArgument(
                "Data size exceeds maximum allowed",
            ));
        }
        req.data[..data.len()].copy_from_slice(data);

        let mut rsp = CmHmacResp::default();
        let rsp_bytes = rsp.as_mut_bytes();
        execute_mailbox_cmd(&mailbox, CmHmacReq::ID.0, req.as_mut_bytes(), rsp_bytes).await?;
        Ok(rsp)
    }
}
