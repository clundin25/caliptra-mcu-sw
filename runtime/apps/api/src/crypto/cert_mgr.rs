// Licensed under the Apache-2.0 license

use crate::crypto::error::{CryptoError, CryptoResult};
use caliptra_api::mailbox::{GetIdevCsrReq, GetIdevCsrResp, MailboxRespHeader, Request};

use libsyscall_caliptra::mailbox::Mailbox;
use libtock_platform::Syscalls;
use zerocopy::{FromBytes, IntoBytes};

pub const IDEV_CSR_MAX_SIZE: usize = GetIdevCsrResp::DATA_MAX_SIZE;

use core::fmt::Write;
use romtime::println;

pub struct CerMgrContext<S: Syscalls> {
    mbox: Mailbox<S>,
}

impl<S: Syscalls> CerMgrContext<S> {
    pub fn new() -> Self {
        CerMgrContext {
            mbox: Mailbox::<S>::new(),
        }
    }

    pub async fn get_idev_csr(
        &mut self,
        csr_der: &mut [u8; IDEV_CSR_MAX_SIZE],
    ) -> CryptoResult<usize> {
        let mut req = GetIdevCsrReq::default();
        // let mut req = MailboxReqHeader::default();

        let mut resp = GetIdevCsrResp {
            hdr: MailboxRespHeader::default(),
            data: [0; GetIdevCsrResp::DATA_MAX_SIZE],
            data_size: 0,
        };

        let resp_bytes = resp.as_mut_bytes();

        let req_bytes = req.as_mut_bytes();

        println!("get_idev_csr: req size: {:?}", req_bytes.len());
        println!("get_idev_csr: resp size: {:?}", resp_bytes.len());

        self.mbox
            .populate_checksum(GetIdevCsrReq::ID.0, req_bytes)?;

        self.mbox
            .execute(GetIdevCsrReq::ID.0, req_bytes, resp_bytes)
            .await?;
        let resp =
            GetIdevCsrResp::ref_from_bytes(resp_bytes).map_err(|_| CryptoError::InvalidResponse)?;
        if resp.data_size == u32::MAX {
            Err(CryptoError::UnprovisionedCsr)?;
        }

        if resp.data_size == 0 || resp.data_size > IDEV_CSR_MAX_SIZE as u32 {
            return Err(CryptoError::InvalidResponse);
        }

        csr_der[..resp.data_size as usize].copy_from_slice(&resp.data[..resp.data_size as usize]);
        Ok(resp.data_size as usize)
    }
}
