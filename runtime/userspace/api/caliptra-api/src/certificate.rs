// Licensed under the Apache-2.0 license

use crate::crypto::error::{CryptoError, CryptoResult};
use caliptra_api::mailbox::{
    CommandId, GetFmcAliasEcc384CertReq, GetIdevCsrReq, GetIdevCsrResp, GetLdevEcc384CertReq, GetLdevCertResp,
    GetRtAliasEcc384CertReq, InvokeDpeReq, InvokeDpeResp, MailboxReqHeader, MailboxRespHeader,
    PopulateIdevEcc384CertReq, Request,
};
use dpe::commands::{
    CertifyKeyCmd, CertifyKeyFlags, Command, CommandHdr, GetCertificateChainCmd, SignCmd, SignFlags,
};
use dpe::context::ContextHandle;
use dpe::response::{CertifyKeyResp, GetCertificateChainResp, Response, SignResp};
use dpe::DPE_PROFILE;
use libsyscall_caliptra::mailbox::Mailbox;
use zerocopy::{FromBytes, FromZeros, IntoBytes};

pub const IDEV_ECC_CSR_MAX_SIZE: usize = GetIdevCsrResp::DATA_MAX_SIZE;
pub const MAX_ECC_CERT_SIZE: usize = GetLdevCertResp::DATA_MAX_SIZE;
pub const MAX_CERT_CHUNK_SIZE: usize = 2048;

pub const ATTESTATION_KEY_LABEL: [u8; 48] = [
    48, 47, 46, 45, 44, 43, 42, 41, 40, 39, 38, 37, 36, 35, 34, 33, 32, 31, 30, 29, 28, 27, 26, 25,
    24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
];

pub enum CertType {
    Ecc,
}

pub struct CertStoreContext {
    mbox: Mailbox,
}

impl Default for CertStoreContext {
    fn default() -> Self {
        CertStoreContext::new()
    }
}

impl CertStoreContext {
    pub fn new() -> Self {
        CertStoreContext {
            mbox: Mailbox::new(),
        }
    }

    pub async fn get_idev_csr(
        &mut self,
        csr_der: &mut [u8; IDEV_ECC_CSR_MAX_SIZE],
    ) -> CryptoResult<usize> {
        let mut req = GetIdevCsrReq::default();

        let mut resp = GetIdevCsrResp {
            hdr: MailboxRespHeader::default(),
            data: [0; GetIdevCsrResp::DATA_MAX_SIZE],
            data_size: 0,
        };

        let req_bytes = req.as_mut_bytes();
        let resp_bytes = resp.as_mut_bytes();

        self.mbox
            .populate_checksum(GetIdevCsrReq::ID.0, req_bytes)
            .map_err(CryptoError::Syscall)?;

        self.mbox
            .execute(GetIdevCsrReq::ID.0, req_bytes, resp_bytes)
            .await
            .map_err(CryptoError::Mailbox)?;
        let resp =
            GetIdevCsrResp::ref_from_bytes(resp_bytes).map_err(|_| CryptoError::InvalidResponse)?;
        if resp.data_size == u32::MAX {
            Err(CryptoError::UnprovisionedCsr)?;
        }

        if resp.data_size == 0 || resp.data_size > IDEV_ECC_CSR_MAX_SIZE as u32 {
            return Err(CryptoError::InvalidResponse);
        }

        csr_der[..resp.data_size as usize].copy_from_slice(&resp.data[..resp.data_size as usize]);
        Ok(resp.data_size as usize)
    }

    pub async fn populate_idev_cert(&mut self, cert: &[u8]) -> CryptoResult<()> {
        if cert.len() > PopulateIdevEcc384CertReq::MAX_CERT_SIZE {
            return Err(CryptoError::InvalidArgument("Invalid cert size"));
        }
        let cmd = CommandId::POPULATE_IDEV_CERT.into();
        let mut req = PopulateIdevEcc384CertReq {
            cert_size: cert.len() as u32,
            ..Default::default()
        };
        req.cert[..cert.len()].copy_from_slice(cert);

        let req_bytes = req.as_mut_bytes();
        let mut resp = MailboxRespHeader::default();
        let resp_bytes = resp.as_mut_bytes();

        self.mbox
            .populate_checksum(cmd, req_bytes)
            .map_err(CryptoError::Syscall)?;

        self.mbox
            .execute(cmd, req_bytes, &mut resp_bytes[..])
            .await
            .map_err(CryptoError::Mailbox)?;
        Ok(())
    }

    pub async fn get_ldev_cert(
        &mut self,
        cert: &mut [u8; MAX_ECC_CERT_SIZE],
    ) -> CryptoResult<usize> {
        let resp = self.get_cert::<GetLdevEcc384CertReq>().await?;
        if resp.data_size > MAX_ECC_CERT_SIZE as u32 {
            return Err(CryptoError::InvalidResponse);
        }
        cert[..resp.data_size as usize].copy_from_slice(&resp.data[..resp.data_size as usize]);
        Ok(resp.data_size as usize)
    }

    pub async fn get_fmc_alias_cert(
        &mut self,
        cert: &mut [u8; MAX_ECC_CERT_SIZE],
    ) -> CryptoResult<usize> {
        let resp = self.get_cert::<GetFmcAliasEcc384CertReq>().await?;
        if resp.data_size > MAX_ECC_CERT_SIZE as u32 {
            return Err(CryptoError::InvalidResponse);
        }
        cert[..resp.data_size as usize].copy_from_slice(&resp.data[..resp.data_size as usize]);
        Ok(resp.data_size as usize)
    }

    pub async fn get_rt_alias_cert(
        &mut self,
        cert: &mut [u8; MAX_ECC_CERT_SIZE],
    ) -> CryptoResult<usize> {
        let resp = self.get_cert::<GetRtAliasEcc384CertReq>().await?;
        if resp.data_size > MAX_ECC_CERT_SIZE as u32 {
            return Err(CryptoError::InvalidResponse);
        }
        cert[..resp.data_size as usize].copy_from_slice(&resp.data[..resp.data_size as usize]);
        Ok(resp.data_size as usize)
    }

    pub async fn certify_attestation_key(
        &mut self,
        cert: &mut [u8],
        derived_pubkey_x: Option<&mut [u8]>,
        derived_pubkey_y: Option<&mut [u8]>,
    ) -> CryptoResult<usize> {
        if let Some(ref x) = derived_pubkey_x {
            if x.len() != DPE_PROFILE.get_tci_size() {
                Err(CryptoError::InvalidArgument("Invalid pubkey size"))?;
            }
        }
        if let Some(ref y) = derived_pubkey_y {
            if y.len() != DPE_PROFILE.get_tci_size() {
                Err(CryptoError::InvalidArgument("Invalid pubkey size"))?;
            }
        }

        let dpe_cmd = CertifyKeyCmd {
            handle: ContextHandle::default(),
            label: ATTESTATION_KEY_LABEL,
            flags: CertifyKeyFlags::empty(),
            format: CertifyKeyCmd::FORMAT_X509,
        };

        let resp = self
            .execute_dpe_cmd(&mut Command::CertifyKey(&dpe_cmd))
            .await?;

        if let Response::CertifyKey(certify_key_resp) = resp {
            let cert_len = certify_key_resp.cert_size as usize;
            if cert_len > cert.len() {
                return Err(CryptoError::InvalidResponse);
            }

            cert[..cert_len].copy_from_slice(&certify_key_resp.cert[..cert_len]);

            if let Some(derived_pubkey_x) = derived_pubkey_x {
                derived_pubkey_x.copy_from_slice(&certify_key_resp.derived_pubkey_x);
            }
            if let Some(derived_pubkey_y) = derived_pubkey_y {
                derived_pubkey_y.copy_from_slice(&certify_key_resp.derived_pubkey_y);
            }
            Ok(cert_len)
        } else {
            Err(CryptoError::InvalidResponse)
        }
    }

    pub async fn sign_with_attestation_key(
        &mut self,
        digest: &[u8],
        signature: &mut [u8],
    ) -> CryptoResult<usize> {
        if digest.len() != DPE_PROFILE.get_hash_size() {
            return Err(CryptoError::InvalidArgument("Invalid digest size"));
        }

        if signature.len() < DPE_PROFILE.get_tci_size() {
            return Err(CryptoError::InvalidArgument("Invalid signature size"));
        }

        let mut dpe_cmd = SignCmd {
            handle: ContextHandle::default(),
            label: ATTESTATION_KEY_LABEL,
            flags: SignFlags::empty(),
            digest: [0; DPE_PROFILE.get_hash_size()],
        };
        dpe_cmd.digest[..digest.len()].copy_from_slice(digest);

        let resp = self.execute_dpe_cmd(&mut Command::Sign(&dpe_cmd)).await?;
        match resp {
            Response::Sign(sign_resp) => {
                let sig_r_size = sign_resp.sig_r.len();
                let sig_s_size = sign_resp.sig_s.len();
                signature[..sig_r_size].copy_from_slice(&sign_resp.sig_r[..]);
                signature[sig_r_size..sig_r_size + sig_s_size]
                    .copy_from_slice(&sign_resp.sig_s[..]);
                Ok(sig_r_size + sig_s_size)
            }
            _ => Err(CryptoError::InvalidResponse),
        }
    }

    pub fn max_cert_chain_chunk_size(&mut self) -> usize {
        MAX_CERT_CHUNK_SIZE
    }

    pub async fn cert_chain_chunk(
        &mut self,
        offset: usize,
        cert_chunk: &mut [u8],
    ) -> CryptoResult<usize> {
        let size = cert_chunk.len();
        if size > MAX_CERT_CHUNK_SIZE {
            Err(CryptoError::InvalidArgument("Chunk size is too large"))?;
        }

        let dpe_cmd = GetCertificateChainCmd {
            offset: offset as u32,
            size: size as u32,
        };

        let resp = self
            .execute_dpe_cmd(&mut Command::GetCertificateChain(&dpe_cmd))
            .await?;

        match resp {
            Response::GetCertificateChain(cert_chain_resp) => {
                if cert_chain_resp.certificate_size > cert_chunk.len() as u32 {
                    return Err(CryptoError::InvalidResponse);
                }

                let cert_chain_resp_len = cert_chain_resp.certificate_size as usize;

                cert_chunk[..cert_chain_resp_len]
                    .copy_from_slice(&cert_chain_resp.certificate_chain[..cert_chain_resp_len]);
                Ok(cert_chain_resp_len)
            }
            _ => Err(CryptoError::InvalidResponse),
        }
    }

    async fn get_cert<R: Request + Default>(&mut self) -> CryptoResult<R::Resp> {
        let mut req = R::default();
        let mut resp = R::Resp::new_zeroed();
        let resp_bytes = resp.as_mut_bytes();
        let req_bytes = req.as_mut_bytes();
        // let resp_bytes = resp.as_mut_bytes();
        let cmd = R::ID.into();

        self.mbox
            .populate_checksum(cmd, req_bytes)
            .map_err(CryptoError::Syscall)?;

        self.mbox
            .execute(cmd, req_bytes, resp_bytes)
            .await
            .map_err(CryptoError::Mailbox)?;

        let mut resp = R::Resp::new_zeroed();
        resp.as_mut_bytes()[..].copy_from_slice(&resp_bytes[..]);

        Ok(resp)
    }

    async fn execute_dpe_cmd<'a>(&mut self, dpe_cmd: &mut Command<'a>) -> CryptoResult<Response> {
        let mut cmd_data: [u8; InvokeDpeReq::DATA_MAX_SIZE] = [0; InvokeDpeReq::DATA_MAX_SIZE];
        let dpe_cmd_id: u32 = Self::dpe_cmd_id(dpe_cmd);

        let cmd_hdr = CommandHdr::new_for_test(dpe_cmd_id);

        let cmd_hdr_bytes = cmd_hdr.as_bytes();
        cmd_data[..cmd_hdr_bytes.len()].copy_from_slice(cmd_hdr_bytes);

        let dpe_cmd_bytes = Self::dpe_cmd_as_bytes(dpe_cmd);
        cmd_data[cmd_hdr_bytes.len()..cmd_hdr_bytes.len() + dpe_cmd_bytes.len()]
            .copy_from_slice(dpe_cmd_bytes);
        let cmd_data_len = cmd_hdr_bytes.len() + dpe_cmd_bytes.len();

        let mut mbox_req = InvokeDpeReq {
            hdr: MailboxReqHeader { chksum: 0 },
            data_size: cmd_data_len as u32,
            data: cmd_data,
        };

        let mut mbox_resp = InvokeDpeResp::default();

        self.mbox
            .populate_checksum(InvokeDpeReq::ID.0, mbox_req.as_mut_bytes())
            .map_err(CryptoError::Syscall)?;
        self.mbox
            .execute(
                InvokeDpeReq::ID.0,
                mbox_req.as_mut_bytes(),
                mbox_resp.as_mut_bytes(),
            )
            .await
            .map_err(CryptoError::Mailbox)?;
        let mut resp = InvokeDpeResp::new_zeroed();
        resp.as_mut_bytes()[..].copy_from_slice(mbox_resp.as_mut_bytes());
        self.parse_dpe_response(dpe_cmd, &resp)
    }

    fn dpe_cmd_id(dpe_cmd: &mut Command) -> u32 {
        match dpe_cmd {
            Command::GetProfile => Command::GET_PROFILE,
            Command::InitCtx(_) => Command::INITIALIZE_CONTEXT,
            Command::DeriveContext(_) => Command::DERIVE_CONTEXT,
            Command::CertifyKey(_) => Command::CERTIFY_KEY,
            Command::Sign(_) => Command::SIGN,
            Command::RotateCtx(_) => Command::ROTATE_CONTEXT_HANDLE,
            Command::DestroyCtx(_) => Command::DESTROY_CONTEXT,
            Command::GetCertificateChain(_) => Command::GET_CERTIFICATE_CHAIN,
        }
    }

    fn dpe_cmd_as_bytes<'a>(dpe_cmd: &'a mut Command) -> &'a [u8] {
        match dpe_cmd {
            Command::CertifyKey(cmd) => cmd.as_bytes(),
            Command::DeriveContext(cmd) => cmd.as_bytes(),
            Command::GetCertificateChain(cmd) => cmd.as_bytes(),
            Command::DestroyCtx(cmd) => cmd.as_bytes(),
            Command::GetProfile => &[],
            Command::InitCtx(cmd) => cmd.as_bytes(),
            Command::RotateCtx(cmd) => cmd.as_bytes(),
            Command::Sign(cmd) => cmd.as_bytes(),
        }
    }

    fn parse_dpe_response(
        &self,
        cmd: &mut Command,
        resp: &InvokeDpeResp,
    ) -> CryptoResult<Response> {
        let data = &resp.data[..resp.data_size as usize];

        match cmd {
            Command::CertifyKey(_) => Ok(Response::CertifyKey(
                CertifyKeyResp::read_from_bytes(data).map_err(|_| CryptoError::InvalidResponse)?,
            )),
            Command::Sign(_) => Ok(Response::Sign(
                SignResp::read_from_bytes(data).map_err(|_| CryptoError::InvalidResponse)?,
            )),
            Command::GetCertificateChain(_) => Ok(Response::GetCertificateChain(
                GetCertificateChainResp::read_from_bytes(data)
                    .map_err(|_| CryptoError::InvalidResponse)?,
            )),
            _ => Err(CryptoError::InvalidResponse),
        }
    }
}
