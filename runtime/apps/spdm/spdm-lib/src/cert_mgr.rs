// Licensed under the Apache-2.0 license
use crate::error::{SpdmError, SpdmResult};
use core::mem::size_of;
use libapi_caliptra::crypto::cert_store::{CertStoreContext, CertType};
use libapi_caliptra::crypto::error::CryptoError;
use libapi_caliptra::crypto::hash::{HashAlgoType, HashContext};
use libtock_platform::Syscalls;
use thiserror_no_std::Error;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::context::SpdmContext;
use core::fmt::Write;

pub const SPDM_MAX_CERT_CHAIN_SLOTS: usize = 8;
pub const SPDM_MAX_HASH_SIZE: usize = 64;
pub const SPDM_CERT_CHAIN_HEADER_SIZE: usize = size_of::<SpdmCertChainHeader>();
// Maximum size of a DER certificate in bytes. Adjust as needed.
pub const MAX_DER_CERT_LENGTH: usize = 1024;

pub const MAX_CERT_COUNT_PER_CHAIN: usize = 6;

pub const MAX_CERT_CHAIN_DATA_SIZE: usize = MAX_DER_CERT_LENGTH * MAX_CERT_COUNT_PER_CHAIN;

pub type SupportedSlotMask = u8;
pub type ProvisionedSlotMask = u8;

#[derive(IntoBytes, FromBytes, Immutable)]
#[repr(packed)]
pub struct SpdmCertChainHeader {
    pub length: u16,
    pub reserved: u16,
}

pub struct SpdmCertChainBuffer {
    pub data: [u8; SPDM_CERT_CHAIN_HEADER_SIZE + SPDM_MAX_HASH_SIZE + MAX_CERT_CHAIN_DATA_SIZE],
    pub length: u16,
}

impl Default for SpdmCertChainBuffer {
    fn default() -> Self {
        SpdmCertChainBuffer {
            data: [0u8; SPDM_CERT_CHAIN_HEADER_SIZE
                + SPDM_MAX_HASH_SIZE
                + MAX_CERT_CHAIN_DATA_SIZE],
            length: 0u16,
        }
    }
}

impl AsRef<[u8]> for SpdmCertChainBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.data[..self.length as usize]
    }
}

impl SpdmCertChainBuffer {
    pub fn new(cert_chain_data: &[u8], root_hash: &[u8]) -> Result<Self, DeviceCertsMgrError> {
        if cert_chain_data.len() > MAX_CERT_CHAIN_DATA_SIZE || root_hash.len() > SPDM_MAX_HASH_SIZE
        {
            Err(DeviceCertsMgrError::BufferTooSmall)?;
        }

        let total_len =
            (cert_chain_data.len() + root_hash.len() + SPDM_CERT_CHAIN_HEADER_SIZE) as u16;
        let mut cert_chain_buf = SpdmCertChainBuffer::default();
        let mut pos = 0;

        // Length
        let len = 2;
        cert_chain_buf.data[pos..(pos + len)].copy_from_slice(&total_len.to_le_bytes());
        pos += len;

        // Reserved
        cert_chain_buf.data[pos] = 0;
        cert_chain_buf.data[pos + 1] = 0;
        pos += 2;

        // Root certificate hash
        let len = root_hash.len();
        cert_chain_buf.data[pos..(pos + len)].copy_from_slice(root_hash);
        pos += len;

        // Certificate chain data
        let len = cert_chain_data.len();
        cert_chain_buf.data[pos..(pos + len)].copy_from_slice(cert_chain_data);
        pos += len;

        cert_chain_buf.length = pos as u16;

        Ok(cert_chain_buf)
    }
}

#[derive(Error, Debug)]
pub enum DeviceCertsMgrError {
    #[error("Unsupported slot ID")]
    UnsupportedSlotId,
    #[error("Unprovisioned slot ID")]
    UnprovisionedSlotId,
    #[error("Buffer too small")]
    BufferTooSmall,
    #[error("Cryto error")]
    CryptoError(#[from] CryptoError),
    #[error("Invalid parameter {0}")]
    InvalidParam(&'static str),
}

pub type DeviceCertsMgrResult<T> = Result<T, DeviceCertsMgrError>;

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum SpdmCertModel {
    DeviceCertModel = 1,
    AliasCertModel = 2,
    GenericCertModel = 3,
}

pub struct DeviceCertChainBuf {
    slot_num: u8,
    cert_type: u8,
    buffer: [u8; DeviceCertChainBuf::MAX_CERT_SIZE * DeviceCertChainBuf::MAX_CERT_COUNT],
    // leaf_cert_buffer: [u8; DeviceCertChainBuf::MAX_CERT_SIZE],
    offset: u16,
    cert_chain_size: u16,
}

impl DeviceCertChainBuf {
    pub const MAX_CERT_SIZE: usize = 1024;
    pub const MAX_CERT_COUNT: usize = 4;
    pub fn new(slot_id: u8) -> Self {
        Self {
            slot_num: slot_id,
            cert_type: CertType::Ecc as u8,
            buffer: [0; DeviceCertChainBuf::MAX_CERT_SIZE * DeviceCertChainBuf::MAX_CERT_COUNT],
            // leaf_cert_buffer: [0; DeviceCertChainBuf::MAX_CERT_SIZE],
            offset: 0,
            cert_chain_size: 0,
        }
    }

    pub fn reset(&mut self) {
        self.offset = 0;
        self.cert_chain_size = 0;
        self.buffer.fill(0);
    }

    pub async fn cert_chain_size<S: Syscalls>(&mut self) -> DeviceCertsMgrResult<usize> {
        if self.cert_chain_size > 0 {
            return Ok(self.cert_chain_size as usize);
        }

        let mut cert_store = CertStoreContext::<S>::new();
        let chunk_size = Self::MAX_CERT_SIZE;
        // let mut cert_chain_comeplte = false;
        let mut offset = 0;

        self.buffer.fill(0);
        self.cert_chain_size = 0;

        // Get intermediate certificates
        loop {
            let start = offset;
            let end = start + chunk_size.min(self.buffer.len() - start);

            let size = cert_store
                .cert_chain_chunk(offset, &mut self.buffer[start..end])
                .await?;

            if size == 0 {
                break;
            }

            offset += size;

            if size < Self::MAX_CERT_SIZE {
                self.cert_chain_size = offset as u16;
                // cert_chain_complete = true;
                break;
            }
        }
        // Get leaf certificate
        let size = cert_store
            .certify_attestation_key(
                &mut self.buffer[self.cert_chain_size as usize..],
                None,
                None,
            )
            .await?;

        self.cert_chain_size += size as u16;

        Ok(self.cert_chain_size as usize)
    }

    pub async fn cert_chunk(
        &self,
        offset: usize,
        len: usize,
        cert_buf: &mut [u8],
    ) -> DeviceCertsMgrResult<usize> {
        if offset >= self.cert_chain_size as usize {
            return Err(DeviceCertsMgrError::BufferTooSmall);
        }

        let chunk_size = self.cert_chain_size as usize - offset;
        let size = len.min(chunk_size);

        cert_buf.copy_from_slice(&self.buffer[offset..offset + size]);

        Ok(size)
    }

    pub fn buffer(&self) -> &[u8] {
        &self.buffer[..self.cert_chain_size as usize]
    }
}

/// Holds the information about a certificate chain for a specific slot.
pub struct CertSlotInfo<'a> {
    // Certificate chain from `Root CA Certificate` upto `IDevID Certificate`.
    // e.g: Root CA-> Intermediate CA (if any)->IDevID Certificate
    pub(crate) root_cert_chain: &'a [&'a [u8]],
    // The staging buffer that holds the intermediate certificates in the chain.
    // These certificates are fetched from Caliptra Core.
    pub(crate) cert_chain_buf: DeviceCertChainBuf,
    // The buffer that holds the leaf certificate
    pub(crate) slot_id: u8,
    // The model of the certificate chain (e.g., Device, Alias, Generic)
    pub(crate) cert_model: Option<SpdmCertModel>,
    // The key pair ID associated with the certificate slot
    pub(crate) key_pair_id: Option<u8>,
    // The key usage mask associated with the certificate slot
    pub(crate) key_usage_mask: Option<u16>,
    // The maximum number of certificates in the chain
    // pub(crate) max_certs_in_chain: u8,
}

impl<'a> CertSlotInfo<'a> {
    pub fn new(
        root_cert_chain: &'a [&'a [u8]],
        slot_id: u8,
        cert_model: Option<SpdmCertModel>,
        key_pair_id: Option<u8>,
        key_usage_mask: Option<u16>,
    ) -> Self {
        Self {
            root_cert_chain,
            cert_chain_buf: DeviceCertChainBuf::new(slot_id),
            slot_id,
            cert_model,
            key_pair_id,
            key_usage_mask,
        }
    }

    pub async fn root_cert_hash<S: Syscalls>(
        &self,
        hash_algo: HashAlgoType,
        root_hash: &mut [u8],
    ) -> DeviceCertsMgrResult<()> {
        let hash_size = hash_algo.hash_size();
        if root_hash.len() < hash_size {
            Err(DeviceCertsMgrError::BufferTooSmall)?;
        }

        let root_ca_cert = self.root_cert_chain[0];
        let root_ca_cert_len = root_ca_cert.len();

        HashContext::<S>::hash_all(hash_algo, &root_ca_cert[..root_ca_cert_len], root_hash)
            .await
            .map_err(DeviceCertsMgrError::CryptoError)?;
        Ok(())
    }

    pub async fn cert_chain_size<S: Syscalls>(&mut self) -> DeviceCertsMgrResult<usize> {
        let mut len = self.root_cert_chain.iter().map(|cert| cert.len()).sum();

        len += self.cert_chain_buf.cert_chain_size::<S>().await?;

        Ok(len)
    }

    pub async fn cert_chain_digest<S: Syscalls>(
        &mut self,
        // ctx: &mut SpdmContext<'a, S>,
        hash_algo: HashAlgoType,
        digest: &mut [u8],
    ) -> DeviceCertsMgrResult<()> {
        let hash_size = hash_algo.hash_size();
        if digest.len() < hash_size {
            Err(DeviceCertsMgrError::BufferTooSmall)?;
        }

        // Get root certificate hash
        let mut root_hash = [0u8; SPDM_MAX_HASH_SIZE];
        self.root_cert_hash::<S>(hash_algo, &mut root_hash).await?;

        // Reset the certificate chain buffer
        self.cert_chain_buf.reset();

        // Get the certificate chain size
        let cert_chain_size = self.cert_chain_size::<S>().await?;

        let total_len = size_of::<SpdmCertChainHeader>() + hash_size + cert_chain_size;

        let cert_chain_header = SpdmCertChainHeader {
            length: total_len as u16,
            reserved: 0,
        };

        let cert_chain_header_bytes = cert_chain_header.as_bytes();

        let mut hash_ctx = HashContext::<S>::new();

        // Hash the Cert chain header
        hash_ctx
            .init(hash_algo, Some(&cert_chain_header_bytes[..]))
            .await?;

        // Hash the root certificate hash
        hash_ctx.update(&root_hash[..hash_size]).await?;

        // writeln!(
        //     ctx.cw,
        //     "SPDM_LIB: cert_chain_digest total_len {} root_hash {:?}",
        //     total_len, root_hash
        // )
        // .unwrap();

        // Hash the root certificate chain
        for cert in self.root_cert_chain.iter() {
            hash_ctx.update(cert).await?;
        }

        // Hash the remaining certificates in the chain
        hash_ctx.update(&self.cert_chain_buf.buffer()).await?;

        // Finalize the hash
        hash_ctx.finalize(digest).await?;
        Ok(())
    }

    pub async fn cert_chain<S: Syscalls>(
        &mut self,
        cert_chain_data: &mut [u8],
    ) -> DeviceCertsMgrResult<usize> {
        let cert_chain_size = self.cert_chain_size::<S>().await?;

        if cert_chain_data.len() < cert_chain_size {
            Err(DeviceCertsMgrError::BufferTooSmall)?;
        }

        // Copy the root certificate chain
        let mut pos = 0;
        for cert in self.root_cert_chain.iter() {
            let cert_len = cert.len();
            if pos + cert_len > cert_chain_data.len() {
                Err(DeviceCertsMgrError::BufferTooSmall)?;
            }
            cert_chain_data[pos..pos + cert_len].copy_from_slice(cert);
            pos += cert_len;
        }

        // Copy rest of the certificate chain
        let dev_cert_chain_size = self.cert_chain_buf.cert_chain_size::<S>().await?;
        if pos + dev_cert_chain_size > cert_chain_data.len() {
            Err(DeviceCertsMgrError::BufferTooSmall)?;
        }
        cert_chain_data[pos..pos + dev_cert_chain_size]
            .copy_from_slice(self.cert_chain_buf.buffer());

        Ok(pos)
    }
}

/// Manages the device certificates and their associated information.
pub struct DeviceCertsManager<'a> {
    supported_slot_mask: SupportedSlotMask,
    provisioned_slot_mask: ProvisionedSlotMask,
    cert_chain_slot_info: &'a mut [CertSlotInfo<'a>],
}

impl<'a> DeviceCertsManager<'a> {
    pub fn new(
        supported_slot_mask: SupportedSlotMask,
        provisioned_slot_mask: ProvisionedSlotMask,
        cert_chain_slot_info: &'a mut [CertSlotInfo<'a>],
    ) -> SpdmResult<Self> {
        let mut prev_slot_id = 0;
        if cert_chain_slot_info.len() < 1 || cert_chain_slot_info.len() > SPDM_MAX_CERT_CHAIN_SLOTS
        {
            Err(SpdmError::InvalidParam)?;
        }

        for (i, cert_chain) in cert_chain_slot_info.into_iter().enumerate() {
            // Slot ID must be unique and in ascending order
            if i > 0 && cert_chain.slot_id <= prev_slot_id {
                Err(SpdmError::InvalidParam)?;
            }
            prev_slot_id = cert_chain.slot_id;

            if cert_chain.slot_id >= SPDM_MAX_CERT_CHAIN_SLOTS as u8 {
                Err(SpdmError::InvalidParam)?;
            }

            if supported_slot_mask & (1 << cert_chain.slot_id) == 0
                || provisioned_slot_mask & (1 << cert_chain.slot_id) == 0
            {
                Err(SpdmError::InvalidParam)?;
            }
        }

        Ok(Self {
            supported_slot_mask,
            provisioned_slot_mask,
            cert_chain_slot_info,
        })
    }

    // pub fn cert_chain_slot_info(&mut self, slot_id: u8) -> Option<&mut CertSlotInfo<'a>> {
    //     self.cert_chain_slot_info
    //         .iter_mut()
    //         .find(|cert_chain| cert_chain.slot_id == slot_id).or(None)
    // }

    pub async fn cert_chain_digest<S: Syscalls>(
        &mut self,
        slot_id: u8,
        hash_algo: HashAlgoType,
        digest: &mut [u8],
    ) -> DeviceCertsMgrResult<()> {
        let cert_chain_info = self
            .cert_chain_slot_info
            .iter_mut()
            .find(|cert_chain| cert_chain.slot_id == slot_id)
            .ok_or(DeviceCertsMgrError::UnsupportedSlotId)?;

        cert_chain_info
            .cert_chain_digest::<S>(hash_algo, digest)
            .await?;
        Ok(())
    }

    pub fn cert_chain_slot_mask(
        &self,
    ) -> Result<(SupportedSlotMask, ProvisionedSlotMask), DeviceCertsMgrError> {
        Ok((self.supported_slot_mask, self.provisioned_slot_mask))
    }

    pub async fn construct_cert_chain_buffer<S: Syscalls>(
        &mut self,
        // ctx: &mut SpdmContext<'a, S>,
        hash_algo: HashAlgoType,
        slot_id: u8,
    ) -> DeviceCertsMgrResult<SpdmCertChainBuffer> {
        let mut cert_chain_data = [0u8; MAX_CERT_CHAIN_DATA_SIZE];
        let cert_chain_info = &mut self
            .cert_chain_slot_info
            .iter_mut()
            .find(|cert_chain| cert_chain.slot_id == slot_id)
            .ok_or(DeviceCertsMgrError::UnsupportedSlotId)?;

        let cert_chain_size = cert_chain_info.cert_chain_size::<S>().await?;

        // writeln!(
        //     ctx.cw,
        //     "SPDM_LIB: construct_cert_chain_buffer cert_chain_size {}",
        //     cert_chain_size
        // )
        // .unwrap();

        if cert_chain_size > cert_chain_data.len() {
            Err(DeviceCertsMgrError::BufferTooSmall)?;
        }

        cert_chain_info
            .cert_chain::<S>(&mut cert_chain_data[..cert_chain_size])
            .await?;

        let mut root_hash = [0u8; SPDM_MAX_HASH_SIZE];
        let hash_size = hash_algo.hash_size();
        cert_chain_info
            .root_cert_hash::<S>(hash_algo, &mut root_hash)
            .await?;

        let cert_chain_buf =
            SpdmCertChainBuffer::new(&cert_chain_data[..cert_chain_size], &root_hash[..hash_size])?;
        Ok(cert_chain_buf)
    }
}
// #[cfg(test)]
// mod test {
//     use super::*;
//     use crate::config;

//     #[test]
//     fn test_get_certificate_chain_data() {
//         let mut cert_chain_data = SpdmCertChainData::default();
//         let device_certs_mgr = DeviceCertsManager::new(1, 1);
//         let slot_id = 0;

//         let root_cert_len = device_certs_mgr
//             .construct_cert_chain_data(slot_id, &mut cert_chain_data)
//             .unwrap();
//         assert_eq!(root_cert_len, config::TEST_ROOT_CA_CERT_DER.len());
//         assert_eq!(
//             cert_chain_data.as_ref().len(),
//             config::TEST_ROOT_CA_CERT_DER.len() + config::DEVID_CERT_DER.len()
//         );
//         assert_eq!(
//             &cert_chain_data.as_ref()[..root_cert_len],
//             &config::TEST_ROOT_CA_CERT_DER[..]
//         );
//         assert_eq!(
//             &cert_chain_data.as_ref()[root_cert_len..],
//             &config::DEVID_CERT_DER[..]
//         );
//     }

//     #[test]
//     fn test_certificate_chain_base_buffer() {
//         let device_certs_mgr = DeviceCertsManager::new(1, 1);
//         let mut cert_chain_data = SpdmCertChainData::default();
//         let slot_id = 0;
//         let root_cert_len = device_certs_mgr
//             .construct_cert_chain_data(slot_id, &mut cert_chain_data)
//             .unwrap();

//         let root_hash = [0xAAu8; SPDM_MAX_HASH_SIZE];
//         let cert_chain_base_buf =
//             SpdmCertChainBaseBuffer::new(root_cert_len, root_hash.as_ref()).unwrap();
//         assert_eq!(
//             cert_chain_base_buf.length,
//             (SPDM_CERT_CHAIN_HEADER_SIZE + root_hash.len()) as u16
//         );
//         assert_eq!(
//             cert_chain_base_buf.as_ref()[..2],
//             ((root_cert_len + SPDM_CERT_CHAIN_HEADER_SIZE + root_hash.len()) as u16).to_le_bytes()
//         );
//         assert_eq!(cert_chain_base_buf.as_ref()[2..4], [0, 0]);
//         assert_eq!(&cert_chain_base_buf.as_ref()[4..], &root_hash[..]);
//     }
// }
