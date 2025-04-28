// Licensed under the Apache-2.0 license
extern crate alloc;

use crate::protocol::algorithms::BaseHashAlgoType;
use crate::protocol::certs::{CertificateInfo, KeyPairID, KeyUsageMask, SPDM_MAX_CERT_SLOTS};
use crate::protocol::{ProvisionedSlotMask, SupportedSlotMask};
use alloc::boxed::Box;
use async_trait::async_trait;
use libapi_caliptra::crypto::error::CryptoError;
use libapi_caliptra::crypto::hash::{HashAlgoType, HashContext, MAX_HASH_SIZE};
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub const SPDM_MAX_CERT_CHAIN_PORTION_LEN: usize = 512;

#[derive(Debug, Clone)]
pub enum CertChainError {
    CertNotFound,
    CertReadError,
    RootCertChainNotFound,
}

pub type CertChainResult<T> = Result<T, CertChainError>;

///! This module defines the `CertChain` trait, which is responsible for managing SPDM certificate chains.
///! Each provisioned slot corresponds to an instance of the `CertChain`, which handles
///! the ASN.1 DER-encoded X.509 v3 certificate chain for that slot.
#[async_trait]
pub trait CertChain {
    /// Get the digest of the root certificate in the certificate chain.
    ///
    /// # Arguments
    /// * `hash_algo` - The hash algorithm to use for the digest.
    /// * `root_hash` - The buffer to store the digest of the root certificate.
    ///
    /// # Returns
    /// * `Ok(usize)` - The number of bytes written to the buffer or an error.
    async fn root_cert_hash<'a>(
        &mut self,
        hash_algo: BaseHashAlgoType,
        root_hash: &'a mut [u8],
    ) -> CertChainResult<usize>;

    /// Get the length of the certificate chain.
    ///
    /// # Returns
    /// * `Ok(usize)` - The length of the certificate chain in bytes or an error.
    async fn cert_chain_length(&mut self) -> CertChainResult<usize>;

    /// Read the certificate chain in portion. The certificate chain is in ASN.1 DER-encoded X.509 v3 format.
    ///
    /// # Arguments
    /// * `offset` - The offset in bytes from the start of the cert chain.
    /// * `cert_portion` - The buffer to store the portion of cert chain.
    ///
    /// # Returns
    /// * `Ok(usize)` - The number of bytes written to the buffer or an error.
    /// If the cert portion size is smaller than the buffer size, the remaining bytes in the buffer will be filled with 0,
    /// indicating the end of the cert chain.
    async fn read_cert_chain<'a>(
        &mut self,
        offset: usize,
        cert_portion: &'a mut [u8],
    ) -> CertChainResult<usize>;

    /// Get the KeyPairID associated with the certificate chain if SPDM responder supports
    /// multiple assymmetric keys in connection.
    ///
    /// # Returns
    /// * `Option<KeyPairID>` - The KeyPairID associated with the certificate chain or None if not supported or not found.
    fn key_pair_id(&mut self) -> Option<KeyPairID>;

    /// Get CertificateInfo associated with the certificate chain if SPDM responder supports
    /// multiple assymmetric keys in connection.
    ///
    /// # Returns
    /// * `Option<CertificateInfo>` - The CertificateInfo associated with the certificate chain or None if not supported or not found.
    fn cert_info(&mut self) -> Option<CertificateInfo>;

    /// Get the KeyUsageMask associated with the certificate chain if SPDM responder supports
    /// multiple assymmetric keys in connection.
    ///
    /// # Returns
    /// * `Option<KeyUsageMask>` - The KeyUsageMask associated with the certificate chain or None if not supported or not found.
    fn key_usage_mask(&mut self) -> Option<KeyUsageMask>;
}

#[derive(Debug)]
pub enum CertStoreError {
    InvalidSlotId,
    UnsupportedHashAlgo,
    BufferTooSmall,
    InvalidOffset,
    Crypto(CryptoError),
    CertChain(CertChainError),
}
pub type CertStoreResult<T> = Result<T, CertStoreError>;

struct CertChainState {
    pub(crate) cert_chain_format_len: u16,
    pub(crate) hash_size: usize,
    pub(crate) root_cert_hash: [u8; MAX_HASH_SIZE],
    pub(crate) cert_chain_format_digest: [u8; MAX_HASH_SIZE],
}

impl CertChainState {
    pub fn new(
        cert_chain_format_len: u16,
        root_cert_hash: &[u8],
        cert_chain_format_digest: &[u8],
    ) -> CertStoreResult<Self> {
        let hash_size = root_cert_hash.len();
        if hash_size > MAX_HASH_SIZE {
            Err(CertStoreError::BufferTooSmall)?;
        }
        let mut root_cert_hash_buf = [0; MAX_HASH_SIZE];
        root_cert_hash_buf[..hash_size].copy_from_slice(root_cert_hash);

        let mut cert_chain_digest_buf = [0; MAX_HASH_SIZE];
        cert_chain_digest_buf[..hash_size].copy_from_slice(cert_chain_format_digest);
        Ok(Self {
            cert_chain_format_len,
            hash_size,
            root_cert_hash: root_cert_hash_buf,
            cert_chain_format_digest: cert_chain_digest_buf,
        })
    }
}

#[derive(IntoBytes, FromBytes, Immutable)]
#[repr(packed)]
pub struct SpdmCertChainHeader {
    pub length: u16,
    pub reserved: u16,
}

pub struct SpdmCertStore<'a> {
    pub(crate) supported_slot_mask: SupportedSlotMask,
    pub(crate) provisioned_slot_mask: ProvisionedSlotMask,
    pub(crate) cert_chain: [Option<&'a mut dyn CertChain>; SPDM_MAX_CERT_SLOTS],
    pub(crate) cert_chain_state: [Option<CertChainState>; SPDM_MAX_CERT_SLOTS],
}

impl<'a> SpdmCertStore<'a> {
    pub const MAX_CERT_CHAIN_FORMAT_METADATA_LEN: usize =
        size_of::<SpdmCertChainHeader>() + MAX_HASH_SIZE;
    pub fn new(
        supported_slot_mask: u8,
        provisioned_slot_mask: u8,
        cert_chain: [Option<&'a mut dyn CertChain>; SPDM_MAX_CERT_SLOTS],
    ) -> CertStoreResult<Self> {
        for slot_id in 0..SPDM_MAX_CERT_SLOTS {
            if (supported_slot_mask & (1 << slot_id)) != 0
                && (provisioned_slot_mask & (1 << slot_id)) != 0
                && cert_chain[slot_id].is_none()
            {
                Err(CertStoreError::InvalidSlotId)?;
            }
        }

        Ok(Self {
            supported_slot_mask,
            provisioned_slot_mask,
            cert_chain,
            cert_chain_state: Default::default(),
        })
    }

    pub fn reset_cert_chain_state(&mut self, slot_id: u8) -> CertStoreResult<()> {
        if slot_id >= SPDM_MAX_CERT_SLOTS as u8 {
            Err(CertStoreError::InvalidSlotId)?;
        }
        self.cert_chain_state[slot_id as usize] = None;
        Ok(())
    }

    pub fn cert_slot_mask(&self) -> (SupportedSlotMask, ProvisionedSlotMask) {
        (self.supported_slot_mask, self.provisioned_slot_mask)
    }

    pub async fn cert_chain_hash(
        &mut self,
        slot_id: u8,
        hash_algo_sel: BaseHashAlgoType,
        digest: &mut [u8],
    ) -> CertStoreResult<usize> {
        if slot_id >= SPDM_MAX_CERT_SLOTS as u8 || self.cert_chain[slot_id as usize].is_none() {
            Err(CertStoreError::InvalidSlotId)?;
        }

        self.reset_cert_chain_state(slot_id)?;

        let hash_algo: HashAlgoType = hash_algo_sel
            .try_into()
            .map_err(|_| CertStoreError::UnsupportedHashAlgo)?;

        let hash_size = hash_algo.hash_size();

        if digest.len() < hash_size {
            Err(CertStoreError::BufferTooSmall)?;
        }

        let mut cert_chain_format_len = size_of::<SpdmCertChainHeader>();

        let mut root_hash = [0; MAX_HASH_SIZE];

        let root_hash_len = self.cert_chain[slot_id as usize]
            .as_mut()
            .unwrap()
            .root_cert_hash(hash_algo_sel, &mut root_hash)
            .await
            .map_err(CertStoreError::CertChain)?;

        cert_chain_format_len += root_hash_len;

        let cert_chain_len = self.cert_chain[slot_id as usize]
            .as_mut()
            .unwrap()
            .cert_chain_length()
            .await
            .map_err(CertStoreError::CertChain)?;

        cert_chain_format_len += cert_chain_len;

        let cert_chain_hdr = SpdmCertChainHeader {
            length: cert_chain_format_len as u16,
            reserved: 0,
        };

        let cert_chain_hdr_bytes = cert_chain_hdr.as_bytes();

        // Hash the cert chain header
        let mut hash_ctx = HashContext::new();
        hash_ctx
            .init(hash_algo, Some(&cert_chain_hdr_bytes))
            .await
            .map_err(CertStoreError::Crypto)?;

        // Hash the root hash
        hash_ctx
            .update(&root_hash[..root_hash_len])
            .await
            .map_err(CertStoreError::Crypto)?;

        // Hash the cert chain
        let mut offset = 0;
        let cert_portion = &mut [0; SPDM_MAX_CERT_CHAIN_PORTION_LEN];

        while offset < cert_chain_len {
            let cert_portion_len = self.cert_chain[slot_id as usize]
                .as_mut()
                .unwrap()
                .read_cert_chain(offset, cert_portion)
                .await
                .map_err(|_| CertStoreError::CertChain(CertChainError::CertReadError))?;

            hash_ctx
                .update(&cert_portion[..cert_portion_len])
                .await
                .map_err(CertStoreError::Crypto)?;

            offset += cert_portion_len;

            cert_portion.fill(0);
        }

        // Finalize the hash into the Cert chain format digest buffer
        hash_ctx
            .finalize(&mut digest[..hash_size])
            .await
            .map_err(CertStoreError::Crypto)?;

        // Store the cert chain state for the later commands
        let cert_chain_state = CertChainState::new(
            cert_chain_format_len as u16,
            &root_hash[..hash_size],
            &digest[..hash_size],
        )?;
        self.cert_chain_state[slot_id as usize] = Some(cert_chain_state);

        Ok(hash_size)
    }

    pub async fn remainder_cert_chain_len(
        &mut self,
        hash_algo_sel: BaseHashAlgoType,
        slot_id: u8,
        offset: u16,
    ) -> CertStoreResult<u16> {
        if slot_id >= SPDM_MAX_CERT_SLOTS as u8 || self.cert_chain[slot_id as usize].is_none() {
            Err(CertStoreError::InvalidSlotId)?;
        }

        let hash_algo: HashAlgoType = hash_algo_sel
            .try_into()
            .map_err(|_| CertStoreError::UnsupportedHashAlgo)?;

        let hash_size = hash_algo.hash_size();

        let cert_chain_format_len = self.cert_chain_format_len(slot_id, hash_size).await?;

        if offset >= cert_chain_format_len {
            Err(CertStoreError::InvalidOffset)?;
        }
        Ok((cert_chain_format_len - offset) as u16)
    }

    /// Reads the certificate chain in SPDM Cert chain format.
    pub async fn read_cert_chain(
        &mut self,
        slot_id: u8,
        hash_algo_sel: BaseHashAlgoType,
        offset: usize,
        cert_portion: &mut [u8],
    ) -> CertStoreResult<usize> {
        if slot_id >= SPDM_MAX_CERT_SLOTS as u8 || self.cert_chain[slot_id as usize].is_none() {
            Err(CertStoreError::InvalidSlotId)?;
        }
        let hash_algo: HashAlgoType = hash_algo_sel
            .try_into()
            .map_err(|_| CertStoreError::UnsupportedHashAlgo)?;

        let hash_size = hash_algo.hash_size();
        let portion_len = cert_portion.len();
        let cert_chain_offset: usize;
        let rem_len: usize;
        let metadata_len = size_of::<SpdmCertChainHeader>() + hash_size;
        let mut read_len = 0;

        if offset < metadata_len {
            let metadata_len = self
                .read_cert_chain_format_metadata(slot_id, hash_algo_sel, offset, cert_portion)
                .await?;
            rem_len = portion_len - metadata_len;
            cert_chain_offset = 0;
            read_len = metadata_len;
        } else {
            cert_chain_offset = offset - metadata_len;
            rem_len = portion_len;
        }

        if rem_len > 0 {
            if let Some(cert_chain) = self.cert_chain[slot_id as usize].as_mut() {
                // Read the cert chain portion
                let bytes_read = cert_chain
                    .read_cert_chain(
                        offset,
                        &mut cert_portion[cert_chain_offset..cert_chain_offset + rem_len],
                    )
                    .await
                    .map_err(|_| CertStoreError::CertChain(CertChainError::CertReadError))?;

                read_len += bytes_read;
            } else {
                return Err(CertStoreError::CertChain(CertChainError::CertNotFound));
            }
        }

        Ok(read_len)
    }

    async fn read_cert_chain_format_metadata(
        &mut self,
        slot_id: u8,
        hash_algo_sel: BaseHashAlgoType,
        offset: usize,
        cert_portion: &mut [u8],
    ) -> CertStoreResult<usize> {
        let portion_len = cert_portion.len();

        let hash_size = hash_algo_sel
            .hash_size()
            .map_err(|_| CertStoreError::UnsupportedHashAlgo)?;
        let mut fixed_size_hdr_buf = [0u8; Self::MAX_CERT_CHAIN_FORMAT_METADATA_LEN];

        // Read the cert chain header first
        let cert_chain_hdr = SpdmCertChainHeader {
            length: self.cert_chain_format_len(slot_id, hash_size).await? as u16,
            reserved: 0,
        };
        let cert_chain_hdr_bytes = cert_chain_hdr.as_bytes();
        fixed_size_hdr_buf[..cert_chain_hdr_bytes.len()].copy_from_slice(&cert_chain_hdr_bytes[..]);

        // Read the root cert hash next
        let root_hash_buf = &mut fixed_size_hdr_buf[cert_chain_hdr_bytes.len()..];
        let root_hash_len = self
            .root_cert_hash(slot_id, hash_algo_sel, root_hash_buf)
            .await?;
        let total_metadata_len = cert_chain_hdr_bytes.len() + root_hash_len;

        if offset >= total_metadata_len {
            return Ok(0);
        }

        let write_len = (total_metadata_len - offset).min(portion_len);

        cert_portion[..write_len].copy_from_slice(&fixed_size_hdr_buf[offset..offset + write_len]);

        Ok(write_len)
    }

    async fn cert_chain_format_len(
        &mut self,
        slot_id: u8,
        hash_size: usize,
    ) -> CertStoreResult<u16> {
        match self.cert_chain_state[slot_id as usize].as_ref() {
            Some(cert_chain_state) => Ok(cert_chain_state.cert_chain_format_len),
            None => {
                let cert_chain = self.cert_chain[slot_id as usize]
                    .as_mut()
                    .ok_or(CertStoreError::InvalidSlotId)?;

                let cert_chain_len = cert_chain
                    .cert_chain_length()
                    .await
                    .map_err(CertStoreError::CertChain)?;

                Ok((size_of::<SpdmCertChainHeader>() + hash_size + cert_chain_len) as u16)
            }
        }
    }

    async fn root_cert_hash(
        &mut self,
        slot_id: u8,
        hash_algo_sel: BaseHashAlgoType,
        root_hash: &mut [u8],
    ) -> CertStoreResult<usize> {
        match self.cert_chain_state[slot_id as usize].as_ref() {
            Some(cert_chain_state) => {
                let hash_size = cert_chain_state.hash_size;
                if root_hash.len() < hash_size {
                    return Err(CertStoreError::BufferTooSmall);
                }
                root_hash[..hash_size]
                    .copy_from_slice(&cert_chain_state.root_cert_hash[..hash_size]);
                Ok(hash_size)
            }
            None => {
                let cert_chain = self.cert_chain[slot_id as usize]
                    .as_mut()
                    .ok_or(CertStoreError::InvalidSlotId)?;

                let hash_algo: HashAlgoType = hash_algo_sel
                    .try_into()
                    .map_err(|_| CertStoreError::UnsupportedHashAlgo)?;

                let hash_size = hash_algo.hash_size();

                if root_hash.len() < hash_size {
                    return Err(CertStoreError::BufferTooSmall);
                }

                cert_chain
                    .root_cert_hash(hash_algo_sel, root_hash)
                    .await
                    .map_err(CertStoreError::CertChain)
            }
        }
    }
}

// #[cfg(test)]
// mod test {
//     use super::*;
//     use crate::protocol::algorithms::BaseHashAlgoType;
//     use crate::protocol::certs::{CertificateInfo, KeyPairID, KeyUsageMask};
//     use crate::protocol::device_capabilities::DeviceCapabilities;
//     use crate::protocol::device_algorithms::LocalDeviceAlgorithms;
//     use crate::protocol::device_algorithms::AlgorithmPriorityTable;
//     use crate::protocol::device_algorithms::{device_algorithms, device_capability_flags};
//     use crate::transport::MctpTransport;
//     use libapi_caliptra::crypto::hash::{HashAlgoType, HashContext};

// }
