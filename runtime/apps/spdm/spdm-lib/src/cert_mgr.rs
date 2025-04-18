// Licensed under the Apache-2.0 license
use crate::error::{SpdmError, SpdmResult};
use crate::protocol::BaseHashAlgoType;
use libapi_caliptra::crypto::cert_mgr::{CertMgrContext, CertType};
use libapi_caliptra::crypto::error::CryptoError;
use libapi_caliptra::crypto::hash::{HashAlgoType, HashContext};
use libtock_platform::Syscalls;
use thiserror_no_std::Error;
use zerocopy::{FromBytes, Immutable, IntoBytes}; 
use core::mem::size_of;

use crate::context::SpdmContext;
use core::fmt::Write;


pub const SPDM_MAX_CERT_CHAIN_SLOTS: usize = 8;
pub const SPDM_MAX_HASH_SIZE: usize = 64;
pub const SPDM_CERT_CHAIN_HEADER_SIZE: usize = size_of::<SpdmCertChainHeader>();
// Maximum size of a DER certificate in bytes. Adjust as needed.
pub const MAX_DER_CERT_LENGTH: usize = 1024;

pub const MAX_CERT_COUNT_PER_CHAIN: usize = 2;

pub const MAX_CERT_CHAIN_DATA_SIZE: usize = MAX_DER_CERT_LENGTH * MAX_CERT_COUNT_PER_CHAIN;

pub type SupportedSlotMask = u8;
pub type ProvisionedSlotMask = u8;

// pub struct SpdmCertChainData {
//     pub data: [u8; config::MAX_CERT_CHAIN_DATA_SIZE],
//     pub length: u16,
// }

// impl Default for SpdmCertChainData {
//     fn default() -> Self {
//         SpdmCertChainData {
//             data: [0u8; config::MAX_CERT_CHAIN_DATA_SIZE],
//             length: 0u16,
//         }
//     }
// }

// impl SpdmCertChainData {
//     pub fn new(data: &[u8]) -> Result<Self, SpdmError> {
//         if data.len() > config::MAX_CERT_CHAIN_DATA_SIZE {
//             return Err(SpdmError::InvalidParam);
//         }
//         let mut cert_chain_data = SpdmCertChainData::default();
//         cert_chain_data.data[..data.len()].copy_from_slice(data);
//         cert_chain_data.length = data.len() as u16;
//         Ok(cert_chain_data)
//     }

//     // Add certificate data to the chain.
//     pub fn add(&mut self, data: &[u8]) -> Result<(), SpdmError> {
//         if self.length as usize + data.len() > config::MAX_CERT_CHAIN_DATA_SIZE {
//             return Err(SpdmError::InvalidParam);
//         }
//         self.data[self.length as usize..(self.length as usize + data.len())].copy_from_slice(data);
//         self.length += data.len() as u16;
//         Ok(())
//     }
// }

// impl AsRef<[u8]> for SpdmCertChainData {
//     fn as_ref(&self) -> &[u8] {
//         &self.data[..self.length as usize]
//     }
// }

#[derive(IntoBytes, FromBytes, Immutable)]
#[repr(packed)]
pub struct SpdmCertChainHeader {
    pub length: u16,
    pub reserved: u16,
}

// // Represents the buffer for the SPDM certificate chain base format as defined in SPDM Specification 1.3.2 Table 33.
// // This buffer contains the total length of the certificate chain (2 bytes), reserved bytes (2 bytes) and the root certificate hash.
// pub struct SpdmCertChainBaseBuffer {
//     pub data: [u8; SPDM_CERT_CHAIN_HEADER_SIZE + SPDM_MAX_HASH_SIZE],
//     pub length: u16,
// }

// impl Default for SpdmCertChainBaseBuffer {
//     fn default() -> Self {
//         SpdmCertChainBaseBuffer {
//             data: [0u8; SPDM_CERT_CHAIN_HEADER_SIZE + SPDM_MAX_HASH_SIZE],
//             length: 0u16,
//         }
//     }
// }

// impl AsRef<[u8]> for SpdmCertChainBaseBuffer {
//     fn as_ref(&self) -> &[u8] {
//         &self.data[..self.length as usize]
//     }
// }

// impl SpdmCertChainBaseBuffer {
//     pub fn new(cert_chain_data_len: usize, root_hash: &[u8]) -> Result<Self, DeviceCertsMgrError> {
//         if cert_chain_data_len > config::MAX_CERT_CHAIN_DATA_SIZE
//             || root_hash.len() > SPDM_MAX_HASH_SIZE
//         {
//             Err(DeviceCertsMgrError::BufferTooSmall)?;
//         }

//         let total_len =
//             (cert_chain_data_len + root_hash.len() + SPDM_CERT_CHAIN_HEADER_SIZE) as u16;
//         let mut cert_chain_base_buf = SpdmCertChainBaseBuffer::default();
//         let mut pos = 0;

//         // Length
//         let len = 2;
//         cert_chain_base_buf.data[pos..(pos + len)].copy_from_slice(&total_len.to_le_bytes());
//         pos += len;

//         // Reserved
//         cert_chain_base_buf.data[pos] = 0;
//         cert_chain_base_buf.data[pos + 1] = 0;
//         pos += 2;

//         // Root certificate hash
//         let len = root_hash.len();
//         cert_chain_base_buf.data[pos..(pos + len)].copy_from_slice(root_hash);
//         pos += len;

//         cert_chain_base_buf.length = pos as u16;

//         Ok(cert_chain_base_buf)
//     }
// }

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

// #[derive(Debug, Clone)]
// pub struct CertChainSlotState {
//     // Number of certificates in the chain
//     pub certs_count: usize,
//     // Sizes of each certificate in the chain
//     pub certs_size: [usize; MAX_CERT_COUNT_PER_CHAIN],
//     // The model of the certificate
//     pub cert_model: Option<SpdmCertModel>,
//     // The key pair ID associated with the certificate slot.
//     pub key_pair_id: Option<u8>,
//     // The key usage mask associated with the certificate slot
//     pub key_usage_mask: Option<u16>,
// }

trait CertChainBuf {
    // const MAX_CERT_SIZE : usize;
    // const MAX_CERT_COUNT : usize = 3;
    // fn cert_count(&self) -> usize;
}

pub struct EccCertChainBuffer {
    pub(crate) certs: [[u8; EccCertChainBuffer::MAX_CERT_SIZE]; EccCertChainBuffer::MAX_CERT_COUNT],
    pub(crate) certs_len: [u16; EccCertChainBuffer::MAX_CERT_COUNT],
}

// impl CertChainBuf for EccCertChainBuffer {
//     const MAX_CERT_SIZE: usize = 1024;
// }

impl EccCertChainBuffer {
    pub const MAX_CERT_COUNT: usize = 3;
    pub const MAX_CERT_SIZE: usize = 1024;
    pub fn new() -> Self {
        Self {
            certs: [[0u8; Self::MAX_CERT_SIZE]; Self::MAX_CERT_COUNT],
            certs_len: [0; Self::MAX_CERT_COUNT],
        }
    }

    pub async fn cert_der<S: Syscalls>(&self, cert_index: usize) -> Option<&[u8]> {
        if cert_index < Self::MAX_CERT_COUNT {
            let cert_len = self.certs_len[cert_index as usize];
            if cert_len == 0 {
                return None;
            } else if cert_len <= Self::MAX_CERT_SIZE as u16 {
                Some(&self.certs[cert_index as usize][..cert_len as usize])
            } else {
                None
            }
        } else {
            None
        }
    }

    pub async fn cert_len<S: Syscalls>(&self, cert_index: usize) -> usize {
        self.cert_der::<S>(cert_index)
            .await
            .map(|cert| cert.len())
            .unwrap_or(0)
    }

    pub fn cert_count(&self) -> usize {
        Self::MAX_CERT_COUNT
        // self.certs_len.iter().filter(|&&len| len > 0).count()
    }
}

/// Holds the information about a certificate chain for a specific slot.
pub struct CertSlotInfo<'a> {
    // Certificate chain from `Root CA Certificate` upto `IDevID Certificate`.
    // e.g: Root CA-> Intermediate CA (if any)->IDevID Certificate
    pub(crate) idev_id_cert_chain: &'a [&'a [u8]],
    // The staging buffer that holds the rest of the certificates in the chain.
    // These certificates are fetched from Caliptra Core.
    pub(crate) cert_chain_buf: &'a EccCertChainBuffer,
    // The slot ID of the certificate chain
    pub(crate) slot_id: u8,
    // The model of the certificate chain (e.g., Device, Alias, Generic)
    pub(crate) cert_model: Option<SpdmCertModel>,
    // The key pair ID associated with the certificate slot
    pub(crate) key_pair_id: Option<u8>,
    // The key usage mask associated with the certificate slot
    pub(crate) key_usage_mask: Option<u16>,
    // The maximum number of certificates in the chain
    pub(crate) max_certs_in_chain: u8,
}

impl<'a> CertSlotInfo<'a> {
    pub fn new(
        idev_id_cert_chain: &'a [&'a [u8]],
        cert_chain_buf: &'a EccCertChainBuffer,
        slot_id: u8,
        cert_model: Option<SpdmCertModel>,
        key_pair_id: Option<u8>,
        key_usage_mask: Option<u16>,
    ) -> Self {
        let max_certs_in_chain = idev_id_cert_chain.len() as u8 + cert_chain_buf.cert_count() as u8;
        Self {
            idev_id_cert_chain,
            cert_chain_buf,
            slot_id,
            cert_model,
            key_pair_id,
            key_usage_mask,
            max_certs_in_chain,
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

        let root_ca_cert = self.idev_id_cert_chain[0];
        let root_ca_cert_len = root_ca_cert.len();

        HashContext::<S>::hash_all(hash_algo, &root_ca_cert[..root_ca_cert_len], root_hash)
            .await
            .map_err(DeviceCertsMgrError::CryptoError)?;
        Ok(())
    }

    pub async fn cert_chain_size<S: Syscalls>(&self) -> usize {
        let mut len = self.idev_id_cert_chain.iter().map(|cert| cert.len()).sum();

        // TODO: Add the sizes of the device certs.
        for i in 0..self.cert_chain_buf.cert_count() {
            len += self.cert_chain_buf.cert_len::<S>(i).await;
        }
        len
    }

    pub async fn cert_der<S: Syscalls>(&self, cert_index: usize) -> Option<&[u8]> {
        if cert_index >= self.max_certs_in_chain as usize {
            return None;
        }

        if cert_index < self.idev_id_cert_chain.len() {
            Some(self.idev_id_cert_chain[cert_index])
        } else {
            let cert_index = cert_index - self.idev_id_cert_chain.len();
            self.cert_chain_buf.cert_der::<S>(cert_index).await
        }
    }

    pub async fn cert_chain_digest<S: Syscalls>(
        &self,
        ctx: &mut SpdmContext<'a, S>,
        hash_algo: HashAlgoType,
        digest: &mut [u8],
    ) -> DeviceCertsMgrResult<()> {
        let hash_size = hash_algo.hash_size();
        if digest.len() < hash_size {
            Err(DeviceCertsMgrError::BufferTooSmall)?;
        }

        // println!("cert_chain_digest hash_size: {}", hash_size);

        // Get root certificate hash
        let mut root_hash = [0u8; SPDM_MAX_HASH_SIZE];
        self.root_cert_hash::<S>(hash_algo, &mut root_hash).await?;

        // Get the certificate chain size
        let cert_chain_size = self.cert_chain_size::<S>().await;

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
        
        writeln!(ctx.cw, "SPDM_LIB: cert_chain_digest total_len {} root_hash {:?}", total_len, root_hash).unwrap();

        // Hash the certificate chain data
        for i in 0..self.max_certs_in_chain as usize {

            let cert = self.cert_der::<S>(i).await;
            if let Some(cert) = cert {
                hash_ctx.update(cert).await?;
            }
        }

        // Finalize the hash
        hash_ctx.finalize(digest).await?;
        Ok(())
    }

    pub async fn cert_chain<S: Syscalls>(
        &self,
        cert_chain_buf: &mut [u8],
    ) -> DeviceCertsMgrResult<usize> {
        let cert_chain_size = self.cert_chain_size::<S>().await;

        if cert_chain_buf.len() < cert_chain_size {
            Err(DeviceCertsMgrError::BufferTooSmall)?;
        }

        let mut pos = 0;
        for i in 0..self.max_certs_in_chain as usize {
            let cert = self.cert_der::<S>(i).await;
            if let Some(cert) = cert {
                let len = cert.len();
                cert_chain_buf[pos..pos + len].copy_from_slice(cert);
                pos += len;
            }
        }

        Ok(pos)
    }
}

// impl Default for CertChainSlotState {
//     fn default() -> Self {
//         Self {
//             certs_count: 0,
//             certs_size: [0; MAX_CERT_COUNT_PER_CHAIN],
//             cert_model: None,
//             key_pair_id: None,
//             key_usage_mask: None,
//         }
//     }
// }

/// Manages the device certificates and their associated information.
pub struct DeviceCertsManager<'a> {
    supported_slot_mask: SupportedSlotMask,
    provisioned_slot_mask: ProvisionedSlotMask,
    cert_chain_slot_info: &'a [CertSlotInfo<'a>],
}

impl<'a> DeviceCertsManager<'a> {
    pub fn new(
        supported_slot_mask: SupportedSlotMask,
        provisioned_slot_mask: ProvisionedSlotMask,
        cert_chain_slot_info: &'a [CertSlotInfo<'a>],
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

    pub fn cert_chain_slot_info(&self, slot_id: u8) -> DeviceCertsMgrResult<&CertSlotInfo<'a>> {
        self.cert_chain_slot_info
            .iter()
            .find(|cert_chain| cert_chain.slot_id == slot_id)
            .ok_or(DeviceCertsMgrError::UnsupportedSlotId)
    }

    pub fn cert_chain_slot_mask(
        &self,
    ) -> Result<(SupportedSlotMask, ProvisionedSlotMask), DeviceCertsMgrError> {
        Ok((self.supported_slot_mask, self.provisioned_slot_mask))
    }

    pub async fn construct_cert_chain_buffer<S: Syscalls>(
        &self,
        ctx: &mut SpdmContext<'a, S>,
        hash_algo: HashAlgoType,
        slot_id: u8,
    ) -> DeviceCertsMgrResult<SpdmCertChainBuffer> {
        let mut cert_chain_data = [0u8; MAX_CERT_CHAIN_DATA_SIZE];
        let cert_chain_info = self
            .cert_chain_slot_info
            .iter()
            .find(|cert_chain| cert_chain.slot_id == slot_id)
            .ok_or(DeviceCertsMgrError::UnsupportedSlotId)?;

        let cert_chain_size = cert_chain_info.cert_chain_size::<S>().await;

        writeln!(
            ctx.cw,
            "SPDM_LIB: construct_cert_chain_buffer cert_chain_size {}",
            cert_chain_size
        )
        .unwrap();

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

        let cert_chain_buf = SpdmCertChainBuffer::new(&cert_chain_data[..cert_chain_size], &root_hash[..hash_size])?;
        Ok(cert_chain_buf)
    }
}

// impl<'a> DeviceCertsManager<'a> {
//     /// Retrieves the supported and provisioned slot masks for certificate chains.
//     ///
//     /// # Returns
//     /// - `Ok((SupportedSlotMask, ProvisionedSlotMask))`: A tuple containing the supported
//     ///   and provisioned slot masks.
//     /// - `Err(DeviceCertsMgrError)`: An error if the operation fails.
//     pub fn cert_chain_slot_mask(
//         &self,
//     ) -> Result<(SupportedSlotMask, ProvisionedSlotMask), DeviceCertsMgrError> {
//         Ok((self.supported_slot_mask, self.provisioned_slot_mask))
//     }

//     /// Retrieves the state of the certificate chain for a specific slot, including the
//     /// number of certificates in the chain, the size of each certificate, and the type model.
//     ///
//     /// # Parameters
//     /// - `slot_id`: The ID of the slot to retrieve the certificate chain state for.
//     /// - `cert_chain_slot_info`: A mutable reference to a `CertChainSlotState` structure
//     ///   to store the retrieved state.
//     ///
//     /// # Returns
//     /// - `Ok(())`: If the operation is successful.
//     /// - `Err(DeviceCertsMgrError)`: An error if the operation fails.
//     pub fn (
//         &self,
//         slot_id: u8,
//         cert_chain_slot_info: &mut CertChainSlotState,
//     ) -> Result<(), DeviceCertsMgrError> {
//         let (supported_mask, provisioned_mask) = self.cert_chain_slot_mask()?;
//         let slot_mask = 1 << slot_id;
//         if slot_mask & supported_mask == 0 {
//             return Err(DeviceCertsMgrError::UnsupportedSlotId);
//         }
//         if slot_mask & provisioned_mask == 0 {
//             return Err(DeviceCertsMgrError::UnprovisionedSlotId);
//         }

//         // Fill the cert_chain_slot_info with test cert chain slot information for now.
//         match slot_id {
//             0 => {
//                 cert_chain_slot_info.certs_count = 2;
//                 cert_chain_slot_info.certs_size[0] = config::TEST_ROOT_CA_CERT_DER.len();
//                 cert_chain_slot_info.certs_size[1] = config::DEVID_CERT_DER.len();
//                 cert_chain_slot_info.cert_model = Some(SpdmCertModel::AliasCertModel);
//                 cert_chain_slot_info.key_pair_id = None;
//                 cert_chain_slot_info.key_usage_mask = None;
//             }
//             _ => return Err(DeviceCertsMgrError::UnsupportedSlotId),
//         }

//         Ok(())
//     }

//     fn get_cert_der_data(
//         &self,
//         slot_id: u8,
//         cert_index: usize,
//         cert_data: &mut [u8],
//     ) -> Result<(), DeviceCertsMgrError> {
//         let (supported_mask, provisioned_mask) = self.cert_chain_slot_mask()?;
//         let slot_mask = 1 << slot_id;
//         if slot_mask & supported_mask == 0 {
//             return Err(DeviceCertsMgrError::UnsupportedSlotId);
//         }
//         if slot_mask & provisioned_mask == 0 {
//             return Err(DeviceCertsMgrError::UnprovisionedSlotId);
//         }
//         // Populate the cert data with test cert info for now.
//         match slot_id {
//             0 => match cert_index {
//                 0 => {
//                     if cert_data.len() < config::TEST_ROOT_CA_CERT_DER.len() {
//                         return Err(DeviceCertsMgrError::BufferTooSmall);
//                     }
//                     cert_data[..config::TEST_ROOT_CA_CERT_DER.len()]
//                         .copy_from_slice(&config::TEST_ROOT_CA_CERT_DER);
//                 }
//                 1 => {
//                     if cert_data.len() < config::DEVID_CERT_DER.len() {
//                         return Err(DeviceCertsMgrError::BufferTooSmall);
//                     }
//                     cert_data[..config::DEVID_CERT_DER.len()]
//                         .copy_from_slice(&config::DEVID_CERT_DER);
//                 }
//                 _ => return Err(DeviceCertsMgrError::UnsupportedSlotId),
//             },
//             _ => return Err(DeviceCertsMgrError::UnsupportedSlotId),
//         }

//         Ok(())
//     }
//     /// Constructs the certificate chain data for a specific slot.
//     ///
//     /// This method validates the slot ID, retrieves the slot state, and iterates over
//     /// the certificates in the chain to construct the certificate chain data.
//     ///
//     /// # Parameters
//     /// - `slot_id`: The ID of the slot to construct the certificate chain data for.
//     /// - `cert_chain_data`: A mutable reference to an `SpdmCertChainData` structure
//     ///   to store the constructed certificate chain data.
//     ///
//     /// # Returns
//     /// - `Ok(usize)`: The length of the root certificate if the operation is successful.
//     /// - `Err(DeviceCertsMgrError)`: An error if the operation fails.
//     pub fn construct_cert_chain_data(
//         &self,
//         slot_id: u8,
//         cert_chain_data: &mut SpdmCertChainData,
//     ) -> Result<usize, DeviceCertsMgrError> {
//         let (supported_mask, provisioned_mask) = self.cert_chain_slot_mask()?;
//         let slot_mask = 1 << slot_id;
//         if slot_mask & supported_mask == 0 {
//             return Err(DeviceCertsMgrError::UnsupportedSlotId);
//         }
//         if slot_mask & provisioned_mask == 0 {
//             return Err(DeviceCertsMgrError::UnprovisionedSlotId);
//         }

//         let mut cert_chain_slot_info = CertChainSlotState::default();
//         // Retrieve slot state
//         self.(slot_id, &mut cert_chain_slot_info)?;

//         let mut root_cert_len = 0;
//         // Iterate over certificates in the chain
//         for (i, &cert_len) in cert_chain_slot_info
//             .certs_size
//             .iter()
//             .take(cert_chain_slot_info.certs_count)
//             .enumerate()
//         {
//             let offset = cert_chain_data.length as usize;
//             let cert_buf = cert_chain_data
//                 .data
//                 .get_mut(offset..offset + cert_len)
//                 .ok_or(DeviceCertsMgrError::BufferTooSmall)?;

//             self.get_cert_der_data(slot_id, i, cert_buf)?;
//             cert_chain_data.length += cert_len as u16;
//             if i == 0 {
//                 root_cert_len = cert_len;
//             }
//         }

//         Ok(root_cert_len)
//     }

//     pub async fn cert_chain_digest<S: Syscalls>(
//         &self,
//         slot_id: u8,
//         hash_type: BaseHashAlgoType,
//         digest: &mut [u8],
//     ) -> Result<(), DeviceCertsMgrError> {
//         let mut cert_chain_data = SpdmCertChainData::default();
//         let mut root_hash = [0u8; SPDM_MAX_HASH_SIZE];
//         let root_cert_len = self.construct_cert_chain_data(slot_id, &mut cert_chain_data)?;

//         let hash_algo: HashAlgoType = hash_type
//             .try_into()
//             .map_err(|_| DeviceCertsMgrError::InvalidParam("Invalid hash type"))?;

//         if digest.len() < hash_algo.hash_size() {
//             Err(DeviceCertsMgrError::BufferTooSmall)?;
//         }

//         // Get the hash of root_cert
//         HashContext::<S>::hash_all(
//             hash_algo,
//             &cert_chain_data.as_ref()[..root_cert_len],
//             &mut root_hash,
//         )
//         .await
//         .map_err(DeviceCertsMgrError::CryptoError)?;

//         // Construct the cert chain base buffer
//         let cert_chain_base_buf =
//             SpdmCertChainBaseBuffer::new(cert_chain_data.length as usize, root_hash.as_ref())?;

//         // Start the hash operation
//         let mut hash_ctx = HashContext::<S>::new();

//         // Hash the cert chain base
//         hash_ctx
//             .init(hash_algo, Some(cert_chain_base_buf.as_ref()))
//             .await?;

//         // Hash the cert chain data
//         hash_ctx.update(cert_chain_data.as_ref()).await?;

//         // Finalize the hash operation
//         hash_ctx.finalize(digest).await?;

//         Ok(())
//     }

//     pub async fn construct_cert_chain_buffer<S: Syscalls>(
//         &self,
//         hash_type: BaseHashAlgoType,
//         slot_id: u8,
//     ) -> Result<SpdmCertChainBuffer, DeviceCertsMgrError> {
//         let mut cert_chain_data = SpdmCertChainData::default();
//         let mut root_hash = [0u8; SPDM_MAX_HASH_SIZE];
//         let root_cert_len = self.construct_cert_chain_data(slot_id, &mut cert_chain_data)?;

//         let hash_algo: HashAlgoType = hash_type
//             .try_into()
//             .map_err(|_| DeviceCertsMgrError::InvalidParam("Invalid Hash type"))?;

//         if root_hash.len() < hash_algo.hash_size() {
//             Err(DeviceCertsMgrError::BufferTooSmall)?;
//         }

//         // Get the hash of root_cert
//         HashContext::<S>::hash_all(
//             hash_algo,
//             &cert_chain_data.as_ref()[..root_cert_len],
//             &mut root_hash,
//         )
//         .await
//         .map_err(DeviceCertsMgrError::CryptoError)?;

//         // Construct the cert chain buffer
//         let cert_chain_buffer =
//             SpdmCertChainBuffer::new(cert_chain_data.as_ref(), root_hash.as_ref())?;

//         Ok(cert_chain_buffer)
//     }
// }

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
