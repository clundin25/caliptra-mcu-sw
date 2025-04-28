// Licensed under the Apache-2.0 license
extern crate alloc;

use crate::config::*;
use alloc::boxed::Box;
use async_trait::async_trait;
use spdm_lib::cert_store::{CertChain, CertChainResult};
use spdm_lib::protocol::{BaseHashAlgoType, CertificateInfo, KeyPairID, KeyUsageMask};

pub struct DeviceCertChain {
    slot_id: u8,
    refresh_leaf_cert: bool,
    leaf_cert: [u8; MAX_CERT_SIZE],
    cert_digest: [u8; MAX_HASH_SIZE],
    cer_chain_len: usize,
}

impl DeviceCertChain {
    pub fn new(slot_id: u8) -> CertChainResult<Self> {
        // Populate IDEV cert
        populate_idev_cert()?;

        Ok(Self {
            slot_id,
            refresh_leaf_cert: true,
            cert_digest: [0; MAX_HASH_SIZE],
            cer_chain_len: 0,
            leaf_cert: [0; MAX_CERT_SIZE],
        })
    }
}

#[async_trait]
impl CertChain for DeviceCertChain {
    // type Error = CertChainError;

    async fn root_cert_hash<'a>(
        &mut self,
        _hash_algo: BaseHashAlgoType,
        _root_hash: &'a mut [u8],
    ) -> CertChainResult<usize> {
        todo!("Implement root_cert_hash function");
    }

    async fn cert_chain_length(&mut self) -> CertChainResult<usize> {
        todo!("Implement cert_chain_length function");
    }

    async fn read_cert_chain<'a>(
        &mut self,
        _offset: usize,
        _cert_portion: &'a mut [u8],
    ) -> CertChainResult<usize> {
        // Read the certificate chain from the device
        todo!("Implement read_cert_chain function");
    }

    fn key_pair_id(&mut self) -> Option<KeyPairID> {
        None
    }

    fn cert_info(&mut self) -> Option<CertificateInfo> {
        None
    }

    fn key_usage_mask(&mut self) -> Option<KeyUsageMask> {
        None
    }
}

fn populate_idev_cert() -> CertChainResult<()> {
    let idev_cert = read_idev_cert()?;
    todo!("Populate the idev_cert into the DeviceCertChain");
}

fn read_idev_cert() -> CertChainResult<()> {
    todo!("Implement read_idev_cert function");
}
