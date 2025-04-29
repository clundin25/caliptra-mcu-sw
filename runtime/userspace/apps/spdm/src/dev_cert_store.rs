// Licensed under the Apache-2.0 license
extern crate alloc;

use crate::config::*;
use alloc::boxed::Box;
use async_trait::async_trait;
use spdm_lib::cert_store::{
    CertStoreError, CertStoreResult, SpdmCertStore, MAX_CERT_SLOTS_SUPPORTED,
};
use spdm_lib::protocol::{AsymAlgo, CertificateInfo, KeyPairID, KeyUsageMask, SHA384_HASH_SIZE};

const MAX_ROOT_CERT_CHAIN_LEN: usize = 1;

pub struct DeviceCertStore<'a> {
    pub(crate) cert_chains: [Option<DeviceCertChain<'a>>; MAX_CERT_SLOTS_SUPPORTED as usize],
}

pub struct DeviceCertChain<'b> {
    slot_id: u8,
    root_cert_chain: &'b [&'b [u8]],
    // refresh_leaf_cert: bool,
    leaf_cert: [u8; MAX_CERT_SIZE],
    root_cert_hash: [u8; SHA384_HASH_SIZE],
    device_cert_chain_len: usize,
}

impl<'b> DeviceCertChain<'b> {
    pub async fn new(slot_id: u8) -> CertStoreResult<Self> {
        if slot_id >= MAX_CERT_SLOTS_SUPPORTED {
            Err(CertStoreError::InvalidSlotId)?;
        }

        let root_cert_chain =
            ROOT_CERT_CHAINS[slot_id as usize].ok_or(CertStoreError::InvalidSlotId)?;

        if DPE_LEAF_CERT_LABELS[slot_id as usize].is_none() {
            Err(CertStoreError::InvalidSlotId)?;
        }

        populate_idev_cert(slot_id).await;

        Ok(Self {
            slot_id,
            root_cert_chain,
            // refresh_leaf_cert: false,
            leaf_cert: [0; MAX_CERT_SIZE],
            root_cert_hash: [0; SHA384_HASH_SIZE],
            device_cert_chain_len: 0,
        })
    }
}

#[async_trait]
impl<'b> SpdmCertStore for DeviceCertStore<'b> {
    fn slot_count(&self) -> u8 {
        MAX_CERT_SLOTS_SUPPORTED
    }

    fn is_provisioned(&self, slot_id: u8) -> bool {
        if slot_id >= self.slot_count() {
            return false;
        }
        self.cert_chains[slot_id as usize].is_some()
    }

    async fn cert_chain_len(
        &mut self,
        _asym_algo: AsymAlgo,
        slot_id: u8,
    ) -> CertStoreResult<usize> {
        if slot_id >= self.slot_count() {
            return Err(CertStoreError::InvalidSlotId);
        }

        todo!("Implement cert_chain_len");
    }

    async fn get_cert_chain<'a>(
        &mut self,
        slot_id: u8,
        asym_algo: AsymAlgo,
        offset: usize,
        cert_portion: &'a mut [u8],
    ) -> CertStoreResult<usize> {
        todo!("Implement get_cert_chain");
    }

    async fn root_cert_hash<'a>(
        &mut self,
        slot_id: u8,
        asym_algo: AsymAlgo,
        cert_hash: &'a mut [u8; SHA384_HASH_SIZE],
    ) -> CertStoreResult<()> {
        todo!("Implement root_cert_hash");
    }

    fn key_pair_id(&mut self, slot_id: u8) -> Option<KeyPairID> {
        None
    }

    fn cert_info(&mut self, slot_id: u8) -> Option<CertificateInfo> {
        None
    }
    fn key_usage_mask(&mut self, slot_id: u8) -> Option<KeyUsageMask> {
        None
    }
}

async fn populate_idev_cert(slot_id: u8) -> CertStoreResult<()> {
    if IDEV_CERTS[slot_id as usize].is_none() {
        Err(CertStoreError::InvalidSlotId)
    } else {
        // todo!("Implement populate_idev_cert");
        Ok(())
    }
}
