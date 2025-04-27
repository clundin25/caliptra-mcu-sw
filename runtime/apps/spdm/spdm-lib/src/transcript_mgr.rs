use crate::protocol::version::SpdmVersion;
use libapi_caliptra::crypto::error::CryptoError;
use libapi_caliptra::crypto::hash::{HashAlgoType, HashContext};
use libtock_platform::Syscalls;
use thiserror_no_std::Error;

#[derive(Error, Debug)]
pub enum TranscriptMgrError {
    #[error("Buffer too small")]
    BufferTooSmall,
    #[error("Cryto error")]
    CryptoError(#[from] CryptoError),
    #[error("Invalid parameter {0}")]
    InvalidParam(&'static str),
    #[error("Invalid state {0}")]
    InvalidState(&'static str),
}
pub type TranscriptMgrResult<T> = Result<T, TranscriptMgrError>;

pub struct TranscriptMgr<S: Syscalls> {
    hash_algo: Option<HashAlgoType>,
    // Buffer for Version, Capabilities, and Algorithm SPDM Messages
    vca_buf: VcaBuffer,
    // Hash context for M1/M2
    // M1/M2 = Concatenate(A, B, C)
    // A = Concatenate (GET_VERSION, VERSION, GET_CAPABILITIES, CAPABILITIES, NEGOTIATE_ALGORITHMS, ALGORITHMS)
    // B = Concatenate (GET_DIGESTS, DIGESTS, GET_CERTIFICATE, CERTIFICATE)
    // C = Concatenate (CHALLENGE, CHALLENGE_AUTH(excluding signature))
    m1m2_hash_ctx: Option<HashContext<S>>,
    // SPDM version
    spdm_version: SpdmVersion,
}

struct VcaBuffer {
    vca_buf: [u8; Self::SPDM_MAX_VCA_BUF_SIZE],
    vca_buf_len: usize,
}

impl VcaBuffer {
    pub const SPDM_MAX_VCA_BUF_SIZE: usize = 512;
    pub fn new() -> Self {
        Self {
            vca_buf: [0; Self::SPDM_MAX_VCA_BUF_SIZE],
            vca_buf_len: 0,
        }
    }

    pub fn reset(&mut self) {
        self.vca_buf_len = 0;
    }

    pub fn append(&mut self, data: &[u8]) -> TranscriptMgrResult<()> {
        let len = data.len();
        if self.vca_buf_len + len > self.vca_buf.len() {
            Err(TranscriptMgrError::BufferTooSmall)?;
        }
        self.vca_buf[self.vca_buf_len..self.vca_buf_len + len].copy_from_slice(data);
        self.vca_buf_len += len;
        Ok(())
    }

    fn data(&self) -> &[u8] {
        &self.vca_buf[..self.vca_buf_len]
    }
}

pub enum TranscriptType {
    Vca,
    M1m2,
}

impl<S: Syscalls> TranscriptMgr<S> {
    pub fn new() -> Self {
        Self {
            hash_algo: None,
            vca_buf: VcaBuffer::new(),
            m1m2_hash_ctx: None,
            spdm_version: SpdmVersion::default(),
        }
    }
    pub fn set_hash_algo(&mut self, hash_algo: HashAlgoType) {
        self.hash_algo = Some(hash_algo);
    }

    pub fn set_spdm_version(&mut self, spdm_version: SpdmVersion) {
        self.spdm_version = spdm_version;
    }

    pub fn get_spdm_version(&self) -> SpdmVersion {
        self.spdm_version
    }

    pub fn get_hash_algo(&self) -> HashAlgoType {
        self.hash_algo.expect("Hash algorithm not set")
    }

    pub fn reset(&mut self) {
        self.vca_buf.reset();
        self.m1m2_hash_ctx = None;
        self.spdm_version = SpdmVersion::default();
    }

    pub fn reset_transcript(&mut self, transcript_type: TranscriptType) {
        match transcript_type {
            TranscriptType::Vca => self.vca_buf.reset(),
            TranscriptType::M1m2 => self.m1m2_hash_ctx = None,
        }
    }

    pub async fn update(
        &mut self,
        data: &[u8],
        transcript_type: TranscriptType,
    ) -> TranscriptMgrResult<()> {
        match transcript_type {
            TranscriptType::Vca => self.vca_buf.append(data),
            TranscriptType::M1m2 => self.update_m1m1(data).await,
        }
    }

    async fn update_m1m1(&mut self, data: &[u8]) -> TranscriptMgrResult<()> {
        if let Some(ctx) = &mut self.m1m2_hash_ctx {
            ctx.update(data).await?;
        } else {
            let hash_algo = self
                .hash_algo
                .ok_or(TranscriptMgrError::InvalidState("Hash algorithm not set"))?;

            // Create a new hash context for M1/M2 and hash VCA data
            let vca_data = self.vca_buf.data();
            let mut hash_ctx = HashContext::<S>::new();

            // Initialize and hash the VCA data
            hash_ctx.init(hash_algo, Some(vca_data)).await?;
            hash_ctx.update(data).await?;

            self.m1m2_hash_ctx = Some(hash_ctx);
        }
        Ok(())
    }

    pub async fn get_hash(&mut self, hash: &mut [u8]) -> TranscriptMgrResult<usize> {
        let hash_size = self
            .hash_algo
            .ok_or(TranscriptMgrError::InvalidState("Hash algorithm not set"))?
            .hash_size();
        match &mut self.m1m2_hash_ctx {
            Some(ctx) if hash.len() >= hash_size => {
                ctx.finalize(hash).await?;
                Ok(hash_size)
            }
            Some(_) => Err(TranscriptMgrError::BufferTooSmall),
            None => Err(TranscriptMgrError::InvalidState("Hash context not set")),
        }
    }
}
