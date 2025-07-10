// Licensed under the Apache-2.0 license

use crate::protocol::{SpdmVersion, SHA384_HASH_SIZE};
use libapi_caliptra::crypto::hash::{HashAlgoType, HashContext};
use libapi_caliptra::error::CaliptraApiError;

#[derive(Debug, PartialEq)]
pub enum TranscriptError {
    BufferOverflow,
    InvalidState,
    CaliptraApi(CaliptraApiError),
}

pub type TranscriptResult<T> = Result<T, TranscriptError>;

struct VcaBuffer {
    data: [u8; Self::SPDM_MAX_BUFFER_SIZE],
    size: usize,
}

impl Default for VcaBuffer {
    fn default() -> Self {
        Self {
            data: [0; Self::SPDM_MAX_BUFFER_SIZE],
            size: 0,
        }
    }
}

impl VcaBuffer {
    pub const SPDM_MAX_BUFFER_SIZE: usize = 256;
    fn reset(&mut self) {
        self.data.fill(0);
        self.size = 0;
    }

    fn append(&mut self, data: &[u8]) -> TranscriptResult<()> {
        if self.size + data.len() > Self::SPDM_MAX_BUFFER_SIZE {
            return Err(TranscriptError::BufferOverflow);
        }
        self.data[self.size..self.size + data.len()].copy_from_slice(data);
        self.size += data.len();
        Ok(())
    }

    fn data(&self) -> &[u8] {
        &self.data[..self.size]
    }
}

pub enum TranscriptContext {
    Vca,
    M1,
    L1,
    FinishRspResponderOnly,
}

/// Transcript management for the SPDM responder.
#[derive(Default)]
pub(crate) struct TranscriptManager {
    spdm_version: SpdmVersion,
    // Buffer for storing `VCA`
    // VCA or A = Concatenate (GET_VERSION, VERSION, GET_CAPABILITIES, CAPABILITIES, NEGOTIATE_ALGORITHMS, ALGORITHMS)
    vca_buf: VcaBuffer,
    // Hash context for `M1`
    // M1 = Concatenate(A, B, C)
    // where
    // B = Concatenate (GET_DIGESTS, DIGESTS, GET_CERTIFICATE, CERTIFICATE)
    // C = Concatenate (CHALLENGE, CHALLENGE_AUTH excluding signature)
    hash_ctx_m1: Option<HashContext>,
    // Hash Context for `L1``
    // L1 = Concatenate(A, M) if SPDM_VERSION >= 1.2 or L1 = Concatenate(M) if SPDM_VERSION < 1.2
    // where
    // M = Concatenate (GET_MEASUREMENTS, MEASUREMENTS\signature)
    hash_ctx_l1: Option<HashContext>,

    // KEY_EXCHANGE_RSP transcript contexts:
    // Hash Context for KEY_EXCHANGE_RSP signature transcript
    // KRS = Concatenate(A, B, C)
    // where
    // B = Concatenate(DIGESTS, Hash(cert chain DER) or Hash(pub key))
    // C = Concatenate(KEY_EXCHANGE, KEY_EXCHANGE_RSP excluding signature and ResponderVerifyData)
    hash_ctx_kex_rsp_sig: Option<HashContext>,
    // Hash Context for KEY_EXCHANGE_RSP HMAC transcript
    // KRH = Concatenate(A, B, C)
    // where
    // B = Concatenate(DIGESTS, Hash(cert chain DER) or Hash(pub key))
    // C = Concatenate(KEY_EXCHANGE, KEY_EXCHANGE_RSP excluding ResponderVerifyData)
    hash_ctx_kex_rsp_hmac: Option<HashContext>,

    // FINISH transcript contexts:
    // Hash Context for FINISH Mutual Authentication signature transcript
    // FMAS = Concatenate(A, B, C, D, E)
    // where
    // B = Concatenate(DIGESTS, Hash(cert chain DER) or Hash(pub key))
    // C = Concatenate(KEY_EXCHANGE, KEY_EXCHANGE_RSP)
    // D = Concatenate(DIGESTS, Hash(cert chain DER) or Hash(pub key)) if encapsulated DIGESTS is issued and MULTI_KEY_CONN_REQ is true
    // E = Finish SPDM Header Fields
    hash_ctx_finish_mutual_auth_signature: Option<HashContext>,
    // Hash Context for FINISH Responder Only HMAC transcript
    // FROH = Concatenate(A, B, C, D)
    // where
    // B = Concatenate(DIGESTS, Hash(cert chain DER) or Hash(pub key))
    // C = Concatenate(KEY_EXCHANGE, KEY_EXCHANGE_RSP)
    // D = Finish SPDM Header Fields
    hash_ctx_finish_responder_only_hmac: Option<HashContext>,
    // Hash Context for FINISH Mutual Authentication HMAC transcript
    // FMAH = Concatenate(A, B, C, D, E, F)
    // where
    // B = Concatenate(DIGESTS, Hash(cert chain DER) or Hash(pub key))
    // C = Concatenate(KEY_EXCHANGE, KEY_EXCHANGE_RSP)
    // D = Concatenate(DIGESTS, Hash(cert chain DER) or Hash(pub key)) if encapsulated DIGESTS is issued and MULTI_KEY_CONN_REQ is true
    // E = Finish SPDM Header Fields
    // F = Finish SPDM Signature
    hash_ctx_finish_mutual_auth_hmac: Option<HashContext>,

    // FINISH_RSP transcript contexts:
    // Hash Context for FINISH_RSP Responder Only HMAC transcript
    // FRRO = Concatenate(A, B, C, D, E)
    // where
    // B = Concatenate(DIGESTS, Hash(cert chain DER) or Hash(pub key))
    // C = Concatenate(KEY_EXCHANGE, KEY_EXCHANGE_RSP)
    // D = FINISH
    // E = FINISH_RSP SPDM Header Fields
    hash_ctx_finish_rsp_responder_only: Option<HashContext>,
    // Hash Context for FINISH_RSP Mutual Authentication HMAC transcript
    // FRMA = Concatenate(A, B, C, D, E, F)
    // where
    // B = Concatenate(DIGESTS, Hash(cert chain DER) or Hash(pub key))
    // C = Concatenate(KEY_EXCHANGE, KEY_EXCHANGE_RSP)
    // D = Concatenate(DIGESTS, Hash(cert chain DER) or Hash(pub key)) if encapsulated DIGESTS is issued and MULTI_KEY_CONN_REQ is true
    // E = FINISH
    // F = FINISH_RSP SPDM Header Fields
    hash_ctx_finish_rsp_mutual_auth: Option<HashContext>,
}

impl TranscriptManager {
    pub fn new() -> Self {
        Self {
            spdm_version: SpdmVersion::V10,
            ..Default::default()
        }
    }

    /// Set the SPDM version selected by the SPDM responder.
    ///
    /// # Arguments
    /// * `spdm_version` - The SPDM version to set.
    pub fn set_spdm_version(&mut self, spdm_version: SpdmVersion) {
        self.spdm_version = spdm_version;
    }

    /// Reset a transcript context or all contexts.
    ///
    /// # Arguments
    /// * `context` - The context to reset. If `None`, all contexts are reset.
    pub fn reset(&mut self) {
        self.spdm_version = SpdmVersion::V10;
        self.vca_buf.reset();
        self.hash_ctx_m1 = None;
        self.hash_ctx_l1 = None;
    }

    /// Reset a transcript context.
    ///
    /// # Arguments
    /// * `context` - The context to reset. If `None`, all contexts are reset.
    pub fn reset_context(&mut self, context: TranscriptContext) {
        match context {
            TranscriptContext::Vca => self.vca_buf.reset(),
            TranscriptContext::M1 => self.hash_ctx_m1 = None,
            TranscriptContext::L1 => self.hash_ctx_l1 = None,
            TranscriptContext::FinishRspResponderOnly => {
                self.hash_ctx_finish_rsp_responder_only = None
            }
        }
    }

    /// Append data to a transcript context.
    ///
    /// # Arguments
    /// * `context` - The context to append data to.
    /// * `data` - The data to append.
    ///
    /// # Returns
    /// * `TranscriptResult<()>` - Result indicating success or failure.
    pub async fn append(
        &mut self,
        context: TranscriptContext,
        data: &[u8],
    ) -> TranscriptResult<()> {
        match context {
            TranscriptContext::Vca => self.vca_buf.append(data),
            TranscriptContext::M1 => self.append_m1(data).await,
            TranscriptContext::L1 => self.append_l1(self.spdm_version, data).await,
            TranscriptContext::FinishRspResponderOnly => {
                self.append_hash_ctx_finish_rsp_responder_only(data).await
            }
        }
    }

    /// Finalize the hash for a given context.
    ///
    /// # Arguments
    /// * `context` - The context to finalize the hash for.
    /// * `hash` - The buffer to store the resulting hash.
    ///
    /// # Returns
    /// * `TranscriptResult<()>` - Result indicating success or failure.
    pub async fn hash(
        &mut self,
        context: TranscriptContext,
        hash: &mut [u8; SHA384_HASH_SIZE],
    ) -> TranscriptResult<()> {
        let hash_ctx = match context {
            TranscriptContext::Vca => return Err(TranscriptError::InvalidState),
            TranscriptContext::M1 => self.hash_ctx_m1.as_mut().take(),
            TranscriptContext::L1 => self.hash_ctx_l1.as_mut().take(),
            TranscriptContext::FinishRspResponderOnly => self.hash_ctx_kex_rsp_sig.as_mut().take(),
        };

        if let Some(ctx) = hash_ctx {
            ctx.finalize(hash)
                .await
                .map_err(TranscriptError::CaliptraApi)?;
        } else {
            return Err(TranscriptError::InvalidState);
        }

        Ok(())
    }

    async fn append_m1(&mut self, data: &[u8]) -> TranscriptResult<()> {
        if let Some(ctx) = &mut self.hash_ctx_m1 {
            ctx.update(data).await.map_err(TranscriptError::CaliptraApi)
        } else {
            let vca_data = self.vca_buf.data();
            let mut ctx = HashContext::new();
            ctx.init(HashAlgoType::SHA384, Some(vca_data))
                .await
                .map_err(TranscriptError::CaliptraApi)?;
            ctx.update(data)
                .await
                .map_err(TranscriptError::CaliptraApi)?;
            self.hash_ctx_m1 = Some(ctx);
            Ok(())
        }
    }

    async fn append_l1(&mut self, spdm_version: SpdmVersion, data: &[u8]) -> TranscriptResult<()> {
        if let Some(ctx) = &mut self.hash_ctx_l1 {
            ctx.update(data).await.map_err(TranscriptError::CaliptraApi)
        } else {
            let vca_data = if spdm_version >= SpdmVersion::V12 {
                Some(self.vca_buf.data())
            } else {
                None
            };
            let mut ctx = HashContext::new();
            ctx.init(HashAlgoType::SHA384, vca_data)
                .await
                .map_err(TranscriptError::CaliptraApi)?;
            ctx.update(data)
                .await
                .map_err(TranscriptError::CaliptraApi)?;
            self.hash_ctx_l1 = Some(ctx);
            Ok(())
        }
    }

    // TODO: add wrapper function or macro for this
    async fn append_hash_ctx_finish_rsp_responder_only(
        &mut self,
        data: &[u8],
    ) -> TranscriptResult<()> {
        if let Some(ctx) = &mut self.hash_ctx_finish_rsp_responder_only {
            ctx.update(data).await.map_err(TranscriptError::CaliptraApi)
        } else {
            let mut ctx = HashContext::new();
            ctx.init(HashAlgoType::SHA384, Some(self.vca_buf.data()))
                .await
                .map_err(TranscriptError::CaliptraApi)?;
            ctx.update(data)
                .await
                .map_err(TranscriptError::CaliptraApi)?;
            self.hash_ctx_finish_rsp_responder_only = Some(ctx);
            Ok(())
        }
    }
}
