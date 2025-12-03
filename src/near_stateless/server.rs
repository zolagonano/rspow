use crate::error::Error;
use crate::error::VerifyError;
use crate::near_stateless::cache::ReplayCache;
use crate::near_stateless::prf::DeterministicNonceProvider;
use crate::near_stateless::time::TimeProvider;
use crate::near_stateless::types::{Submission, VerifierConfig};
use crate::near_stateless::{cache::ReplayCacheError, client::derive_master_challenge};
use std::sync::Arc;
use std::sync::RwLock;

#[derive(Debug, thiserror::Error)]
pub enum NsError {
    #[error("timestamp too old")]
    StaleTimestamp,
    #[error("timestamp is in the future")]
    FutureTimestamp,
    #[error("replay detected")]
    Replay,
    #[error("master challenge mismatch")]
    MasterChallengeMismatch,
    #[error("verification failed: {0}")]
    Verify(#[from] VerifyError),
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    #[error("replay cache error: {0}")]
    Cache(#[from] ReplayCacheError),
}

/// Server-side verifier helper for near-stateless PoW submissions.
pub struct NearStatelessVerifier<P: DeterministicNonceProvider, C: ReplayCache, T: TimeProvider> {
    config: RwLock<VerifierConfig>,
    nonce_provider: Arc<P>,
    replay_cache: Arc<C>,
    time_provider: Arc<T>,
}

impl<P, C, T> NearStatelessVerifier<P, C, T>
where
    P: DeterministicNonceProvider + 'static,
    C: ReplayCache + 'static,
    T: TimeProvider + 'static,
{
    pub fn new(
        config: VerifierConfig,
        nonce_provider: Arc<P>,
        replay_cache: Arc<C>,
        time_provider: Arc<T>,
    ) -> Result<Self, Error> {
        config.validate()?;
        Ok(Self {
            config: RwLock::new(config),
            nonce_provider,
            replay_cache,
            time_provider,
        })
    }

    /// Update verifier configuration at runtime.
    pub fn set_config(&self, new_config: VerifierConfig) -> Result<(), Error> {
        new_config.validate()?;
        let mut guard = self.config.write().expect("config lock poisoned");
        *guard = new_config;
        Ok(())
    }

    /// Verify a submission against server policy using the provided secret.
    pub fn verify_submission(
        &self,
        server_secret: [u8; 32],
        submission: &Submission,
    ) -> Result<(), NsError> {
        let cfg = self.config.read().expect("config lock poisoned").clone();

        let now = self.time_provider.now_seconds();
        let ts = submission.timestamp;

        if ts > now {
            return Err(NsError::FutureTimestamp);
        }
        let age = now - ts;
        if age as u128 >= cfg.time_window.as_secs() as u128 {
            return Err(NsError::StaleTimestamp);
        }

        // Compute expiry for replay cache: ts + window
        let expires_at = ts.saturating_add(cfg.time_window.as_secs());

        // Recompute deterministic nonce and master challenge
        let det_nonce = self.nonce_provider.derive(server_secret, ts);
        let master_challenge = derive_master_challenge(det_nonce, submission.client_nonce);

        if submission.proof_bundle.master_challenge != master_challenge {
            return Err(NsError::MasterChallengeMismatch);
        }

        submission
            .proof_bundle
            .verify_strict(cfg.min_difficulty, cfg.min_required_proofs)?;

        let inserted =
            self.replay_cache
                .insert_if_absent(submission.client_nonce, expires_at, now)?;
        if !inserted {
            return Err(NsError::Replay);
        }

        Ok(())
    }
}
