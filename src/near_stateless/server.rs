use crate::error::Error;
use crate::error::VerifyError;
use crate::near_stateless::cache::ReplayCache;
use crate::near_stateless::prf::DeterministicNonceProvider;
use crate::near_stateless::time::TimeProvider;
use crate::near_stateless::types::{Submission, VerifierConfig};
use crate::near_stateless::{cache::ReplayCacheError, client::derive_master_challenge};
use left_right::{Absorb, ReadHandle, WriteHandle};
use std::sync::{Arc, Mutex};

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

/// Update messages for left-right config.
enum ConfigUpdate {
    Set(VerifierConfig),
}

impl Absorb<ConfigUpdate> for VerifierConfig {
    fn absorb_first(&mut self, update: &mut ConfigUpdate, _first: &Self) {
        match update {
            ConfigUpdate::Set(cfg) => *self = cfg.clone(),
        }
    }

    fn sync_with(&mut self, first: &Self) {
        *self = first.clone();
    }
}

/// Server-side verifier helper for near-stateless PoW submissions.
pub struct NearStatelessVerifier<P: DeterministicNonceProvider, C: ReplayCache, T: TimeProvider> {
    config_r: ReadHandle<VerifierConfig>,
    config_w: Mutex<WriteHandle<VerifierConfig, ConfigUpdate>>,
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
        let (mut config_w, config_r) = left_right::new::<VerifierConfig, ConfigUpdate>();
        config_w.append(ConfigUpdate::Set(config));
        config_w.publish();
        Ok(Self {
            config_r,
            config_w: Mutex::new(config_w),
            nonce_provider,
            replay_cache,
            time_provider,
        })
    }

    /// Update verifier configuration at runtime.
    pub fn set_config(&self, new_config: VerifierConfig) -> Result<(), Error> {
        new_config.validate()?;
        let mut wh = self.config_w.lock().expect("config writer poisoned");
        wh.append(ConfigUpdate::Set(new_config));
        wh.publish();
        Ok(())
    }

    /// Verify a submission against server policy using the provided secret.
    pub fn verify_submission(
        &self,
        server_secret: [u8; 32],
        submission: &Submission,
    ) -> Result<(), NsError> {
        let cfg = self
            .config_r
            .enter()
            .map(|g| g.clone())
            .expect("config read handle closed");

        let now = self.time_provider.now_seconds();
        let ts = submission.timestamp;

        if ts > now {
            return Err(NsError::FutureTimestamp);
        }
        let age = now.saturating_sub(ts);
        let window_secs = cfg.time_window.as_secs();
        if age >= window_secs {
            return Err(NsError::StaleTimestamp);
        }

        // Compute expiry for replay cache: ts + window
        let expires_at = ts.saturating_add(window_secs);

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
