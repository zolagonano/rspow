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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::equix::engine::EquixEngineBuilder;
    use crate::near_stateless::client::{build_submission, solve_submission};
    use crate::near_stateless::prf::DeterministicNonceProvider;
    use crate::near_stateless::time::TimeProvider;
    use crate::pow::PowEngine;
    use std::collections::HashMap;
    use std::sync::atomic::AtomicU64;

    #[derive(Default, Clone)]
    struct MapReplayCache {
        map: Arc<Mutex<HashMap<[u8; 32], u64>>>,
    }

    impl ReplayCache for MapReplayCache {
        fn insert_if_absent(
            &self,
            client_nonce: [u8; 32],
            expires_at: u64,
            now: u64,
        ) -> Result<bool, ReplayCacheError> {
            let mut map = self.map.lock().unwrap();
            if let Some(exp) = map.get(&client_nonce) {
                if *exp > now {
                    return Ok(false);
                }
            }
            map.insert(client_nonce, expires_at);
            Ok(true)
        }
    }

    #[derive(Clone, Copy, Default)]
    struct TestNonceProvider;

    impl DeterministicNonceProvider for TestNonceProvider {
        fn derive(&self, secret: [u8; 32], ts: u64) -> [u8; 32] {
            let mut out = secret;
            out[..8].copy_from_slice(&ts.to_le_bytes());
            out
        }
    }

    #[derive(Clone, Copy)]
    struct FixedTimeProvider {
        now: u64,
    }

    impl TimeProvider for FixedTimeProvider {
        fn now_seconds(&self) -> u64 {
            self.now
        }
    }

    fn make_engine(bits: u32, required: usize) -> EquixEngineBuilder {
        EquixEngineBuilder::default()
            .bits(bits)
            .threads(1)
            .required_proofs(required)
            .progress(Arc::new(AtomicU64::new(0)))
    }

    fn solve_one(
        engine: &mut crate::equix::engine::EquixEngine,
        det: [u8; 32],
        client_nonce: [u8; 32],
        ts: u64,
    ) -> Submission {
        solve_submission(engine, ts, det, client_nonce).expect("solve should succeed")
    }

    fn verifier_with(
        cfg: VerifierConfig,
        time: impl TimeProvider + 'static,
        replay: impl ReplayCache + 'static,
    ) -> NearStatelessVerifier<TestNonceProvider, impl ReplayCache, impl TimeProvider> {
        NearStatelessVerifier::new(
            cfg,
            Arc::new(TestNonceProvider),
            Arc::new(replay),
            Arc::new(time),
        )
        .expect("config should be valid")
    }

    #[test]
    fn config_rejects_subsecond_window() {
        let cfg = VerifierConfig {
            time_window: std::time::Duration::from_millis(900),
            min_difficulty: 1,
            min_required_proofs: 1,
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn verify_submission_happy_path() {
        let mut engine = make_engine(1, 1).build_validated().unwrap();
        let cfg = VerifierConfig {
            time_window: std::time::Duration::from_secs(10),
            ..Default::default()
        };
        let ts = 1_000;
        let now = 1_004;
        let det = TestNonceProvider.derive([9u8; 32], ts);
        let client_nonce = [7u8; 32];
        let submission = solve_one(&mut engine, det, client_nonce, ts);

        let verifier = verifier_with(cfg, FixedTimeProvider { now }, MapReplayCache::default());

        assert!(verifier.verify_submission([9u8; 32], &submission).is_ok());
    }

    #[test]
    fn rejects_future_timestamp() {
        let mut engine = make_engine(1, 1).build_validated().unwrap();
        let ts = 10;
        let det = TestNonceProvider.derive([1u8; 32], ts);
        let submission = solve_one(&mut engine, det, [2u8; 32], ts);
        let verifier = verifier_with(
            VerifierConfig::default(),
            FixedTimeProvider { now: 5 },
            MapReplayCache::default(),
        );

        match verifier.verify_submission([1u8; 32], &submission) {
            Err(NsError::FutureTimestamp) => {}
            other => panic!("expected future timestamp, got {:?}", other),
        }
    }

    #[test]
    fn rejects_stale_timestamp() {
        let mut engine = make_engine(1, 1).build_validated().unwrap();
        let cfg = VerifierConfig {
            time_window: std::time::Duration::from_secs(5),
            ..Default::default()
        };
        let ts = 10;
        let det = TestNonceProvider.derive([3u8; 32], ts);
        let submission = solve_one(&mut engine, det, [4u8; 32], ts);
        let verifier = verifier_with(
            cfg,
            FixedTimeProvider { now: 16 },
            MapReplayCache::default(),
        );

        match verifier.verify_submission([3u8; 32], &submission) {
            Err(NsError::StaleTimestamp) => {}
            other => panic!("expected stale, got {:?}", other),
        }
    }

    #[test]
    fn detects_replay() {
        let mut engine = make_engine(1, 1).build_validated().unwrap();
        let cfg = VerifierConfig {
            time_window: std::time::Duration::from_secs(10),
            ..Default::default()
        };
        let ts = 100;
        let det = TestNonceProvider.derive([5u8; 32], ts);
        let submission = solve_one(&mut engine, det, [6u8; 32], ts);
        let verifier = verifier_with(
            cfg,
            FixedTimeProvider { now: 103 },
            MapReplayCache::default(),
        );

        verifier
            .verify_submission([5u8; 32], &submission)
            .expect("first verify should succeed");

        match verifier.verify_submission([5u8; 32], &submission) {
            Err(NsError::Replay) => {}
            other => panic!("expected replay, got {:?}", other),
        }
    }

    #[test]
    fn config_update_applies_to_verification() {
        let mut engine = make_engine(1, 1).build_validated().unwrap();
        let ts = 200;
        let det = TestNonceProvider.derive([8u8; 32], ts);
        let submission = solve_one(&mut engine, det, [9u8; 32], ts);
        let verifier = verifier_with(
            VerifierConfig {
                time_window: std::time::Duration::from_secs(10),
                ..Default::default()
            },
            FixedTimeProvider { now: 205 },
            MapReplayCache::default(),
        );

        let new_cfg = VerifierConfig {
            time_window: std::time::Duration::from_secs(10),
            min_required_proofs: 2,
            ..Default::default()
        };
        verifier.set_config(new_cfg).unwrap();

        match verifier.verify_submission([8u8; 32], &submission) {
            Err(NsError::Verify(VerifyError::InvalidDifficulty)) => {}
            other => panic!("expected difficulty error, got {:?}", other),
        }
    }

    #[test]
    fn master_challenge_mismatch_is_rejected() {
        let mut engine = make_engine(1, 1).build_validated().unwrap();
        let ts = 50;
        let det = TestNonceProvider.derive([11u8; 32], ts);
        let submission = solve_one(&mut engine, det, [12u8; 32], ts);
        let verifier = verifier_with(
            VerifierConfig {
                time_window: std::time::Duration::from_secs(10),
                ..Default::default()
            },
            FixedTimeProvider { now: 55 },
            MapReplayCache::default(),
        );

        match verifier.verify_submission([99u8; 32], &submission) {
            Err(NsError::MasterChallengeMismatch) => {}
            other => panic!("expected mismatch, got {:?}", other),
        }
    }

    #[test]
    fn build_submission_is_equivalent_to_struct_literal() {
        let mut engine = make_engine(1, 1).build_validated().unwrap();
        let ts = 70;
        let det = TestNonceProvider.derive([13u8; 32], ts);
        let client_nonce = [14u8; 32];
        let master = derive_master_challenge(det, client_nonce);
        let bundle = engine.solve_bundle(master).expect("solve should succeed");

        let via_helper = build_submission(ts, client_nonce, bundle.clone());
        let direct = Submission {
            timestamp: ts,
            client_nonce,
            proof_bundle: bundle,
        };

        assert_eq!(via_helper.timestamp, direct.timestamp);
        assert_eq!(via_helper.client_nonce, direct.client_nonce);
        assert_eq!(
            via_helper.proof_bundle.proofs.len(),
            direct.proof_bundle.proofs.len()
        );
    }
}
