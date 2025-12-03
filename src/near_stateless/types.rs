use std::time::Duration;

use crate::equix::types::ProofBundle;
use crate::error::Error;

/// Configuration used by the near-stateless verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierConfig {
    pub time_window: Duration,
    pub min_difficulty: u32,
    pub min_required_proofs: usize,
}

impl VerifierConfig {
    pub fn validate(&self) -> Result<(), Error> {
        if self.time_window.is_zero() {
            return Err(Error::InvalidConfig("time_window must be > 0".into()));
        }
        if self.min_difficulty == 0 {
            return Err(Error::InvalidConfig("min_difficulty must be >= 1".into()));
        }
        if self.min_required_proofs == 0 {
            return Err(Error::InvalidConfig(
                "min_required_proofs must be >= 1".into(),
            ));
        }
        Ok(())
    }
}

/// Payload submitted by clients for verification.
#[derive(Debug, Clone)]
pub struct Submission {
    pub timestamp: u64,
    pub client_nonce: [u8; 32],
    pub proof_bundle: ProofBundle,
}

#[derive(Debug, thiserror::Error)]
pub enum SubmissionBuilderError {
    #[error("invalid config: {0}")]
    InvalidConfig(String),
}
