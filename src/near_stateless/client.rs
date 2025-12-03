use blake3::Hasher;

use crate::equix::{EquixEngine, ProofBundle};
use crate::near_stateless::types::{Submission, SubmissionBuilderError};
use crate::pow::PowEngine;

/// Derive the master challenge used by the EquiX engine.
///
/// Uses the canonical domain tag `"rspow:challenge:v1"`.
pub fn derive_master_challenge(deterministic_nonce: [u8; 32], client_nonce: [u8; 32]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"rspow:challenge:v1");
    hasher.update(&deterministic_nonce);
    hasher.update(&client_nonce);
    hasher.finalize().into()
}

/// Build a submission object from its components.
pub fn build_submission(
    timestamp: u64,
    client_nonce: [u8; 32],
    proof_bundle: ProofBundle,
) -> Submission {
    Submission {
        timestamp,
        client_nonce,
        proof_bundle,
    }
}

/// Convenience helper: derive master challenge, solve with the provided engine, and
/// package into a `Submission`.
pub fn solve_submission(
    engine: &mut EquixEngine,
    timestamp: u64,
    deterministic_nonce: [u8; 32],
    client_nonce: [u8; 32],
) -> Result<Submission, SubmissionBuilderError> {
    let master_challenge = derive_master_challenge(deterministic_nonce, client_nonce);
    let proof_bundle = engine
        .solve_bundle(master_challenge)
        .map_err(|e| SubmissionBuilderError::InvalidConfig(e.to_string()))?;
    Ok(build_submission(timestamp, client_nonce, proof_bundle))
}
