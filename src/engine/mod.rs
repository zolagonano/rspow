use crate::core::{derive_challenge, Blake3TagHasher, TagHasher};
use crate::error::{Error, VerifyError};
use crate::stream::{NonceSource, StopFlag};
use crate::types::{Proof, ProofBundle, ProofConfig};
use crate::verify::verify_bundle_strict;
use derive_builder::Builder;
use equix as equix_crate;
use sha2::Digest;
use sha2::Sha256;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub trait PowEngine {
    fn solve_bundle(&mut self, master_challenge: [u8; 32]) -> Result<ProofBundle, Error>;
    fn resume(
        &mut self,
        existing: ProofBundle,
        required_proofs: usize,
    ) -> Result<ProofBundle, Error>;
}

#[derive(Builder, Debug)]
#[builder(pattern = "owned")]
pub struct EquixEngine {
    pub bits: u32,
    pub threads: usize,
    pub required_proofs: usize,
    pub progress: Arc<AtomicU64>,
    #[builder(default = "Box::new(Blake3TagHasher)")]
    pub hasher: Box<dyn TagHasher>,
}

impl EquixEngine {
    fn validate(&self) -> Result<(), Error> {
        if self.bits == 0 {
            return Err(Error::InvalidConfig("bits must be > 0".into()));
        }
        if self.threads == 0 {
            return Err(Error::InvalidConfig("threads must be >= 1".into()));
        }
        if self.required_proofs == 0 {
            return Err(Error::InvalidConfig("required_proofs must be >= 1".into()));
        }
        Ok(())
    }
}

impl EquixEngineBuilder {
    fn validate(&self) -> Result<(), Error> {
        if self.bits.unwrap_or(0) == 0 {
            return Err(Error::InvalidConfig("bits must be > 0".into()));
        }
        if self.threads.unwrap_or(0) == 0 {
            return Err(Error::InvalidConfig("threads must be >= 1".into()));
        }
        if self.required_proofs.unwrap_or(0) == 0 {
            return Err(Error::InvalidConfig("required_proofs must be >= 1".into()));
        }
        if self.progress.is_none() {
            return Err(Error::InvalidConfig("progress must be provided".into()));
        }
        Ok(())
    }

    pub fn build_validated(self) -> Result<EquixEngine, Error> {
        self.validate()?;
        self.build()
            .map_err(|e| Error::InvalidConfig(e.to_string()))
    }
}

impl PowEngine for EquixEngine {
    fn solve_bundle(&mut self, master_challenge: [u8; 32]) -> Result<ProofBundle, Error> {
        self.validate()?;
        let mut bundle = ProofBundle {
            proofs: Vec::new(),
            config: ProofConfig { bits: self.bits },
            master_challenge,
        };
        if self.required_proofs == 0 {
            return Ok(bundle);
        }
        let nonce_source = NonceSource::new(0);
        let stop = StopFlag::new();
        let required = self.required_proofs;
        while !stop.should_stop() {
            let id = nonce_source.fetch() as usize;
            let challenge = derive_challenge(&*self.hasher, master_challenge, id);
            match solve_single(challenge, self.bits) {
                Ok(solution) => {
                    let proof = Proof {
                        id,
                        challenge,
                        solution,
                    };
                    bundle.insert_proof(proof).map_err(|err| match err {
                        VerifyError::DuplicateProof => {
                            Error::SolverFailed("duplicate proof".into())
                        }
                        VerifyError::InvalidDifficulty => {
                            Error::SolverFailed("invalid difficulty".into())
                        }
                        VerifyError::Malformed => Error::SolverFailed("malformed proof".into()),
                    })?;
                    let prev = self.progress.fetch_add(1, Ordering::SeqCst) + 1;
                    if prev >= required as u64 {
                        stop.force_stop();
                    }
                }
                Err(err) => return Err(err),
            }
        }
        Ok(bundle)
    }

    fn resume(
        &mut self,
        mut existing: ProofBundle,
        required_proofs: usize,
    ) -> Result<ProofBundle, Error> {
        self.validate()?;
        verify_bundle_strict(&existing).map_err(|e| Error::SolverFailed(e.to_string()))?;
        if required_proofs < existing.len() {
            return Err(Error::InvalidConfig(
                "required_proofs must be >= existing proofs".into(),
            ));
        }
        self.required_proofs = required_proofs;
        self.progress
            .fetch_add(existing.len() as u64, Ordering::SeqCst);
        if existing.len() >= required_proofs {
            return Ok(existing);
        }
        let nonce_source = NonceSource::new(existing.len() as u64);
        let stop = StopFlag::new();
        while existing.len() < required_proofs && !stop.should_stop() {
            let id = nonce_source.fetch() as usize;
            let challenge = derive_challenge(&*self.hasher, existing.master_challenge, id);
            match solve_single(challenge, self.bits) {
                Ok(solution) => {
                    let proof = Proof {
                        id,
                        challenge,
                        solution,
                    };
                    if let Err(err) = existing.insert_proof(proof) {
                        return Err(Error::SolverFailed(err.to_string()));
                    }
                    let prev = self.progress.fetch_add(1, Ordering::SeqCst) + 1;
                    if prev >= required_proofs as u64 {
                        stop.force_stop();
                    }
                }
                Err(err) => return Err(err),
            }
        }
        Ok(existing)
    }
}

fn solve_single(challenge: [u8; 32], bits: u32) -> Result<[u8; 16], Error> {
    let equix =
        equix_crate::EquiX::new(&challenge).map_err(|err| Error::SolverFailed(err.to_string()))?;
    let solutions = equix.solve();
    let mut hasher = Sha256::new();
    for sol in solutions.iter() {
        let bytes = sol.to_bytes();
        hasher.update(bytes);
        let hash: [u8; 32] = hasher.finalize_reset().into();
        if leading_zero_bits(&hash) >= bits {
            return Ok(bytes);
        }
    }
    Err(Error::SolverFailed("no solution meeting difficulty".into()))
}

fn leading_zero_bits(hash: &[u8; 32]) -> u32 {
    let mut count = 0u32;
    for byte in hash {
        if *byte == 0 {
            count += 8;
            continue;
        }
        count += (*byte).leading_zeros();
        break;
    }
    count
}
