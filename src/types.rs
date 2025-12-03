use crate::core::derive_challenge;
use crate::error::VerifyError;
use crate::pow::{PowBundle, PowConfig, PowProof};
use blake3::hash as blake3_hash;
use equix as equix_crate;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Proof {
    pub id: u64,
    pub challenge: [u8; 32],
    pub solution: [u8; 16],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProofConfig {
    pub bits: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProofBundle {
    pub proofs: Vec<Proof>,
    pub config: ProofConfig,
    pub master_challenge: [u8; 32],
}

impl PowProof for Proof {
    fn id(&self) -> u64 {
        self.id
    }
}

impl PowConfig for ProofConfig {
    fn difficulty(&self) -> u32 {
        self.bits
    }
}

impl PowBundle for ProofBundle {
    type Proof = Proof;
    type Config = ProofConfig;

    fn proofs(&self) -> &[Self::Proof] {
        &self.proofs
    }

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn master_challenge(&self) -> &[u8; 32] {
        &self.master_challenge
    }

    fn insert_proof(&mut self, proof: Self::Proof) -> Result<(), VerifyError> {
        ProofBundle::insert_proof(self, proof)
    }

    fn verify_strict(&self) -> Result<(), VerifyError> {
        ProofBundle::verify_strict(self)
    }
}

impl ProofBundle {
    pub fn len(&self) -> usize {
        self.proofs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.proofs.is_empty()
    }

    pub fn insert_proof(&mut self, proof: Proof) -> Result<(), VerifyError> {
        if self.proofs.iter().any(|p| p.id == proof.id) {
            return Err(VerifyError::DuplicateProof);
        }
        self.proofs.push(proof);
        self.proofs.sort_by_key(|p| p.id);
        Ok(())
    }

    pub fn verify_strict(&self) -> Result<(), VerifyError> {
        let mut prev_id: Option<u64> = None;
        for proof in &self.proofs {
            if let Some(pid) = prev_id {
                if proof.id == pid {
                    return Err(VerifyError::DuplicateProof);
                }
                if proof.id < pid {
                    return Err(VerifyError::Malformed);
                }
            }
            prev_id = Some(proof.id);
            proof.verify(self.config.bits, self.master_challenge)?;
        }
        Ok(())
    }
}

impl Proof {
    pub fn verify(&self, bits: u32, master_challenge: [u8; 32]) -> Result<(), VerifyError> {
        let expected_challenge = derive_challenge(master_challenge, self.id);
        if expected_challenge != self.challenge {
            return Err(VerifyError::Malformed);
        }

        let hash = blake3_hash(&self.solution);
        let hash_bytes: [u8; 32] = *hash.as_bytes();
        let leading = leading_zero_bits(&hash_bytes);
        if leading < bits {
            return Err(VerifyError::InvalidDifficulty);
        }

        let equix = equix_crate::EquiX::new(&self.challenge).map_err(|_| VerifyError::Malformed)?;
        let solution = equix_crate::Solution::try_from_bytes(&self.solution)
            .map_err(|_| VerifyError::Malformed)?;
        equix
            .verify(&solution)
            .map_err(|_| VerifyError::Malformed)?;

        Ok(())
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::EquixEngineBuilder;
    use crate::error::VerifyError;
    use crate::pow::PowEngine;
    use std::sync::atomic::AtomicU64;
    use std::sync::Arc;

    fn small_bundle(bits: u32, required: usize) -> ProofBundle {
        let progress = Arc::new(AtomicU64::new(0));
        let mut engine = EquixEngineBuilder::default()
            .bits(bits)
            .threads(1)
            .required_proofs(required)
            .progress(progress)
            .build()
            .expect("build engine");
        let master = [5u8; 32];
        engine.solve_bundle(master).expect("solve bundle")
    }

    #[test]
    fn verify_strict_accepts_valid_bundle() {
        let bundle = small_bundle(1, 2);
        bundle.verify_strict().expect("bundle should verify");
    }

    #[test]
    fn verify_strict_rejects_duplicate_id() {
        let base = small_bundle(1, 2);
        let first = base.proofs[0];
        let bundle = ProofBundle {
            proofs: vec![first, first],
            config: base.config,
            master_challenge: base.master_challenge,
        };
        let err = bundle
            .verify_strict()
            .expect_err("duplicate id should be rejected");
        assert!(matches!(err, VerifyError::DuplicateProof));
    }

    #[test]
    fn verify_strict_rejects_tampered_challenge() {
        let mut bundle = small_bundle(1, 1);
        bundle.proofs[0].challenge[0] ^= 1;
        let err = bundle
            .verify_strict()
            .expect_err("tampered challenge should be rejected");
        assert!(matches!(err, VerifyError::Malformed));
    }
}
