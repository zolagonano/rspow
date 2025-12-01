use crate::core::derive_challenge;
use crate::error::VerifyError;
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

        let equix = equix_crate::EquiX::new(&self.challenge).map_err(|_| VerifyError::Malformed)?;
        let solution = equix_crate::Solution::try_from_bytes(&self.solution)
            .map_err(|_| VerifyError::Malformed)?;
        equix
            .verify(&solution)
            .map_err(|_| VerifyError::Malformed)?;

        let hash = blake3_hash(&self.solution);
        let hash_bytes: [u8; 32] = *hash.as_bytes();
        let leading = leading_zero_bits(&hash_bytes);
        if leading < bits {
            return Err(VerifyError::InvalidDifficulty);
        }

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
