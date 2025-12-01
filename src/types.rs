use crate::core::TagHasher;
use crate::error::VerifyError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Proof {
    pub id: usize,
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

    pub fn verify_strict(&self, hasher: &dyn TagHasher) -> Result<(), VerifyError> {
        crate::verify::verify_bundle_strict(self, hasher)
    }
}
