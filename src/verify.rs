use crate::core::{self, TagHasher};
use crate::error::VerifyError;
use crate::types::{Proof, ProofBundle};
use equix as equix_crate;
use sha2::{Digest, Sha256};

pub fn verify_proof(proof: &Proof, config_bits: u32) -> Result<(), VerifyError> {
    let equix = equix_crate::EquiX::new(&proof.challenge).map_err(|_| VerifyError::Malformed)?;
    let solution = equix_crate::Solution::try_from_bytes(&proof.solution)
        .map_err(|_| VerifyError::Malformed)?;
    equix
        .verify(&solution)
        .map_err(|_| VerifyError::Malformed)?;

    let mut hasher = Sha256::new();
    hasher.update(proof.solution);
    let hash: [u8; 32] = hasher.finalize().into();
    let leading = leading_zero_bits(&hash);
    if leading < config_bits {
        return Err(VerifyError::InvalidDifficulty);
    }
    Ok(())
}

pub fn verify_bundle_strict(
    bundle: &ProofBundle,
    hasher: &dyn TagHasher,
) -> Result<(), VerifyError> {
    let mut prev_id = None;
    for (expected_id, proof) in bundle.proofs.iter().enumerate() {
        if let Some(pid) = prev_id {
            if proof.id == pid {
                return Err(VerifyError::DuplicateProof);
            }
            if proof.id < pid {
                return Err(VerifyError::Malformed);
            }
        }
        if proof.id != expected_id {
            return Err(VerifyError::Malformed);
        }
        prev_id = Some(proof.id);
        let expected = core::derive_challenge(hasher, bundle.master_challenge, proof.id);
        if expected != proof.challenge {
            return Err(VerifyError::Malformed);
        }
        verify_proof(proof, bundle.config.bits)?;
    }
    Ok(())
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
