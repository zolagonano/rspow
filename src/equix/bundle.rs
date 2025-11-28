use super::types::EquixProof;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

/// A bundle of EquiX proofs along with a base tag for replay protection.
/// Server can store only the `base_tag`; remaining tags can be derived deterministically.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EquixProofBundle {
    pub base_tag: [u8; 32],
    pub proofs: Vec<EquixProof>,
}

impl EquixProofBundle {
    /// Verify all proofs against the provided seed and difficulty.
    ///
    /// Duplicate `(work_nonce, solution)` entries are rejected to avoid replay/dup skew.
    pub fn verify_all(&self, seed: &[u8], bits: u32) -> Result<Vec<bool>, String> {
        let mut out = Vec::with_capacity(self.proofs.len());
        let mut seen = HashSet::with_capacity(self.proofs.len());
        for p in &self.proofs {
            if !seen.insert((p.work_nonce, p.solution.0)) {
                return Err("duplicate EquiX proof in bundle".to_owned());
            }
            let ok = crate::equix_check_bits(seed, p, bits)?;
            out.push(ok);
        }
        Ok(out)
    }

    /// Derived tags for proofs[1..]; server can avoid storing multiple keys.
    pub fn derived_tags(&self) -> Vec<[u8; 32]> {
        if self.proofs.len() <= 1 {
            return Vec::new();
        }
        derive_replay_tags(&self.base_tag, self.proofs.len() - 1)
    }
}

/// Derive replay tags from a base tag to avoid storing multiple keys server-side.
/// If your server has a secret, prefer HMAC(base, idx) at the application layer.
pub fn derive_replay_tags(base_tag: &[u8; 32], count: usize) -> Vec<[u8; 32]> {
    let mut v = Vec::with_capacity(count);
    for i in 1..=count {
        let mut h = Sha256::new();
        h.update(b"rspow:replay:v1|");
        h.update(base_tag);
        h.update((i as u64).to_le_bytes());
        v.push(h.finalize().into());
    }
    v
}
