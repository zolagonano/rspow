use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};

/// 16-byte EquiX solution wrapper for type safety.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct EquixSolution(pub [u8; 16]);

/// A single EquiX proof (work_nonce + solution bytes).
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct EquixProof {
    pub work_nonce: u64,
    /// Concrete EquiX solution bytes; verifier checks with `equix::verify_bytes`.
    pub solution: EquixSolution,
}

/// A solved EquiX hit with its hashed output.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EquixHit {
    pub proof: EquixProof,
    pub hash: [u8; 32],
}

impl Hash for EquixHit {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.proof.hash(state);
    }
}
