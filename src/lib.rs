//! EquiX-only rewrite core library.
//! Currently exposes a synchronous proof-of-work engine and verification types.

pub mod error;
pub mod pow;

pub mod core;
pub mod engine;
pub mod stream;
pub mod types;

pub use crate::error::{Error, VerifyError};
pub use crate::pow::{PowBundle, PowConfig, PowEngine, PowProof};
pub use crate::types::{Proof, ProofBundle, ProofConfig};
