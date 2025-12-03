//! EquiX-only rewrite core library.
//! Currently exposes a synchronous proof-of-work engine and verification types.

pub mod error;
pub mod pow;

pub mod core;
pub mod stream;
pub mod types;

#[cfg(feature = "equix")]
pub mod equix;

#[cfg(feature = "equix")]
pub use crate::equix::{EquixEngine, EquixEngineBuilder, Proof, ProofBundle, ProofConfig};
pub use crate::error::{Error, VerifyError};
pub use crate::pow::{PowBundle, PowConfig, PowEngine, PowProof};
