//! EquiX-only rewrite core library.
//! Currently exposes a synchronous proof-of-work engine and verification types.

pub mod error;
pub mod pow;

pub mod core;
#[cfg(feature = "equix")]
pub mod engine;
pub mod stream;
#[cfg(feature = "equix")]
pub mod types;

pub use crate::error::{Error, VerifyError};
pub use crate::pow::{PowBundle, PowConfig, PowEngine, PowProof};
#[cfg(feature = "equix")]
pub use crate::types::{Proof, ProofBundle, ProofConfig};
