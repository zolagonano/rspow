//! EquiX-only rewrite core library.
//! Currently exposes a synchronous proof-of-work engine and verification types.

pub mod core;
pub mod engine;
pub mod error;
pub mod stream;
pub mod types;

pub use crate::engine::{EquixEngine, EquixEngineBuilder, PowEngine};
pub use crate::error::{Error, VerifyError};
pub use crate::types::{Proof, ProofBundle, ProofConfig};
