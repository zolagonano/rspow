//! Near-stateless PoW helpers (feature-gated).
//!
//! Provides building blocks for the near-stateless protocol described in
//! `docs/near_stateless_pow.md`:
//! - Deterministic nonce derivation (keyed BLAKE3) via a pluggable provider.
//! - Replay cache abstraction with a default in-memory (moka) implementation.
//! - Server-side verifier helper that validates the full submission flow.
//! - Client-side helpers to build master challenges and package submissions.

pub mod cache;
pub mod client;
pub mod prf;
pub mod server;
pub mod time;
pub mod types;

pub use crate::near_stateless::client::solve_submission_from_params;
pub use cache::{MokaReplayCache, ReplayCache, ReplayCacheError};
pub use client::build_engine_from_params;
pub use client::{build_submission, derive_master_challenge};
pub use prf::{Blake3NonceProvider, DeterministicNonceProvider};
pub use server::{NearStatelessVerifier, NsError};
pub use time::{SystemTimeProvider, TimeProvider};
pub use types::{SolveParams, Submission, SubmissionBuilderError, VerifierConfig};
