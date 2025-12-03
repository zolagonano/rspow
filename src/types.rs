use crate::error::Error;

/// Generic result type for proof-of-work operations that can fail with the
/// library's Error type.
pub type ProofResult<T> = Result<T, Error>;

/// Generic solver function type for PoW backends.
///
/// Implementations take a derived challenge and difficulty parameter and either
/// return a candidate solution or indicate that no suitable solution was found.
pub type SolverFn<Solution> =
    dyn Fn([u8; 32], u32) -> Result<Option<Solution>, Error> + Send + Sync;
