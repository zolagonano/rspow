use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum VerifyError {
    #[error("duplicate proof")]
    DuplicateProof,
    #[error("proof does not meet difficulty")]
    InvalidDifficulty,
    #[error("malformed proof or bundle")]
    Malformed,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Error {
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    #[error("solver failed: {0}")]
    SolverFailed(String),
    #[error("solver channel closed")]
    ChannelClosed,
}
