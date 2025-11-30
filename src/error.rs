use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    DuplicateProof,
    InvalidDifficulty,
    Malformed,
}

impl Display for VerifyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::DuplicateProof => write!(f, "duplicate proof"),
            VerifyError::InvalidDifficulty => write!(f, "proof does not meet difficulty"),
            VerifyError::Malformed => write!(f, "malformed proof or bundle"),
        }
    }
}

impl std::error::Error for VerifyError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidConfig(String),
    SolverFailed(String),
    ChannelClosed,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidConfig(msg) => write!(f, "invalid config: {msg}"),
            Error::SolverFailed(msg) => write!(f, "solver failed: {msg}"),
            Error::ChannelClosed => write!(f, "solver channel closed"),
        }
    }
}

impl std::error::Error for Error {}
