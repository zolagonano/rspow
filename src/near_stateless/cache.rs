use moka::sync::Cache;

/// Error type for replay cache operations.
#[derive(Debug, thiserror::Error)]
pub enum ReplayCacheError {
    #[error("replay cache operation failed: {0}")]
    Other(String),
}

/// Replay cache abstraction for preventing duplicate client_nonce submissions.
pub trait ReplayCache: Send + Sync {
    /// Insert the nonce with the given expiry (unix seconds) if absent or expired.
    /// Returns `Ok(true)` if inserted, `Ok(false)` if it already existed and is still valid.
    fn insert_if_absent(
        &self,
        client_nonce: [u8; 32],
        expires_at: u64,
        now: u64,
    ) -> Result<bool, ReplayCacheError>;
}

/// In-memory replay cache backed by `moka::sync::Cache` storing expiry timestamps.
#[derive(Debug, Clone)]
pub struct MokaReplayCache {
    inner: Cache<[u8; 32], u64>,
}

impl MokaReplayCache {
    pub fn new(max_capacity: u64) -> Self {
        Self {
            inner: Cache::builder().max_capacity(max_capacity).build(),
        }
    }
}

impl ReplayCache for MokaReplayCache {
    fn insert_if_absent(
        &self,
        client_nonce: [u8; 32],
        expires_at: u64,
        now: u64,
    ) -> Result<bool, ReplayCacheError> {
        if let Some(exp) = self.inner.get(&client_nonce) {
            if exp > now {
                return Ok(false);
            }
            self.inner.invalidate(&client_nonce);
        }
        self.inner.insert(client_nonce, expires_at);
        Ok(true)
    }
}
