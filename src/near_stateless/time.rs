use std::time::{SystemTime, UNIX_EPOCH};

/// Abstraction to allow testing/time injection.
pub trait TimeProvider: Send + Sync {
    fn now_seconds(&self) -> u64;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemTimeProvider;

impl TimeProvider for SystemTimeProvider {
    fn now_seconds(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}
