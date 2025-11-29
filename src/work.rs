//! Shared atomic helpers for parallel nonce distribution and early-stop coordination.
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

/// Atomically distributed monotonically increasing nonces.
#[derive(Debug)]
pub struct NonceSource {
    next: AtomicU64,
}

impl NonceSource {
    /// Create a nonce source starting from `start`.
    pub const fn new(start: u64) -> Self {
        Self {
            next: AtomicU64::new(start),
        }
    }

    /// Reserve and return the next nonce.
    #[inline]
    pub fn fetch(&self) -> u64 {
        self.next.fetch_add(1, Ordering::Relaxed)
    }
}

/// Track found hits and coordinate early stop across workers.
#[derive(Debug)]
pub struct HitStop {
    limit: usize,
    found: AtomicUsize,
    stop: AtomicBool,
}

impl HitStop {
    /// Build with a positive hit `limit`.
    pub fn new(limit: usize) -> Result<Self, String> {
        if limit == 0 {
            return Err("hit limit must be >= 1".to_owned());
        }
        Ok(Self {
            limit,
            found: AtomicUsize::new(0),
            stop: AtomicBool::new(false),
        })
    }

    /// Whether workers should stop.
    #[inline]
    pub fn should_stop(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    /// Record a hit; returns `true` if this hit reached the limit and triggered stop.
    pub fn record_hit(&self) -> bool {
        if self.should_stop() {
            return true;
        }
        let prev = self.found.fetch_add(1, Ordering::SeqCst) + 1;
        if prev >= self.limit {
            self.stop.store(true, Ordering::SeqCst);
            true
        } else {
            false
        }
    }

    /// Force stop (e.g., on fatal error).
    pub fn force_stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }

    /// Number of hits recorded so far.
    pub fn found(&self) -> usize {
        self.found.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_source_increments() {
        let ns = NonceSource::new(5);
        assert_eq!(ns.fetch(), 5);
        assert_eq!(ns.fetch(), 6);
    }

    #[test]
    fn hit_stop_triggers_at_limit() {
        let hs = HitStop::new(2).unwrap();
        assert!(!hs.should_stop());
        assert!(!hs.record_hit());
        assert_eq!(hs.found(), 1);
        assert!(hs.record_hit());
        assert!(hs.should_stop());
    }
}
