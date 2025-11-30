use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[derive(Debug)]
pub struct NonceSource {
    next: AtomicU64,
}

impl NonceSource {
    pub const fn new(start: u64) -> Self {
        Self {
            next: AtomicU64::new(start),
        }
    }

    #[inline]
    pub fn fetch(&self) -> u64 {
        self.next.fetch_add(1, Ordering::Relaxed)
    }
}

#[derive(Debug)]
pub struct StopFlag {
    stop: AtomicBool,
}

impl StopFlag {
    pub const fn new() -> Self {
        Self {
            stop: AtomicBool::new(false),
        }
    }

    #[inline]
    pub fn should_stop(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    pub fn force_stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

impl Default for StopFlag {
    fn default() -> Self {
        Self::new()
    }
}
