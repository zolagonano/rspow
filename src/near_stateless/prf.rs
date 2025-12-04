use blake3::Hasher;

/// Pluggable provider for deterministic nonces derived from a server secret and timestamp.
pub trait DeterministicNonceProvider: Send + Sync {
    /// Derive a deterministic 32-byte nonce for the given UNIX timestamp (seconds).
    fn derive(&self, secret: [u8; 32], ts: u64) -> [u8; 32];
}

/// Default keyed-BLAKE3 implementation with domain separation.
#[derive(Debug, Clone, Copy, Default)]
pub struct Blake3NonceProvider;

impl DeterministicNonceProvider for Blake3NonceProvider {
    fn derive(&self, secret: [u8; 32], ts: u64) -> [u8; 32] {
        let mut hasher = Hasher::new_keyed(&secret);
        hasher.update(b"rspow:nonce:v1");
        hasher.update(&ts.to_le_bytes());
        hasher.finalize().into()
    }
}
