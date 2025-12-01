use blake3::Hasher as Blake3Hasher;

pub trait TagHasher: Send + Sync + std::fmt::Debug {
    fn hash(&self, data: &[u8]) -> [u8; 32];
}

#[derive(Debug, Default, Clone)]
pub struct Blake3TagHasher;

impl TagHasher for Blake3TagHasher {
    fn hash(&self, data: &[u8]) -> [u8; 32] {
        let mut hasher = Blake3Hasher::new();
        hasher.update(data);
        hasher.finalize().into()
    }
}

pub fn derive_challenge<H: TagHasher + ?Sized>(
    hasher: &H,
    master_challenge: [u8; 32],
    proof_id: u64,
) -> [u8; 32] {
    let mut input = Vec::with_capacity(4 + 32 + 8);
    input.extend_from_slice(b"rspow:equix:challenge:v1|");
    input.extend_from_slice(&master_challenge);
    input.extend_from_slice(&proof_id.to_le_bytes());
    hasher.hash(&input)
}
