use blake3::Hasher as Blake3Hasher;

pub fn derive_challenge(master_challenge: [u8; 32], proof_id: u64) -> [u8; 32] {
    let mut hasher = Blake3Hasher::new();
    hasher.update(b"rspow:equix:challenge:v1|");
    hasher.update(&master_challenge);
    hasher.update(&proof_id.to_le_bytes());
    hasher.finalize().into()
}
