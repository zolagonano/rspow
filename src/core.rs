use blake3::Hasher as Blake3Hasher;

pub fn derive_challenge(master_challenge: [u8; 32], proof_id: u64) -> [u8; 32] {
    let mut hasher = Blake3Hasher::new();
    hasher.update(b"rspow:challenge:v1|");
    hasher.update(&master_challenge);
    hasher.update(&proof_id.to_le_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_challenge_is_deterministic_and_id_sensitive() {
        let master = [42u8; 32];
        let c1 = derive_challenge(master, 0);
        let c2 = derive_challenge(master, 0);
        let c3 = derive_challenge(master, 1);
        assert_eq!(c1, c2, "same input must yield same challenge");
        assert_ne!(c1, c3, "different proof ids should change challenge");
    }
}
