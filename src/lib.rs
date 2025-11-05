use argon2::{Argon2, Algorithm, Version};
use ripemd::Ripemd320;
use serde::Serialize;
use sha2::{Digest, Sha256, Sha512};

pub use argon2::Params as Argon2Params;
pub use scrypt::Params as ScryptParams;

/// Enum defining different Proof of Work (PoW) algorithms.
#[allow(non_camel_case_types)]
pub enum PoWAlgorithm {
    Sha2_256,
    Sha2_512,
    RIPEMD_320,
    Scrypt(ScryptParams),
    Argon2id(Argon2Params),
}

impl PoWAlgorithm {
    /// Calculates SHA-256 hash with given data and nonce.
    pub fn calculate_sha2_256(data: &[u8], nonce: usize) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);

        hasher.update(nonce.to_le_bytes());

        let final_hash = hasher.finalize();

        final_hash.to_vec()
    }

    /// Calculates SHA-512 hash with given data and nonce.
    pub fn calculate_sha2_512(data: &[u8], nonce: usize) -> Vec<u8> {
        let mut hasher = Sha512::new();
        hasher.update(data);

        hasher.update(nonce.to_le_bytes());

        let final_hash = hasher.finalize();

        final_hash.to_vec()
    }

    /// Calculates RIPEMD320 hash with given data and nonce.
    pub fn calculate_ripemd_320(data: &[u8], nonce: usize) -> Vec<u8> {
        let mut hasher = Ripemd320::new();
        hasher.update(data);

        hasher.update(nonce.to_le_bytes());

        let final_hash = hasher.finalize();

        final_hash.to_vec()
    }

    /// Calculates Argon2id hash with given data and nonce.
    pub fn calculate_scrypt(data: &[u8], nonce: usize, params: &ScryptParams) -> Vec<u8> {
        let mut output = vec![0; 32];

        let _ = scrypt::scrypt(data, &nonce.to_le_bytes(), params, &mut output);

        output
    }

    /// Calculates Scrypt hash with given data and nonce.
    pub fn calculate_argon2id(data: &[u8], nonce: usize, params: &Argon2Params) -> Vec<u8> {
        let mut output = vec![0; 32];
        let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params.to_owned());
        a2.hash_password_into(data, &nonce.to_le_bytes(), &mut output)
            .unwrap();

        output
    }

    /// Calculates hash based on the selected algorithm.
    pub fn calculate(&self, data: &[u8], nonce: usize) -> Vec<u8> {
        match self {
            Self::Sha2_256 => Self::calculate_sha2_256(data, nonce),
            Self::Sha2_512 => Self::calculate_sha2_512(data, nonce),
            Self::RIPEMD_320 => Self::calculate_ripemd_320(data, nonce),
            Self::Scrypt(params) => Self::calculate_scrypt(data, nonce, params),
            Self::Argon2id(params) => Self::calculate_argon2id(data, nonce, params),
        }
    }
}

/// Struct representing Proof of Work (PoW) with data, difficulty, and algorithm.
pub struct PoW {
    data: Vec<u8>,
    difficulty: usize,
    algorithm: PoWAlgorithm,
}

impl PoW {
    /// Creates a new instance of PoW with serialized data, difficulty, and algorithm.
    pub fn new(
        data: impl Serialize,
        difficulty: usize,
        algorithm: PoWAlgorithm,
    ) -> Result<Self, String> {
        Ok(PoW {
            data: serde_json::to_vec(&data).unwrap(),
            difficulty,
            algorithm,
        })
    }

    /// Calculates the target of zeros based on the difficulty
    pub fn calculate_target(&self) -> Vec<u8> {
        // 0x30 is code for ascii character '0'
        vec![0x30u8; self.difficulty]
    }

    /// Calculates PoW with the given target hash.
    pub fn calculate_pow(&self, target: &[u8]) -> (Vec<u8>, usize) {
        let mut nonce = 0;

        loop {
            let hash = self.algorithm.calculate(&self.data, nonce);

            if &hash[..target.len()] == target {
                return (hash, nonce);
            }
            nonce += 1;
        }
    }

    /// Verifies PoW with the given target hash and PoW result.
    pub fn verify_pow(&self, target: &[u8], pow_result: (Vec<u8>, usize)) -> bool {
        let (hash, nonce) = pow_result;

        let calculated_hash = self.algorithm.calculate(&self.data, nonce);

        if &calculated_hash[..target.len()] == target && calculated_hash == hash {
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pow_algorithm_sha2_256() {
        let data = b"hello world";
        let nonce = 12345;
        let expected_hash = [
            113, 212, 92, 254, 42, 99, 0, 112, 60, 9, 31, 138, 105, 191, 234, 231, 122, 30, 73, 12,
            3, 10, 182, 230, 134, 80, 94, 32, 162, 164, 204, 9,
        ];
        let hash = PoWAlgorithm::calculate_sha2_256(data, nonce);

        assert_eq!(hash, expected_hash);
    }

    #[test]
    fn test_pow_algorithm_sha2_512() {
        let data = b"hello world";
        let nonce = 12345;
        let expected_hash = [
            166, 65, 125, 254, 189, 250, 254, 9, 146, 145, 86, 129, 163, 210, 160, 17, 234, 234,
            87, 92, 214, 37, 91, 204, 146, 93, 65, 135, 191, 41, 107, 117, 29, 81, 124, 53, 202,
            89, 149, 159, 8, 113, 241, 163, 84, 231, 16, 32, 237, 17, 9, 182, 201, 68, 83, 241, 39,
            23, 106, 152, 58, 110, 134, 144,
        ];
        let hash = PoWAlgorithm::calculate_sha2_512(data, nonce);

        assert_eq!(hash, expected_hash);
    }

    #[test]
    fn test_pow_algorithm_ripemd_320() {
        let data = b"hello world";
        let nonce = 12345;
        let expected_hash = [
            136, 243, 131, 91, 134, 239, 75, 101, 140, 4, 66, 6, 143, 87, 176, 118, 94, 92, 142,
            211, 74, 63, 182, 20, 119, 221, 125, 126, 20, 227, 45, 10, 34, 110, 210, 133, 131, 44,
            45, 23,
        ];

        let hash = PoWAlgorithm::calculate_ripemd_320(data, nonce);

        assert_eq!(hash, expected_hash);
    }

    #[test]
    fn test_pow_algorithm_dispatch_ripemd_320() {
        let data = b"hello world";
        let nonce = 12345;
        let via_dispatch = PoWAlgorithm::RIPEMD_320.calculate(data, nonce);
        let direct = PoWAlgorithm::calculate_ripemd_320(data, nonce);
        assert_eq!(via_dispatch, direct);
    }

    #[test]
    fn test_pow_algorithm_scrypt() {
        let data = b"hello world";
        let nonce = 12345;
        let params = ScryptParams::new(8, 4, 1, 32).unwrap();
        let expected_hash = [
            214, 100, 105, 187, 137, 13, 176, 155, 184, 158, 6, 229, 136, 55, 197, 78, 159, 216,
            153, 53, 214, 163, 145, 214, 252, 84, 4, 185, 92, 91, 111, 234,
        ];

        let hash = PoWAlgorithm::calculate_scrypt(data, nonce, &params);

        assert_eq!(hash, expected_hash);
    }

    #[test]
    fn test_pow_algorithm_argon2id() {
        let data = b"hello world";
        let nonce = 12345;
        let params = Argon2Params::new(16, 2, 2, None).unwrap();
        let expected_hash = [
            243, 150, 29, 238, 126, 244, 47, 122, 69, 22, 69, 20, 102, 5, 218, 124,
            251, 140, 204, 53, 133, 2, 147, 207, 66, 17, 241, 177, 20, 249, 251, 155,
        ];

        let hash = PoWAlgorithm::calculate_argon2id(data, nonce, &params);

        assert_eq!(hash, expected_hash);
    }
    #[test]
    fn test_pow_calculate_pow() {
        let data = "hello world";
        let difficulty = 2;
        let target = "00".as_bytes();
        let algorithm = PoWAlgorithm::Sha2_512;
        let pow = PoW::new(data, difficulty, algorithm).unwrap();

        let (hash, nonce) = pow.calculate_pow(&target);

        assert!(hash.starts_with(&target[..difficulty]));

        assert!(pow.verify_pow(&target, (hash.clone(), nonce)));
    }
}
