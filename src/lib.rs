use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

pub use scrypt::Params as ScryptParams;

pub enum PoWAlgorithm {
    Sha2_256,
    Sha2_512,
    Scrypt(ScryptParams),
}

impl PoWAlgorithm {
    pub fn calculate_sha2_256(data: &[u8], nonce: usize) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);

        hasher.update(nonce.to_le_bytes());

        let final_hash = hasher.finalize();

        final_hash.to_vec()
    }

    pub fn calculate_sha2_512(data: &[u8], nonce: usize) -> Vec<u8> {
        let mut hasher = Sha512::new();
        hasher.update(data);

        hasher.update(nonce.to_le_bytes());

        let final_hash = hasher.finalize();

        final_hash.to_vec()
    }

    pub fn calculate_scrypt(data: &[u8], nonce: usize, params: &ScryptParams) -> Vec<u8> {
        let mut output = Vec::new();

        scrypt::scrypt(data, &nonce.to_le_bytes(), params, &mut output);

        output
    }

    pub fn calculate(&self, data: &[u8], nonce: usize) -> Vec<u8> {
        match self {
            Self::Sha2_256 => Self::calculate_sha2_256(data, nonce),
            Self::Sha2_512 => Self::calculate_sha2_512(data, nonce),
            Self::Scrypt(params) => Self::calculate_scrypt(data, nonce, params),
        }
    }
}

pub struct PoW {
    data: Vec<u8>,
    difficulty: usize,
    algorithm: PoWAlgorithm,
}

impl PoW {
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

    pub fn verify_pow(&self, target: &[u8], pow_result: (Vec<u8>, usize)) -> bool {
        let (hash, nonce) = pow_result;

        let calculated_hash = self.algorithm.calculate(&self.data, nonce);

        if &calculated_hash[..target.len()] == target && calculated_hash == hash {
            return true;
        }
        false
    }
}
