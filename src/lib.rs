//! RSPOW: simple multi-algorithm proof-of-work utilities.
//!
//! Supported algorithms:
//! - SHA-256, SHA-512, RIPEMD-320
//! - Scrypt, Argon2id (with custom `Params`)
//! - EquiX (Tor's Equi‑X client puzzle; we hash the solution bytes with `sha256`)
//!
//! Difficulty modes:
//! - `AsciiZeroPrefix` (default): hash must start with `difficulty` bytes of ASCII '0' (0x30).
//! - `LeadingZeroBits`: hash must have at least `difficulty` leading zero bits (big-endian within bytes).
//!
//! Quick examples:
//!
//! ```rust
//! use rspow::{PoW, PoWAlgorithm};
//!
//! let data = "hello";
//! let algorithm = PoWAlgorithm::Sha2_256;
//! let pow = PoW::new(data, 2, algorithm).unwrap();
//! let target = pow.calculate_target();
//! let (_hash, _nonce) = pow.calculate_pow(&target);
//! ```
//!
//! ```rust
//! use rspow::{PoW, PoWAlgorithm, DifficultyMode};
//!
//! let data = "hello";
//! let pow = PoW::with_mode(data, 10, PoWAlgorithm::Sha2_256, DifficultyMode::LeadingZeroBits).unwrap();
//! let (_hash, _nonce) = pow.calculate_pow(&[]); // target ignored in bits mode
//! ```
//!
use argon2::{Algorithm, Argon2, Version};
use ripemd::Ripemd320;
use serde::{ser::SerializeStruct, Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
// EquiX solver
use equix as equix_crate;

pub use argon2::Params as Argon2Params;
pub use scrypt::Params as ScryptParams;

// Expose KPoW (k puzzles with worker pool) utilities.
pub mod kpow;

pub mod bench {
    use super::{meets_leading_zero_bits, Argon2Params, PoWAlgorithm};
    use hex::encode as hex_encode;
    use serde::{Deserialize, Serialize};
    use std::convert::TryFrom;
    use std::time::Instant;

    /// Result of a single Proof-of-Work run.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct BenchOutcome {
        pub bits: u32,
        pub data_len: usize,
        pub time_ms: u128,
        pub tries: u64,
        pub nonce: u64,
        pub hash_hex: String,
        pub m_kib: u32,
        pub t_cost: u32,
        pub p_cost: u32,
    }

    const Z95: f64 = 1.959963984540054;
    const Z99: f64 = 2.5758293035489004;

    fn confidence_bounds(mean: f64, stderr: f64) -> (f64, f64, f64, f64) {
        if stderr <= f64::EPSILON {
            return (mean, mean, mean, mean);
        }

        let ci95_low = mean - Z95 * stderr;
        let ci95_high = mean + Z95 * stderr;
        let ci99_low = mean - Z99 * stderr;
        let ci99_high = mean + Z99 * stderr;
        (ci95_low, ci95_high, ci99_low, ci99_high)
    }

    /// Construct Argon2 parameters from memory cost (KiB), time cost, and parallelism.
    #[allow(dead_code)]
    pub fn argon2_params_kib(
        memory_cost_kib: u32,
        time_cost: u32,
        parallelism: u32,
    ) -> Result<Argon2Params, String> {
        Argon2Params::new(memory_cost_kib, time_cost, parallelism, None)
            .map_err(|err| err.to_string())
    }

    /// Aggregated statistics over multiple runs.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct BenchSummary {
        pub mean_time_ms: f64,
        pub std_time_ms: f64,
        pub min_time_ms: u128,
        pub max_time_ms: u128,
        pub stderr_time_ms: f64,
        pub ci95_low_time_ms: f64,
        pub ci95_high_time_ms: f64,
        pub ci99_low_time_ms: f64,
        pub ci99_high_time_ms: f64,
        pub mean_tries: f64,
        pub std_tries: f64,
        pub min_tries: u64,
        pub max_tries: u64,
        pub stderr_tries: f64,
        pub ci95_low_tries: f64,
        pub ci95_high_tries: f64,
        pub ci99_low_tries: f64,
        pub ci99_high_tries: f64,
    }

    /// Compute summary statistics across multiple outcomes.
    #[allow(dead_code)]
    pub fn summarize(outcomes: &[BenchOutcome]) -> Result<BenchSummary, String> {
        if outcomes.is_empty() {
            return Err("no outcomes supplied".to_owned());
        }

        let count = outcomes.len() as f64;

        let mut sum_time = 0.0f64;
        let mut sum_time_sq = 0.0f64;
        let mut sum_tries = 0.0f64;
        let mut sum_tries_sq = 0.0f64;
        let mut min_time = u128::MAX;
        let mut max_time = u128::MIN;
        let mut min_tries = u64::MAX;
        let mut max_tries = u64::MIN;

        for outcome in outcomes {
            let time = outcome.time_ms as f64;
            let tries = outcome.tries as f64;
            sum_time += time;
            sum_time_sq += time * time;
            sum_tries += tries;
            sum_tries_sq += tries * tries;
            min_time = min_time.min(outcome.time_ms);
            max_time = max_time.max(outcome.time_ms);
            min_tries = min_tries.min(outcome.tries);
            max_tries = max_tries.max(outcome.tries);
        }

        let mean_time_ms = sum_time / count;
        let n = outcomes.len() as f64;
        let std_time_ms = if outcomes.len() > 1 {
            let variance_time = (sum_time_sq - (sum_time * sum_time) / n) / (n - 1.0);
            variance_time.max(0.0).sqrt()
        } else {
            0.0
        };

        let stderr_time_ms = if n > 0.0 { std_time_ms / n.sqrt() } else { 0.0 };

        let (ci95_low_time_ms, ci95_high_time_ms, ci99_low_time_ms, ci99_high_time_ms) =
            confidence_bounds(mean_time_ms, stderr_time_ms);

        let mean_tries = sum_tries / count;
        let std_tries = if outcomes.len() > 1 {
            let variance_tries = (sum_tries_sq - (sum_tries * sum_tries) / n) / (n - 1.0);
            variance_tries.max(0.0).sqrt()
        } else {
            0.0
        };

        let stderr_tries = if n > 0.0 { std_tries / n.sqrt() } else { 0.0 };

        let (ci95_low_tries, ci95_high_tries, ci99_low_tries, ci99_high_tries) =
            confidence_bounds(mean_tries, stderr_tries);

        Ok(BenchSummary {
            mean_time_ms,
            std_time_ms,
            min_time_ms: min_time,
            max_time_ms: max_time,
            stderr_time_ms,
            ci95_low_time_ms,
            ci95_high_time_ms,
            ci99_low_time_ms,
            ci99_high_time_ms,
            mean_tries,
            std_tries,
            min_tries,
            max_tries,
            stderr_tries,
            ci95_low_tries,
            ci95_high_tries,
            ci99_low_tries,
            ci99_high_tries,
        })
    }

    /// CSV header shared by run rows and summary rows.
    #[allow(dead_code)]
    pub const fn csv_header() -> &'static str {
        "kind,algo,mode,m_kib,t_cost,p_cost,data_len,bits,run_idx,time_ms,tries,nonce,hash_hex,mean_time_ms,std_time_ms,stderr_time_ms,ci95_low_time_ms,ci95_high_time_ms,ci99_low_time_ms,ci99_high_time_ms,min_time_ms,max_time_ms,mean_tries,std_tries,stderr_tries,ci95_low_tries,ci95_high_tries,ci99_low_tries,ci99_high_tries,min_tries,max_tries"
    }

    /// Format a single run outcome as a CSV row.
    #[allow(dead_code)]
    pub fn csv_row_run(outcome: &BenchOutcome, algo: &str, mode: &str, run_idx: u32) -> String {
        format!(
            "run,{algo},{mode},{},{},{},{},{},{},{},{},{},{},,,,,,,,",
            outcome.m_kib,
            outcome.t_cost,
            outcome.p_cost,
            outcome.data_len,
            outcome.bits,
            run_idx,
            outcome.time_ms,
            outcome.tries,
            outcome.nonce,
            outcome.hash_hex
        )
    }

    /// Format summary statistics as a CSV row.
    #[allow(dead_code)]
    #[allow(clippy::too_many_arguments)]
    pub fn csv_row_summary(
        bits: u32,
        data_len: usize,
        m_kib: u32,
        t_cost: u32,
        p_cost: u32,
        summary: &BenchSummary,
        algo: &str,
        mode: &str,
    ) -> String {
        format!(
            "summary,{algo},{mode},{m_kib},{t_cost},{p_cost},{data_len},{bits},,,,,,{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{},{},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{},{}",
            summary.mean_time_ms,
            summary.std_time_ms,
            summary.stderr_time_ms,
            summary.ci95_low_time_ms,
            summary.ci95_high_time_ms,
            summary.ci99_low_time_ms,
            summary.ci99_high_time_ms,
            summary.min_time_ms,
            summary.max_time_ms,
            summary.mean_tries,
            summary.std_tries,
            summary.stderr_tries,
            summary.ci95_low_tries,
            summary.ci95_high_tries,
            summary.ci99_low_tries,
            summary.ci99_high_tries,
            summary.min_tries,
            summary.max_tries
        )
    }

    /// Run Argon2id PoW search once using LeadingZeroBits difficulty.
    #[allow(dead_code)]
    pub fn bench_argon2_leading_bits_once(
        data: &[u8],
        bits: u32,
        params: &Argon2Params,
        start_nonce: u64,
    ) -> Result<BenchOutcome, String> {
        let mut nonce = start_nonce;
        let mut tries: u64 = 0;
        let algorithm = PoWAlgorithm::Argon2id(params.clone());
        let start = Instant::now();

        loop {
            let nonce_usize = usize::try_from(nonce)
                .map_err(|_| "nonce exceeds usize::MAX on this platform".to_owned())?;
            let hash = algorithm.calculate(data, nonce_usize);
            tries = tries
                .checked_add(1)
                .ok_or_else(|| "tries overflow".to_owned())?;
            if meets_leading_zero_bits(&hash, bits) {
                let time_ms = start.elapsed().as_millis();
                return Ok(BenchOutcome {
                    bits,
                    data_len: data.len(),
                    time_ms,
                    tries,
                    nonce,
                    hash_hex: hex_encode(hash),
                    m_kib: params.m_cost(),
                    t_cost: params.t_cost(),
                    p_cost: params.p_cost(),
                });
            }
            nonce = nonce
                .checked_add(1)
                .ok_or_else(|| "nonce overflow".to_owned())?;
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn summarize_basic_stats() {
            let outcomes = [
                BenchOutcome {
                    bits: 1,
                    data_len: 4,
                    time_ms: 10,
                    tries: 2,
                    nonce: 5,
                    hash_hex: String::new(),
                    m_kib: 8,
                    t_cost: 1,
                    p_cost: 1,
                },
                BenchOutcome {
                    bits: 1,
                    data_len: 4,
                    time_ms: 20,
                    tries: 4,
                    nonce: 6,
                    hash_hex: String::new(),
                    m_kib: 8,
                    t_cost: 1,
                    p_cost: 1,
                },
            ];

            let summary = summarize(&outcomes).expect("summary");
            assert_eq!(summary.min_time_ms, 10);
            assert_eq!(summary.max_time_ms, 20);
            assert_eq!(summary.min_tries, 2);
            assert_eq!(summary.max_tries, 4);
            assert!((summary.mean_time_ms - 15.0).abs() < f64::EPSILON);
            assert!((summary.mean_tries - 3.0).abs() < f64::EPSILON);
            assert!((summary.std_time_ms - 7.0710678118654755).abs() < 1e-9);
            assert!((summary.stderr_time_ms - 5.0).abs() < 1e-9);
            assert!((summary.ci95_low_time_ms - 5.200180077299731).abs() < 1e-6);
            assert!((summary.ci95_high_time_ms - 24.79981992270027).abs() < 1e-6);
            assert!((summary.ci99_low_time_ms - 2.120853482255498).abs() < 1e-6);
            assert!((summary.ci99_high_time_ms - 27.879146517744502).abs() < 1e-6);
            assert!((summary.std_tries - 1.4142135623730951).abs() < 1e-9);
            assert!((summary.stderr_tries - 1.0).abs() < 1e-9);
            assert!((summary.ci95_low_tries - 1.040036015459946).abs() < 1e-6);
            assert!((summary.ci95_high_tries - 4.959963984540054).abs() < 1e-6);
            assert!((summary.ci99_low_tries - 0.4241706964510996).abs() < 1e-6);
            assert!((summary.ci99_high_tries - 5.5758293035489).abs() < 1e-6);
        }

        #[test]
        fn summarize_single_sample() {
            let outcomes = [BenchOutcome {
                bits: 1,
                data_len: 4,
                time_ms: 42,
                tries: 7,
                nonce: 10,
                hash_hex: String::new(),
                m_kib: 8,
                t_cost: 1,
                p_cost: 1,
            }];

            let summary = summarize(&outcomes).expect("summary");
            assert_eq!(summary.mean_time_ms, 42.0);
            assert_eq!(summary.std_time_ms, 0.0);
            assert_eq!(summary.stderr_time_ms, 0.0);
            assert_eq!(summary.ci95_low_time_ms, 42.0);
            assert_eq!(summary.ci95_high_time_ms, 42.0);
            assert_eq!(summary.ci99_low_time_ms, 42.0);
            assert_eq!(summary.ci99_high_time_ms, 42.0);
            assert_eq!(summary.mean_tries, 7.0);
            assert_eq!(summary.std_tries, 0.0);
            assert_eq!(summary.stderr_tries, 0.0);
        }

        #[test]
        fn csv_alignment_summary_columns() {
            let header = csv_header();
            let h: Vec<&str> = header.split(',').collect();
            // Build a tiny summary from two outcomes
            let outcomes = [
                BenchOutcome {
                    bits: 1,
                    data_len: 4,
                    time_ms: 10,
                    tries: 2,
                    nonce: 0,
                    hash_hex: String::new(),
                    m_kib: 8,
                    t_cost: 1,
                    p_cost: 1,
                },
                BenchOutcome {
                    bits: 1,
                    data_len: 4,
                    time_ms: 20,
                    tries: 4,
                    nonce: 0,
                    hash_hex: String::new(),
                    m_kib: 8,
                    t_cost: 1,
                    p_cost: 1,
                },
            ];
            let s = summarize(&outcomes).unwrap();
            let row = csv_row_summary(1, 4, 8, 1, 1, &s, "argon2id", "leading_zero_bits");
            let c: Vec<&str> = row.split(',').collect();
            assert_eq!(h.len(), c.len(), "header/row column count mismatch");
            // Header indices (1-based): 19=ci99_low_time_ms, 20=ci99_high_time_ms
            let ci99_low_time: f64 = c[18].parse().unwrap();
            let ci99_high_time: f64 = c[19].parse().unwrap();
            assert!(ci99_low_time <= ci99_high_time);
            // 28=ci99_low_tries, 29=ci99_high_tries (1-based)
            let ci99_low_tries: f64 = c[27].parse().unwrap();
            let ci99_high_tries: f64 = c[28].parse().unwrap();
            assert!(ci99_low_tries <= ci99_high_tries);
        }
    }
}

/// Enum defining different Proof of Work (PoW) algorithms.
#[allow(non_camel_case_types)]
#[derive(Clone, Debug)]
pub enum PoWAlgorithm {
    Sha2_256,
    Sha2_512,
    RIPEMD_320,
    Scrypt(ScryptParams),
    Argon2id(Argon2Params),
    /// Equi‑X client puzzle: challenge is `data || nonce_le`.
    /// If one or more solutions exist, take the lexicographically smallest
    /// solution's bytes, hash with `sha256`, and use that as the output.
    /// If there is no solution or construction fails, return 32 bytes of 0xFF
    /// (ensures difficulty check fails).
    EquiX,
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

    /// Calculates EquiX-based pseudo-hash with given data and nonce.
    ///
    /// Rule: challenge = `data || nonce.to_le_bytes()`. Run EquiX.
    /// If solutions exist, choose the lexicographically smallest 16‑byte
    /// solution and return `sha256(solution_bytes)`; otherwise or on error,
    /// return 32 bytes of `0xFF`.
    pub fn calculate_equix(data: &[u8], nonce: usize) -> Vec<u8> {
        // Build challenge: data || nonce (little‑endian)
        let mut challenge = Vec::with_capacity(data.len() + std::mem::size_of::<usize>());
        challenge.extend_from_slice(data);
        challenge.extend_from_slice(&nonce.to_le_bytes());

        // Instantiate EquiX and solve
        let equix = match equix_crate::EquiX::new(&challenge) {
            Ok(e) => e,
            Err(_) => return vec![0xFFu8; 32],
        };
        let solutions = equix.solve();
        if solutions.is_empty() {
            return vec![0xFFu8; 32];
        }

        // Pick lexicographically smallest solution bytes
        let mut best: Option<Vec<u8>> = None;
        for sol in solutions.iter() {
            let bytes = sol.to_bytes(); // fixed 16 bytes
            match &mut best {
                None => best = Some(bytes.to_vec()),
                Some(prev) => {
                    if bytes.as_slice() < prev.as_slice() {
                        *prev = bytes.to_vec();
                    }
                }
            }
        }

        let best_bytes = best.expect("solutions not empty");
        let mut hasher = Sha256::new();
        hasher.update(&best_bytes);
        hasher.finalize().to_vec()
    }

    /// Calculates hash based on the selected algorithm.
    pub fn calculate(&self, data: &[u8], nonce: usize) -> Vec<u8> {
        match self {
            Self::Sha2_256 => Self::calculate_sha2_256(data, nonce),
            Self::Sha2_512 => Self::calculate_sha2_512(data, nonce),
            Self::RIPEMD_320 => Self::calculate_ripemd_320(data, nonce),
            Self::Scrypt(params) => Self::calculate_scrypt(data, nonce, params),
            Self::Argon2id(params) => Self::calculate_argon2id(data, nonce, params),
            Self::EquiX => Self::calculate_equix(data, nonce),
        }
    }
}

/// Utility: check whether `hash` has at least `bits` leading zero bits.
///
/// Convention: count leading zero bits in big-endian bit order within each byte
/// (i.e., the most significant bit is checked first).
/// - When `bits == 0`, return `true`.
/// - When `bits > hash.len() * 8`, return `false`.
pub fn meets_leading_zero_bits(hash: &[u8], bits: u32) -> bool {
    if bits == 0 {
        return true;
    }
    let total_bits = (hash.len() as u32) * 8;
    if bits > total_bits {
        return false;
    }

    let full_bytes = (bits / 8) as usize;
    let rem_bits = (bits % 8) as u8;

    // Full-zero check for bytes fully covered by `bits`.
    for b in hash.iter().take(full_bytes) {
        if *b != 0 {
            return false;
        }
    }

    // Remaining high bits in the next byte must be zero as well.
    if rem_bits > 0 {
        let b = hash[full_bytes];
        let mask = 0xFFu8 << (8 - rem_bits);
        if (b & mask) != 0 {
            return false;
        }
    }

    true
}

/// Difficulty modes supported by PoW.
#[derive(Clone, Copy, Debug)]
pub enum DifficultyMode {
    /// Legacy mode: prefix must be ASCII '0' bytes (0x30), one per difficulty level.
    AsciiZeroPrefix,
    /// New mode: require a given number of leading zero bits.
    LeadingZeroBits,
}

/// Struct representing Proof of Work (PoW) with data, difficulty, and algorithm.
#[derive(Clone, Debug)]
pub struct PoW {
    data: Vec<u8>,
    difficulty: usize,
    algorithm: PoWAlgorithm,
    mode: DifficultyMode,
}

// ---- Eq / PartialEq / Hash for DifficultyMode, PoWAlgorithm, PoW ----

impl PartialEq for DifficultyMode {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::AsciiZeroPrefix, Self::AsciiZeroPrefix)
                | (Self::LeadingZeroBits, Self::LeadingZeroBits)
        )
    }
}
impl Eq for DifficultyMode {}
impl std::hash::Hash for DifficultyMode {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            DifficultyMode::AsciiZeroPrefix => 0u8.hash(state),
            DifficultyMode::LeadingZeroBits => 1u8.hash(state),
        }
    }
}

impl PartialEq for PoWAlgorithm {
    fn eq(&self, other: &Self) -> bool {
        use PoWAlgorithm::*;
        match (self, other) {
            (Sha2_256, Sha2_256) => true,
            (Sha2_512, Sha2_512) => true,
            (RIPEMD_320, RIPEMD_320) => true,
            (Scrypt(a), Scrypt(b)) => a.log_n() == b.log_n() && a.r() == b.r() && a.p() == b.p(),
            (Argon2id(a), Argon2id(b)) => {
                a.m_cost() == b.m_cost() && a.t_cost() == b.t_cost() && a.p_cost() == b.p_cost()
            }
            (EquiX, EquiX) => true,
            _ => false,
        }
    }
}
impl Eq for PoWAlgorithm {}
impl std::hash::Hash for PoWAlgorithm {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        use PoWAlgorithm::*;
        match self {
            Sha2_256 => 0u8.hash(state),
            Sha2_512 => 1u8.hash(state),
            RIPEMD_320 => 2u8.hash(state),
            Scrypt(p) => {
                3u8.hash(state);
                p.log_n().hash(state);
                p.r().hash(state);
                p.p().hash(state);
            }
            Argon2id(p) => {
                4u8.hash(state);
                p.m_cost().hash(state);
                p.t_cost().hash(state);
                p.p_cost().hash(state);
            }
            EquiX => 5u8.hash(state),
        }
    }
}

impl PartialEq for PoW {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
            && self.difficulty == other.difficulty
            && self.algorithm == other.algorithm
            && self.mode == other.mode
    }
}
impl Eq for PoW {}
impl std::hash::Hash for PoW {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.data.hash(state);
        self.difficulty.hash(state);
        self.algorithm.hash(state);
        self.mode.hash(state);
    }
}

// ---- Serde for DifficultyMode, PoWAlgorithm, PoW ----

impl Serialize for DifficultyMode {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> Result<<S as serde::Serializer>::Ok, <S as serde::Serializer>::Error>
    where
        S: serde::Serializer,
    {
        match self {
            DifficultyMode::AsciiZeroPrefix => serializer.serialize_str("AsciiZeroPrefix"),
            DifficultyMode::LeadingZeroBits => serializer.serialize_str("LeadingZeroBits"),
        }
    }
}

impl<'de> Deserialize<'de> for DifficultyMode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "AsciiZeroPrefix" => Ok(DifficultyMode::AsciiZeroPrefix),
            "LeadingZeroBits" => Ok(DifficultyMode::LeadingZeroBits),
            other => Err(serde::de::Error::unknown_variant(
                other,
                &["AsciiZeroPrefix", "LeadingZeroBits"],
            )),
        }
    }
}

impl Serialize for PoWAlgorithm {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use PoWAlgorithm::*;
        match self {
            Sha2_256 => serializer.serialize_str("Sha2_256"),
            Sha2_512 => serializer.serialize_str("Sha2_512"),
            RIPEMD_320 => serializer.serialize_str("RIPEMD_320"),
            EquiX => serializer.serialize_str("EquiX"),
            Scrypt(p) => {
                #[derive(Serialize)]
                struct ScryptParamsSer {
                    log_n: u8,
                    r: u32,
                    p: u32,
                }
                let wrapper = ScryptParamsSer {
                    log_n: p.log_n(),
                    r: p.r(),
                    p: p.p(),
                };
                let mut st = serializer.serialize_struct("Scrypt", 1)?;
                st.serialize_field("Scrypt", &wrapper)?;
                st.end()
            }
            Argon2id(p) => {
                #[derive(Serialize)]
                struct Argon2ParamsSer {
                    m_kib: u32,
                    t_cost: u32,
                    p_cost: u32,
                }
                let wrapper = Argon2ParamsSer {
                    m_kib: p.m_cost(),
                    t_cost: p.t_cost(),
                    p_cost: p.p_cost(),
                };
                let mut st = serializer.serialize_struct("Argon2id", 1)?;
                st.serialize_field("Argon2id", &wrapper)?;
                st.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for PoWAlgorithm {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{Error, MapAccess, Visitor};
        use std::fmt;

        // Accept either a unit string variant or an object {Variant: {..}} for params variants
        struct AlgoVisitor;
        impl<'de> Visitor<'de> for AlgoVisitor {
            type Value = PoWAlgorithm;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("PoWAlgorithm as string or single-key object")
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                match v {
                    "Sha2_256" => Ok(PoWAlgorithm::Sha2_256),
                    "Sha2_512" => Ok(PoWAlgorithm::Sha2_512),
                    "RIPEMD_320" => Ok(PoWAlgorithm::RIPEMD_320),
                    "EquiX" => Ok(PoWAlgorithm::EquiX),
                    _ => Err(E::unknown_variant(
                        v,
                        &[
                            "Sha2_256",
                            "Sha2_512",
                            "RIPEMD_320",
                            "Scrypt",
                            "Argon2id",
                            "EquiX",
                        ],
                    )),
                }
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                if let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "Scrypt" => {
                            #[derive(Deserialize)]
                            struct ScryptParamsDe {
                                log_n: u8,
                                r: u32,
                                p: u32,
                            }
                            let p = map.next_value::<ScryptParamsDe>()?;
                            // We default to 32 bytes output length which matches this crate's use.
                            let params = ScryptParams::new(p.log_n, p.r, p.p, 32)
                                .map_err(|e| A::Error::custom(e.to_string()))?;
                            Ok(PoWAlgorithm::Scrypt(params))
                        }
                        "Argon2id" => {
                            #[derive(Deserialize)]
                            struct Argon2ParamsDe {
                                m_kib: u32,
                                t_cost: u32,
                                p_cost: u32,
                            }
                            let p = map.next_value::<Argon2ParamsDe>()?;
                            let params = Argon2Params::new(p.m_kib, p.t_cost, p.p_cost, None)
                                .map_err(|e| A::Error::custom(e.to_string()))?;
                            Ok(PoWAlgorithm::Argon2id(params))
                        }
                        other => Err(A::Error::unknown_field(other, &["Scrypt", "Argon2id"])),
                    }
                } else {
                    Err(A::Error::custom("empty map for PoWAlgorithm"))
                }
            }
        }
        deserializer.deserialize_any(AlgoVisitor)
    }
}

impl Serialize for PoW {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("PoW", 4)?;
        st.serialize_field("data", &self.data)?;
        st.serialize_field("difficulty", &self.difficulty)?;
        st.serialize_field("algorithm", &self.algorithm)?;
        st.serialize_field("mode", &self.mode)?;
        st.end()
    }
}

impl<'de> Deserialize<'de> for PoW {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct PoWDe {
            data: Vec<u8>,
            difficulty: usize,
            algorithm: PoWAlgorithm,
            mode: DifficultyMode,
        }
        let raw = PoWDe::deserialize(deserializer)?;
        Ok(PoW {
            data: raw.data,
            difficulty: raw.difficulty,
            algorithm: raw.algorithm,
            mode: raw.mode,
        })
    }
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
            mode: DifficultyMode::AsciiZeroPrefix,
        })
    }

    /// Creates a new instance of PoW with explicit difficulty mode.
    pub fn with_mode(
        data: impl Serialize,
        difficulty: usize,
        algorithm: PoWAlgorithm,
        mode: DifficultyMode,
    ) -> Result<Self, String> {
        Ok(PoW {
            data: serde_json::to_vec(&data).unwrap(),
            difficulty,
            algorithm,
            mode,
        })
    }

    /// Calculates the target of ASCII '0' bytes based on difficulty.
    ///
    /// Note: meaningful only for `AsciiZeroPrefix` mode; ignored for `LeadingZeroBits`.
    pub fn calculate_target(&self) -> Vec<u8> {
        // 0x30 is code for ascii character '0'
        vec![0x30u8; self.difficulty]
    }

    /// Calculates PoW with the given target hash.
    /// For `AsciiZeroPrefix`, the `target` must be the ASCII '0' prefix of length `difficulty`.
    /// For `LeadingZeroBits`, `target` is ignored; `difficulty` is interpreted as bit count.
    pub fn calculate_pow(&self, target: &[u8]) -> (Vec<u8>, usize) {
        let mut nonce = 0;

        loop {
            let hash = self.algorithm.calculate(&self.data, nonce);
            match self.mode {
                DifficultyMode::AsciiZeroPrefix => {
                    if &hash[..target.len()] == target {
                        return (hash, nonce);
                    }
                }
                DifficultyMode::LeadingZeroBits => {
                    if meets_leading_zero_bits(&hash, self.difficulty as u32) {
                        return (hash, nonce);
                    }
                }
            }
            nonce += 1;
        }
    }

    /// Verifies PoW with the given target hash and PoW result.
    pub fn verify_pow(&self, target: &[u8], pow_result: (Vec<u8>, usize)) -> bool {
        let (hash, nonce) = pow_result;

        let calculated_hash = self.algorithm.calculate(&self.data, nonce);
        match self.mode {
            DifficultyMode::AsciiZeroPrefix => {
                if &calculated_hash[..target.len()] == target && calculated_hash == hash {
                    return true;
                }
                false
            }
            DifficultyMode::LeadingZeroBits => {
                if meets_leading_zero_bits(&calculated_hash, self.difficulty as u32)
                    && calculated_hash == hash
                {
                    return true;
                }
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{from_str, to_string};
    use std::collections::HashSet;

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
            243, 150, 29, 238, 126, 244, 47, 122, 69, 22, 69, 20, 102, 5, 218, 124, 251, 140, 204,
            53, 133, 2, 147, 207, 66, 17, 241, 177, 20, 249, 251, 155,
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

    #[test]
    fn test_pow_calculate_pow_leading_zero_bits() {
        // Use fast hash to keep test time acceptable.
        let data = "hello world";
        let bits = 8; // ~256 expected tries
        let algorithm = PoWAlgorithm::Sha2_256;
        let pow = PoW::with_mode(data, bits, algorithm, DifficultyMode::LeadingZeroBits).unwrap();

        // target is ignored for bits mode; pass empty slice for clarity.
        let (hash, nonce) = pow.calculate_pow(&[]);
        assert!(meets_leading_zero_bits(&hash, bits as u32));
        assert!(pow.verify_pow(&[], (hash, nonce)));
    }

    // -------- Leading‑zero‑bits helper tests --------
    #[test]
    fn test_meets_leading_zero_bits_basic() {
        // 0x00 0x00 0xFF -> first 16 bits are 0; the 17th bit is 1
        let h = [0x00u8, 0x00u8, 0xFFu8];
        assert!(meets_leading_zero_bits(&h, 0));
        assert!(meets_leading_zero_bits(&h, 1));
        assert!(meets_leading_zero_bits(&h, 7));
        assert!(meets_leading_zero_bits(&h, 8));
        assert!(meets_leading_zero_bits(&h, 9));
        assert!(meets_leading_zero_bits(&h, 15));
        assert!(meets_leading_zero_bits(&h, 16));
        assert!(!meets_leading_zero_bits(&h, 17));
    }

    #[test]
    fn test_meets_leading_zero_bits_edges() {
        // MSB is 1: 0x80 -> 1000_0000
        let h1 = [0x80u8, 0x00u8];
        assert!(!meets_leading_zero_bits(&h1, 1));

        // 0x7F -> 0111_1111, has only 1 leading zero bit
        let h2 = [0x7Fu8, 0xFFu8];
        assert!(meets_leading_zero_bits(&h2, 1));
        assert!(!meets_leading_zero_bits(&h2, 2));

        // 0x00 0x80: first 8 bits are zero; the 9th is 1
        let h3 = [0x00u8, 0x80u8];
        assert!(meets_leading_zero_bits(&h3, 8));
        assert!(!meets_leading_zero_bits(&h3, 9));

        // Out of range: bits exceed available bit length
        let h4 = [0x00u8, 0x00u8, 0x00u8];
        assert!(meets_leading_zero_bits(&h4, 24));
        assert!(!meets_leading_zero_bits(&h4, 25));
    }

    // -------- Serde/Eq/Hash regression tests --------
    #[test]
    fn serde_roundtrip_powalgorithm_variants() {
        let a1 = PoWAlgorithm::Sha2_256;
        let s1 = to_string(&a1).unwrap();
        let b1: PoWAlgorithm = from_str(&s1).unwrap();
        assert_eq!(a1, b1);

        let a2 = PoWAlgorithm::Argon2id(Argon2Params::new(16, 2, 1, None).unwrap());
        let s2 = to_string(&a2).unwrap();
        let b2: PoWAlgorithm = from_str(&s2).unwrap();
        assert_eq!(a2, b2);

        let a3 = PoWAlgorithm::Scrypt(ScryptParams::new(8, 4, 1, 32).unwrap());
        let s3 = to_string(&a3).unwrap();
        let b3: PoWAlgorithm = from_str(&s3).unwrap();
        assert_eq!(a3, b3);

        let a4 = PoWAlgorithm::EquiX;
        let s4 = to_string(&a4).unwrap();
        let b4: PoWAlgorithm = from_str(&s4).unwrap();
        assert_eq!(a4, b4);
    }

    #[test]
    fn serde_roundtrip_pow() {
        let pow = PoW::with_mode(
            "data",
            12,
            PoWAlgorithm::Sha2_256,
            DifficultyMode::LeadingZeroBits,
        )
        .unwrap();
        let s = to_string(&pow).unwrap();
        let back: PoW = from_str(&s).unwrap();
        assert_eq!(pow, back);
    }

    #[test]
    fn hash_set_pow_and_algo() {
        let pow = PoW::new("hi", 2, PoWAlgorithm::Sha2_512).unwrap();
        let mut hs = HashSet::new();
        hs.insert(pow.clone());
        assert!(hs.contains(&pow));

        let algo = PoWAlgorithm::Argon2id(Argon2Params::new(32, 3, 2, None).unwrap());
        let mut hs2 = HashSet::new();
        hs2.insert(algo.clone());
        assert!(hs2.contains(&algo));
    }

    // -------- EquiX basic integration tests --------
    #[test]
    fn test_pow_algorithm_equix_calculate_deterministic() {
        let data = b"hello world";
        let nonce = 42usize;
        let h1 = PoWAlgorithm::calculate_equix(data, nonce);
        let h2 = PoWAlgorithm::calculate_equix(data, nonce);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32);
    }

    #[test]
    fn test_pow_equix_bits_zero_trivial() {
        // bits=0 should pass immediately at nonce=0 (verification also succeeds),
        // providing a fast regression without heavy computation.
        let data = "hello equix";
        let pow = PoW::with_mode(
            data,
            0,
            PoWAlgorithm::EquiX,
            DifficultyMode::LeadingZeroBits,
        )
        .unwrap();
        let (hash, nonce) = pow.calculate_pow(&[]);
        assert_eq!(nonce, 0);
        assert_eq!(hash.len(), 32);
        assert!(pow.verify_pow(&[], (hash, nonce)));
    }
}
