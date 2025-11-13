//! KPoW: k puzzles with an alpha-sized worker pool and a central scheduler.
#![allow(unexpected_cfgs)]
//!
//! Design goals
//! - Deterministic interface: caller sets bits, Argon2 params, worker count, seed, payload.
//! - Puzzles are derived internally from `(seed, payload, index)`; caller does not pass raw puzzles.
//! - Simple scheduler: start with k puzzles; for each puzzle, keep issuing single-try subtasks
//!   (one nonce per task) until that puzzle succeeds; once `k` successes collected, stop.
//! - Verification-friendly: provide `KProof` type and a `verify_proof` helper.
//!
//! Notes on threading/wasm
//! - Native (non-wasm): std::thread worker pool + mpsc channels.
//! - Wasm: if target supports atomics (threaded wasm), use the same model; otherwise fall back to
//!   single-thread execution transparently.

// Enforce threaded WASM by default. To temporarily allow single-thread fallback when
// building for wasm32 without atomics, compile with `--cfg kpow_allow_single_thread`.
#[cfg(all(
    target_arch = "wasm32",
    not(target_feature = "atomics"),
    not(kpow_allow_single_thread)
))]
compile_error!(
    "KPoW requires threaded WebAssembly (wasm32 with +atomics). \
     Enable target features +atomics,+bulk-memory,+mutable-globals and serve with COOP/COEP. \
     For temporary single-thread fallback during experiments, build with --cfg kpow_allow_single_thread."
);

use crate::{meets_leading_zero_bits, Argon2Params, PoWAlgorithm};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Instant;

/// A single proof item sufficient for external verification.
/// Verifier needs: (bits, params, seed, payload, index, nonce, hash) to recompute and check.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KProof {
    pub index: usize,
    pub nonce: u64,
    pub hash: [u8; 32],
}

impl KProof {
    /// Serialize hash as hex for logging or transport (optional helper).
    pub fn hash_hex(&self) -> String {
        hex::encode(self.hash)
    }
}

/// Execution summary for a batch of k puzzles.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KPowResult {
    pub total_time_ms: u128,
    pub total_tries: u64,
    pub successes: usize,
}

/// KPoW configuration: bits, Argon2 params, worker pool size, seed and payload.
#[derive(Clone, Debug)]
pub struct KPow {
    pub bits: u32,
    pub params: Argon2Params,
    pub workers: usize,
    pub seed: [u8; 32],
    pub payload: Vec<u8>,
}

// Note: we intentionally implement Eq/PartialEq/Hash/Serde manually to avoid
// exposing Argon2Params internals or relying on its trait support.
impl PartialEq for KPow {
    fn eq(&self, other: &Self) -> bool {
        self.bits == other.bits
            && self.workers == other.workers
            && self.seed == other.seed
            && self.payload == other.payload
            && self.params.m_cost() == other.params.m_cost()
            && self.params.t_cost() == other.params.t_cost()
            && self.params.p_cost() == other.params.p_cost()
    }
}

impl Eq for KPow {}

impl std::hash::Hash for KPow {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.bits.hash(state);
        self.workers.hash(state);
        self.seed.hash(state);
        self.payload.hash(state);
        self.params.m_cost().hash(state);
        self.params.t_cost().hash(state);
        self.params.p_cost().hash(state);
    }
}

impl Serialize for KPow {
    /// Serialize as a stable, readable struct with Argon2 parameters expanded.
    /// Fields: bits, workers, seed([u8;32]), payload(Vec<u8>), params{m_kib,t_cost,p_cost}.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct ParamsSer {
            m_kib: u32,
            t_cost: u32,
            p_cost: u32,
        }
        #[derive(Serialize)]
        struct KPowSer<'a> {
            bits: u32,
            workers: usize,
            seed: &'a [u8; 32],
            payload: &'a [u8],
            params: ParamsSer,
        }
        let params = ParamsSer {
            m_kib: self.params.m_cost(),
            t_cost: self.params.t_cost(),
            p_cost: self.params.p_cost(),
        };
        let wrapper = KPowSer {
            bits: self.bits,
            workers: self.workers,
            seed: &self.seed,
            payload: &self.payload,
            params,
        };
        wrapper.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for KPow {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct ParamsDe {
            m_kib: u32,
            t_cost: u32,
            p_cost: u32,
        }
        #[derive(Deserialize)]
        struct KPowDe {
            bits: u32,
            workers: usize,
            seed: [u8; 32],
            payload: Vec<u8>,
            params: ParamsDe,
        }
        let raw = KPowDe::deserialize(deserializer)?;
        let params =
            Argon2Params::new(raw.params.m_kib, raw.params.t_cost, raw.params.p_cost, None)
                .map_err(|e| serde::de::Error::custom(e.to_string()))?;
        Ok(KPow {
            bits: raw.bits,
            params,
            workers: raw.workers,
            seed: raw.seed,
            payload: raw.payload,
        })
    }
}

impl KPow {
    /// Create a new KPoW configuration.
    pub fn new(
        bits: u32,
        params: Argon2Params,
        workers: usize,
        seed: [u8; 32],
        payload: Vec<u8>,
    ) -> Self {
        KPow {
            bits,
            params,
            workers,
            seed,
            payload,
        }
    }

    /// Derive `k` puzzles deterministically from (seed, payload).
    /// Convention: puzzle_i = SHA256( b"KPOW" || seed || LE(i,8) || payload ), 32 bytes.
    pub fn derive_puzzles(&self, k: usize) -> Vec<[u8; 32]> {
        let mut out = Vec::with_capacity(k);
        for i in 0..k {
            let mut hasher = Sha256::new();
            hasher.update(b"KPOW");
            hasher.update(self.seed);
            hasher.update((i as u64).to_le_bytes());
            hasher.update(&self.payload);
            let digest = hasher.finalize();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&digest);
            out.push(arr);
        }
        out
    }

    /// Verify a single proof against this KPoW configuration.
    pub fn verify_proof(&self, proof: &KProof) -> bool {
        let puzzles = self.derive_puzzles(proof.index + 1);
        let data = puzzles[proof.index];
        let hash =
            PoWAlgorithm::Argon2id(self.params.clone()).calculate(&data, proof.nonce as usize);
        let mut h32 = [0u8; 32];
        h32.copy_from_slice(&hash);
        h32 == proof.hash && meets_leading_zero_bits(&hash, self.bits)
    }

    /// Solve k puzzles and return only overall stats (legacy/benchmark use).
    /// Prefer `solve_proofs` or `solve_proofs_with_stats` for production/verification flows.
    pub fn solve(&self, k: usize) -> Result<KPowResult, String> {
        let (_proofs, stats) = self.solve_proofs_with_stats(k)?;
        Ok(stats)
    }

    /// Solve k puzzles and return k proofs (no stats, minimal overhead path).
    pub fn solve_proofs(&self, k: usize) -> Result<Vec<KProof>, String> {
        let (proofs, _stats) = self.solve_proofs_inner(k, false)?;
        Ok(proofs)
    }

    /// Solve k puzzles and return (k proofs, overall stats) for benchmarking.
    pub fn solve_proofs_with_stats(&self, k: usize) -> Result<(Vec<KProof>, KPowResult), String> {
        let (proofs, stats_opt) = self.solve_proofs_inner(k, true)?;
        let stats = stats_opt.expect("stats requested but missing");
        Ok((proofs, stats))
    }

    /// Internal entry that routes to parallel/single-thread backends.
    fn solve_proofs_inner(
        &self,
        k: usize,
        with_stats: bool,
    ) -> Result<(Vec<KProof>, Option<KPowResult>), String> {
        #[cfg(any(
            not(target_arch = "wasm32"),
            all(target_arch = "wasm32", target_feature = "atomics"),
        ))]
        {
            self.solve_parallel(k, with_stats)
        }
        #[cfg(not(any(
            not(target_arch = "wasm32"),
            all(target_arch = "wasm32", target_feature = "atomics"),
        )))]
        {
            self.solve_single_thread(k, with_stats)
        }
    }

    /// Single-thread baseline implementation (used on non-threaded wasm targets).
    #[allow(dead_code)]
    fn solve_single_thread(
        &self,
        k: usize,
        with_stats: bool,
    ) -> Result<(Vec<KProof>, Option<KPowResult>), String> {
        let puzzles = self.derive_puzzles(k);
        let start = if with_stats {
            Some(Instant::now())
        } else {
            None
        };
        let mut total_tries: u64 = 0;
        let mut successes = 0usize;
        let mut proofs = Vec::with_capacity(k);

        for (idx, data) in puzzles.into_iter().enumerate() {
            let mut nonce: u64 = 0;
            loop {
                let hash =
                    PoWAlgorithm::Argon2id(self.params.clone()).calculate(&data, nonce as usize);
                if with_stats {
                    total_tries += 1;
                }
                if meets_leading_zero_bits(&hash, self.bits) {
                    successes += 1;
                    let mut h32 = [0u8; 32];
                    h32.copy_from_slice(&hash);
                    proofs.push(KProof {
                        index: idx,
                        nonce,
                        hash: h32,
                    });
                    break;
                }
                nonce = nonce
                    .checked_add(1)
                    .ok_or_else(|| "nonce overflow".to_owned())?;
            }
        }
        let stats = if with_stats {
            Some(KPowResult {
                total_time_ms: start.unwrap().elapsed().as_millis(),
                total_tries,
                successes,
            })
        } else {
            None
        };
        Ok((proofs, stats))
    }

    /// Parallel scheduler + worker pool (native and threaded-wasm).
    #[cfg(any(
        not(target_arch = "wasm32"),
        all(target_arch = "wasm32", target_feature = "atomics"),
    ))]
    fn solve_parallel(
        &self,
        k: usize,
        with_stats: bool,
    ) -> Result<(Vec<KProof>, Option<KPowResult>), String> {
        use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};
        use std::thread;

        if self.workers == 0 {
            return Err("workers must be >= 1".to_owned());
        }

        let puzzles = Arc::new(self.derive_puzzles(k));
        let params = self.params.clone();
        let bits = self.bits;

        struct PuzzleAtomics {
            done: AtomicBool,
            next_nonce: AtomicU64,
        }
        let atoms: Arc<Vec<PuzzleAtomics>> = Arc::new(
            (0..k)
                .map(|_| PuzzleAtomics {
                    done: AtomicBool::new(false),
                    next_nonce: AtomicU64::new(0),
                })
                .collect(),
        );

        let proofs_by_idx: Arc<Vec<Mutex<Option<KProof>>>> =
            Arc::new((0..k).map(|_| Mutex::new(None)).collect());
        let stop = Arc::new(AtomicBool::new(false));
        let successes = Arc::new(AtomicUsize::new(0));
        let total_tries_atomic = Arc::new(AtomicU64::new(0));
        let start = if with_stats {
            Some(Instant::now())
        } else {
            None
        };

        let mut joins = Vec::with_capacity(self.workers);
        for t_id in 0..self.workers {
            let puzzles = puzzles.clone();
            let params = params.clone();
            let atoms = atoms.clone();
            let proofs_by_idx = proofs_by_idx.clone();
            let stop_flag = stop.clone();
            let successes_ctr = successes.clone();
            let tries_ctr = total_tries_atomic.clone();
            let k_local = k;
            let bits_local = bits;
            let j = thread::spawn(move || {
                let mut cursor = t_id % k_local;
                loop {
                    if stop_flag.load(Ordering::Relaxed) {
                        break;
                    }
                    let mut did_work = false;
                    for step in 0..k_local {
                        if stop_flag.load(Ordering::Relaxed) {
                            break;
                        }
                        let idx = (cursor + step) % k_local;
                        let a = &atoms[idx];
                        if a.done.load(Ordering::Relaxed) {
                            continue;
                        }
                        let n = a.next_nonce.fetch_add(1, Ordering::Relaxed);
                        if a.done.load(Ordering::Relaxed) {
                            continue;
                        }
                        let data = puzzles[idx];
                        let hash =
                            PoWAlgorithm::Argon2id(params.clone()).calculate(&data, n as usize);
                        tries_ctr.fetch_add(1, Ordering::Relaxed);
                        if meets_leading_zero_bits(&hash, bits_local)
                            && !a.done.swap(true, Ordering::SeqCst)
                        {
                            let mut h32 = [0u8; 32];
                            h32.copy_from_slice(&hash);
                            if let Ok(mut slot) = proofs_by_idx[idx].lock() {
                                *slot = Some(KProof {
                                    index: idx,
                                    nonce: n,
                                    hash: h32,
                                });
                            }
                            let prev = successes_ctr.fetch_add(1, Ordering::SeqCst) + 1;
                            if prev >= k_local {
                                stop_flag.store(true, Ordering::SeqCst);
                            }
                        }
                        did_work = true;
                        if stop_flag.load(Ordering::Relaxed) {
                            break;
                        }
                    }
                    cursor = (cursor + 1) % k_local;
                    if !did_work {
                        thread::yield_now();
                    }
                }
            });
            joins.push(j);
        }

        for j in joins {
            let _ = j.join();
        }

        let mut proofs: Vec<KProof> = Vec::with_capacity(k);
        for (i, m) in proofs_by_idx.iter().enumerate() {
            if let Ok(guard) = m.lock() {
                if let Some(p) = &*guard {
                    proofs.push(p.clone());
                }
            } else {
                let _ = i;
            }
        }
        let succ = successes.load(Ordering::Relaxed);
        let stats = if with_stats {
            Some(KPowResult {
                total_time_ms: start.unwrap().elapsed().as_millis(),
                total_tries: total_tries_atomic.load(Ordering::Relaxed),
                successes: succ,
            })
        } else {
            None
        };
        Ok((proofs, stats))
    }
}

// --- Wasm threading bootstrap (optional, wasm-only) ---
#[cfg(target_arch = "wasm32")]
mod wasm_threads_init {
    use super::*;
    use wasm_bindgen::prelude::*;

    /// Initialize the wasm thread pool for std::thread on wasm (Web Workers under the hood).
    /// Must be called from JS before invoking parallel KPoW on the main thread.
    /// If not called (or platform lacks atomics), KPoW falls back to single-thread.
    #[wasm_bindgen]
    pub async fn init_wasm_threads(workers: usize) -> Result<(), JsValue> {
        wasm_bindgen_rayon::init_thread_pool(workers)
            .await
            .map_err(|e| JsValue::from_str(&format!("init_thread_pool failed: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{from_str, to_string};
    use std::collections::HashSet;

    #[test]
    fn serde_roundtrip_kproof_and_result() {
        let p = KProof {
            index: 3,
            nonce: 42,
            hash: [7u8; 32],
        };
        let s = to_string(&p).unwrap();
        let back: KProof = from_str(&s).unwrap();
        assert_eq!(p, back);

        let r = KPowResult {
            total_time_ms: 123,
            total_tries: 456,
            successes: 3,
        };
        let s2 = to_string(&r).unwrap();
        let back2: KPowResult = from_str(&s2).unwrap();
        assert_eq!(r, back2);
    }

    #[test]
    fn eq_hash_kpow() {
        let params = Argon2Params::new(16, 2, 1, None).unwrap();
        let a = KPow {
            bits: 8,
            params: params.clone(),
            workers: 2,
            seed: [1u8; 32],
            payload: vec![1, 2, 3],
        };
        let b = KPow {
            bits: 8,
            params: params.clone(),
            workers: 2,
            seed: [1u8; 32],
            payload: vec![1, 2, 3],
        };
        assert_eq!(a, b);
        let mut set = HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
    }

    #[test]
    fn serde_roundtrip_kpow() {
        let params = Argon2Params::new(32, 3, 2, None).unwrap();
        let k = KPow {
            bits: 10,
            params,
            workers: 4,
            seed: [9u8; 32],
            payload: vec![9, 9],
        };
        let s = to_string(&k).unwrap();
        let back: KPow = from_str(&s).unwrap();
        assert_eq!(k, back);
    }
}
