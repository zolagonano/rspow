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
use sha2::{Digest, Sha256};
use std::time::Instant;

/// A single proof item sufficient for external verification.
/// Verifier needs: (bits, params, seed, payload, index, nonce, hash) to recompute and check.
#[derive(Clone, Debug)]
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
#[derive(Clone, Debug)]
pub struct KPowResult {
    pub total_time_ms: u128,
    pub total_tries: u64,
    pub successes: usize,
}

/// KPoW configuration: bits, Argon2 params, worker pool size, seed and payload.
pub struct KPow {
    pub bits: u32,
    pub params: Argon2Params,
    pub workers: usize,
    pub seed: [u8; 32],
    pub payload: Vec<u8>,
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
            hasher.update(&self.seed);
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
        let hash = PoWAlgorithm::Argon2id(self.params.clone())
            .calculate(&data, proof.nonce as usize);
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
            return self.solve_parallel(k, with_stats);
        }
        #[cfg(not(any(
            not(target_arch = "wasm32"),
            all(target_arch = "wasm32", target_feature = "atomics"),
        )))]
        {
            return self.solve_single_thread(k, with_stats);
        }
    }

    /// Single-thread baseline implementation (used on non-threaded wasm targets).
    fn solve_single_thread(
        &self,
        k: usize,
        with_stats: bool,
    ) -> Result<(Vec<KProof>, Option<KPowResult>), String> {
        let puzzles = self.derive_puzzles(k);
        let start = if with_stats { Some(Instant::now()) } else { None };
        let mut total_tries: u64 = 0;
        let mut successes = 0usize;
        let mut proofs = Vec::with_capacity(k);

        for (idx, data) in puzzles.into_iter().enumerate() {
            let mut nonce: u64 = 0;
            loop {
                let hash = PoWAlgorithm::Argon2id(self.params.clone())
                    .calculate(&data, nonce as usize);
                if with_stats {
                    total_tries += 1;
                }
                if meets_leading_zero_bits(&hash, self.bits) {
                    successes += 1;
                    let mut h32 = [0u8; 32];
                    h32.copy_from_slice(&hash);
                    proofs.push(KProof { index: idx, nonce, hash: h32 });
                    break;
                }
                nonce = nonce.checked_add(1).ok_or_else(|| "nonce overflow".to_owned())?;
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
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::mpsc;
        use std::sync::Arc;
        use std::thread;

        if self.workers == 0 {
            return Err("workers must be >= 1".to_owned());
        }

        let puzzles = Arc::new(self.derive_puzzles(k));
        let params = self.params.clone();
        let bits = self.bits;

        // Task and result channels
        #[derive(Clone, Copy)]
        struct Task {
            idx: usize,
            nonce: u64,
        }
        #[derive(Clone, Copy)]
        struct Res {
            idx: usize,
            nonce: u64,
            ok: bool,
            hash: [u8; 32],
        }

        let (task_tx, task_rx) = mpsc::channel::<Task>();
        let (res_tx, res_rx) = mpsc::channel::<Res>();
        let stop = Arc::new(AtomicBool::new(false));

        // Spawn workers
        let mut joins = Vec::with_capacity(self.workers);
        for _ in 0..self.workers {
            let rx = task_rx.clone();
            let tx = res_tx.clone();
            let puzzles = puzzles.clone();
            let params = params.clone();
            let stop = stop.clone();
            let j = thread::spawn(move || {
                while let Ok(Task { idx, nonce }) = rx.recv() {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    let data = puzzles[idx];
                    let hash = PoWAlgorithm::Argon2id(params.clone())
                        .calculate(&data, nonce as usize);
                    let ok = meets_leading_zero_bits(&hash, bits);
                    let mut h32 = [0u8; 32];
                    h32.copy_from_slice(&hash);
                    let _ = tx.send(Res { idx, nonce, ok, hash: h32 });
                }
            });
            joins.push(j);
        }
        drop(res_tx); // receiver side stays; workers hold their own tx clone

        // Scheduler state
        struct State { next_nonce: u64, done: bool }
        let mut states: Vec<State> = (0..k).map(|_| State { next_nonce: 0, done: false }).collect();
        let mut proofs_by_idx: Vec<Option<KProof>> = (0..k).map(|_| None).collect();

        // Prime the queue: one task per puzzle
        for i in 0..k {
            task_tx.send(Task { idx: i, nonce: 0 }).map_err(|e| e.to_string())?;
        }

        let start = if with_stats { Some(Instant::now()) } else { None };
        let mut total_tries: u64 = 0;
        let mut successes = 0usize;

        while successes < k {
            let Res { idx, nonce, ok, hash } = res_rx.recv().map_err(|e| e.to_string())?;
            if with_stats { total_tries += 1; }

            let st = &mut states[idx];
            if st.done {
                // Already completed, ignore any straggler result
                continue;
            }
            if ok {
                st.done = true;
                successes += 1;
                proofs_by_idx[idx] = Some(KProof { index: idx, nonce, hash });
                if successes == k {
                    stop.store(true, Ordering::Relaxed);
                    break;
                }
            } else {
                st.next_nonce = st.next_nonce.checked_add(1).ok_or_else(|| "nonce overflow".to_owned())?;
                task_tx.send(Task { idx, nonce: st.next_nonce }).map_err(|e| e.to_string())?;
            }
        }

        // Close task channel to let workers exit once they finish current task
        drop(task_tx);
        for j in joins { let _ = j.join(); }

        let proofs: Vec<KProof> = proofs_by_idx
            .into_iter()
            .enumerate()
            .filter_map(|(_i, p)| p)
            .collect();
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
}
