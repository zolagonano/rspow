use super::types::{EquixHit, EquixProof, EquixSolution};
use crate::work::{HitStop, NonceSource};
use crate::{meets_leading_zero_bits, DifficultyMode};
use equix as equix_crate;
use flume::TrySendError;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Build EquiX challenge bytes from an application‑defined seed and a `work_nonce`.
///
/// Recommendation (SDK usage): let `seed = SHA256("rspow:equix:v1|" || server_nonce || payload_bytes)`.
/// Keep `seed` stable for the session and only vary `work_nonce` locally.
pub fn equix_challenge(seed: &[u8], work_nonce: u64) -> Vec<u8> {
    let mut ch = Vec::with_capacity(seed.len() + 8);
    ch.extend_from_slice(seed);
    ch.extend_from_slice(&work_nonce.to_le_bytes());
    ch
}

/// Verify a single EquiX proof and return `sha256(solution_bytes)` if valid.
///
/// This is an O(1) verification path: it does not try to solve EquiX.
pub fn equix_verify_solution(seed: &[u8], proof: &EquixProof) -> Result<[u8; 32], String> {
    let challenge = equix_challenge(seed, proof.work_nonce);
    equix_crate::verify_bytes(&challenge, &proof.solution.0).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    hasher.update(proof.solution.0);
    let h = hasher.finalize();
    Ok(h.into())
}

/// Verify that the proof meets a leading‑zero‑bits difficulty.
pub fn equix_check_bits(seed: &[u8], proof: &EquixProof, bits: u32) -> Result<bool, String> {
    let hash = equix_verify_solution(seed, proof)?;
    Ok(meets_leading_zero_bits(&hash, bits))
}

/// Solve EquiX by varying `work_nonce`, returning the first proof meeting `bits`.
///
/// This is the client‑side search routine. It skips challenges that construct/solve with
/// zero solutions and continues with the next `work_nonce`.
pub fn equix_solve_with_bits(
    seed: &[u8],
    bits: u32,
    start_work_nonce: u64,
) -> Result<(EquixProof, [u8; 32]), String> {
    let mut work_nonce = start_work_nonce;
    loop {
        let challenge = equix_challenge(seed, work_nonce);
        // Build EquiX; on rare constraint errors, skip to next work_nonce.
        let equix = match equix_crate::EquiX::new(&challenge) {
            Ok(e) => e,
            Err(_) => {
                work_nonce = work_nonce
                    .checked_add(1)
                    .ok_or_else(|| "work_nonce overflow".to_owned())?;
                continue;
            }
        };
        let solutions = equix.solve();
        for sol in solutions.iter() {
            let bytes = sol.to_bytes();
            let mut hasher = Sha256::new();
            hasher.update(bytes);
            let hash: [u8; 32] = hasher.finalize().into();
            if meets_leading_zero_bits(&hash, bits) {
                let proof = EquixProof {
                    work_nonce,
                    solution: EquixSolution(bytes),
                };
                return Ok((proof, hash));
            }
        }
        work_nonce = work_nonce
            .checked_add(1)
            .ok_or_else(|| "work_nonce overflow".to_owned())?;
    }
}

/// Configuration for parallel EquiX solving.
#[derive(Clone, Debug)]
pub struct EquixSolveConfig {
    pub threads: usize,
    pub hits: usize,
    pub start_work_nonce: u64,
}

impl EquixSolveConfig {
    /// Build a configuration with default threads = max(1, num_cpus-1).
    pub fn default_with_hits(hits: usize) -> Result<Self, String> {
        let p = std::thread::available_parallelism()
            .map(|nz| nz.get())
            .unwrap_or(1)
            .saturating_sub(1)
            .max(1);
        Ok(Self {
            threads: p,
            hits,
            start_work_nonce: 0,
        })
    }
}

/// High-level EquiX solver wrapper.
pub struct EquixSolver<'a> {
    seed: &'a [u8],
    bits: u32,
}

impl<'a> EquixSolver<'a> {
    pub fn new(seed: &'a [u8], bits: u32) -> Self {
        Self { seed, bits }
    }

    pub fn solve_hits(&self, cfg: &EquixSolveConfig) -> Result<Vec<EquixHit>, String> {
        equix_solve_parallel_hits_cfg(self.seed, self.bits, cfg)
    }

    pub fn solve_bundle(
        &self,
        cfg: &EquixSolveConfig,
        base_tag: [u8; 32],
    ) -> Result<super::bundle::EquixProofBundle, String> {
        let hits = self.solve_hits(cfg)?;
        equix_solve_bundle(self.seed, self.bits, cfg, base_tag, hits)
    }

    /// Stream hits as they are found; the stream closes once `hits` are satisfied.
    pub fn solve_stream(&self, cfg: EquixSolveConfig) -> Result<EquixHitStream, String> {
        equix_solve_stream(self.seed.to_vec(), self.bits, cfg)
    }
}

/// Parallel EquiX solve: collect up to `cfg.hits` proofs using `cfg.threads` workers, varying `work_nonce`.
#[allow(clippy::type_complexity)]
pub fn equix_solve_parallel_hits_cfg(
    seed: &[u8],
    bits: u32,
    cfg: &EquixSolveConfig,
) -> Result<Vec<EquixHit>, String> {
    if cfg.threads == 0 || cfg.hits == 0 {
        return Err("threads and hits must be >= 1".to_owned());
    }
    let seed_vec = seed.to_vec();
    let bound = (cfg.threads.max(1) * 4).max(cfg.hits);
    let (tx, rx) = flume::bounded::<(u64, [u8; 16], [u8; 32])>(bound);
    let ctx = WorkerCtx::new(seed_vec, cfg, tx.clone())?;

    let mut joins = Vec::with_capacity(cfg.threads);
    for _ in 0..cfg.threads {
        let ctx_t = ctx.clone();
        let j = thread::spawn(move || {
            while !ctx_t.stop.should_stop() {
                let wn = ctx_t.nonce.fetch();
                let challenge = equix_challenge(&ctx_t.seed, wn);
                let eq = match equix_crate::EquiX::new(&challenge) {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                let sols = eq.solve();
                for sol in sols.iter() {
                    let bytes = sol.to_bytes();
                    let mut hasher = Sha256::new();
                    hasher.update(bytes);
                    let hash: [u8; 32] = hasher.finalize().into();
                    if meets_leading_zero_bits(&hash, bits) {
                        match ctx_t.tx.try_send((wn, bytes, hash)) {
                            Ok(_) => {}
                            Err(TrySendError::Full(_)) => {
                                // backpressure: drop this hit and continue searching
                            }
                            Err(TrySendError::Disconnected(_)) => {
                                ctx_t.stop.force_stop();
                                return;
                            }
                        }
                        break;
                    }
                }
            }
        });
        joins.push(j);
    }
    drop(tx);

    let mut hits = Vec::with_capacity(cfg.hits);
    let mut seen = HashSet::with_capacity(cfg.hits * 2);
    while let Ok((wn, bytes, hash)) = rx.recv() {
        if !seen.insert((wn, bytes)) {
            continue;
        }
        hits.push(EquixHit {
            proof: EquixProof {
                work_nonce: wn,
                solution: EquixSolution(bytes),
            },
            hash,
        });
        if ctx.stop.record_hit() {
            break;
        }
    }
    ctx.stop.force_stop();
    for j in joins {
        let _ = j.join();
    }
    hits.sort_by_key(|h| (h.proof.work_nonce, h.proof.solution.0));
    Ok(hits)
}

/// Backwards-compatible signature: matches earlier API.
#[allow(clippy::type_complexity)]
pub fn equix_solve_parallel_hits(
    seed: &[u8],
    bits: u32,
    hits: usize,
    threads: usize,
    start_work_nonce: u64,
) -> Result<Vec<(EquixProof, [u8; 32])>, String> {
    let cfg = EquixSolveConfig {
        threads,
        hits,
        start_work_nonce,
    };
    let hits = equix_solve_parallel_hits_cfg(seed, bits, &cfg)?;
    Ok(hits.into_iter().map(|h| (h.proof, h.hash)).collect())
}

/// Stream hits as they are found. Receiver closes after `cfg.hits` discoveries.
pub fn equix_solve_stream(
    seed: Vec<u8>,
    bits: u32,
    cfg: EquixSolveConfig,
) -> Result<EquixHitStream, String> {
    if cfg.threads == 0 || cfg.hits == 0 {
        return Err("threads and hits must be >= 1".to_owned());
    }
    let seed_vec = seed.to_vec();
    let bound = (cfg.threads.max(1) * 4).max(cfg.hits);
    let (tx, rx) = flume::bounded::<EquixHit>(bound);
    let stop = Arc::new(HitStop::new(cfg.hits)?);
    let nonce_src = Arc::new(NonceSource::new(cfg.start_work_nonce));
    let dedup = Arc::new(std::sync::Mutex::new(HashSet::with_capacity(cfg.hits * 2)));
    let mut joins = Vec::with_capacity(cfg.threads);
    for _ in 0..cfg.threads {
        let seed_t = seed_vec.clone();
        let nonce_t = nonce_src.clone();
        let stop_t = stop.clone();
        let tx_t = tx.clone();
        let dedup_t = dedup.clone();
        let j = thread::spawn(move || {
            while !stop_t.should_stop() {
                let wn = nonce_t.fetch();
                let challenge = equix_challenge(&seed_t, wn);
                let eq = match equix_crate::EquiX::new(&challenge) {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                let sols = eq.solve();
                for sol in sols.iter() {
                    let bytes = sol.to_bytes();
                    let mut hasher = Sha256::new();
                    hasher.update(bytes);
                    let hash: [u8; 32] = hasher.finalize().into();
                    if meets_leading_zero_bits(&hash, bits) {
                        // global dedup for stream
                        let key = (wn, bytes);
                        if let Ok(mut seen) = dedup_t.lock() {
                            if !seen.insert(key) {
                                continue;
                            }
                        } else {
                            stop_t.force_stop();
                            break;
                        }
                        let hit = EquixHit {
                            proof: EquixProof {
                                work_nonce: wn,
                                solution: EquixSolution(bytes),
                            },
                            hash,
                        };
                        match tx_t.try_send(hit) {
                            Ok(_) => {}
                            Err(TrySendError::Full(_)) => {}
                            Err(TrySendError::Disconnected(_)) => {
                                stop_t.force_stop();
                                return;
                            }
                        }
                        let _ = stop_t.record_hit();
                        break; // next work_nonce
                    }
                }
            }
        });
        joins.push(j);
    }
    drop(tx);
    Ok(EquixHitStream {
        rx,
        stop,
        joins,
        remaining: std::sync::atomic::AtomicUsize::new(cfg.hits),
    })
}

/// Build a bundle directly from hits, keeping caller-facing API ergonomic.
pub fn equix_solve_bundle(
    seed: &[u8],
    bits: u32,
    _cfg: &EquixSolveConfig,
    base_tag: [u8; 32],
    hits: Vec<EquixHit>,
) -> Result<super::bundle::EquixProofBundle, String> {
    let mut proofs = Vec::with_capacity(hits.len());
    for h in hits {
        let ok = equix_check_bits(seed, &h.proof, bits)?;
        if !ok {
            return Err("internal error: hit does not satisfy bits".to_owned());
        }
        proofs.push(h.proof);
    }
    Ok(super::bundle::EquixProofBundle { base_tag, proofs })
}

/// Streaming receiver for EquiX hits; join handles are awaited on drop.
pub struct EquixHitStream {
    rx: flume::Receiver<EquixHit>,
    stop: Arc<HitStop>,
    joins: Vec<thread::JoinHandle<()>>,
    remaining: std::sync::atomic::AtomicUsize,
}

impl EquixHitStream {
    /// Blocking receive; returns `None` when stream is closed.
    pub fn recv(&self) -> Option<EquixHit> {
        if self.remaining.load(std::sync::atomic::Ordering::Relaxed) == 0 {
            return None;
        }
        match self.rx.recv() {
            Ok(hit) => {
                self.remaining
                    .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                Some(hit)
            }
            Err(_) => None,
        }
    }

    /// Non-blocking receive with timeout to avoid busy wait in hosts that prefer it.
    pub fn recv_timeout(&self, timeout: Duration) -> Option<EquixHit> {
        if self.remaining.load(std::sync::atomic::Ordering::Relaxed) == 0 {
            return None;
        }
        match self.rx.recv_timeout(timeout) {
            Ok(hit) => {
                self.remaining
                    .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                Some(hit)
            }
            Err(_) => None,
        }
    }

    /// Number of hits already recorded globally.
    pub fn found(&self) -> usize {
        self.stop.found()
    }
}

impl Drop for EquixHitStream {
    fn drop(&mut self) {
        self.stop.force_stop();
        for j in self.joins.drain(..) {
            let _ = j.join();
        }
    }
}

/// Validate that EquiX always operates in leading-zero-bits mode.
pub const fn equix_difficulty_mode() -> DifficultyMode {
    DifficultyMode::LeadingZeroBits
}
#[derive(Clone)]
struct WorkerCtx {
    seed: Arc<Vec<u8>>,
    nonce: Arc<NonceSource>,
    stop: Arc<HitStop>,
    tx: flume::Sender<(u64, [u8; 16], [u8; 32])>,
}

impl WorkerCtx {
    fn new(
        seed: Vec<u8>,
        cfg: &EquixSolveConfig,
        tx: flume::Sender<(u64, [u8; 16], [u8; 32])>,
    ) -> Result<Self, String> {
        Ok(Self {
            seed: Arc::new(seed),
            nonce: Arc::new(NonceSource::new(cfg.start_work_nonce)),
            stop: Arc::new(HitStop::new(cfg.hits)?),
            tx,
        })
    }
}
