use crate::core::{derive_challenge, Blake3TagHasher, TagHasher};
use crate::error::Error;
use crate::stream::{NonceSource, StopFlag};
use crate::types::{Proof, ProofBundle, ProofConfig};
use crate::verify::verify_bundle_strict;
use derive_builder::Builder;
use equix as equix_crate;
use flume::{Receiver, Sender};
use sha2::Digest;
use sha2::Sha256;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;

pub trait PowEngine {
    fn solve_bundle(&mut self, master_challenge: [u8; 32]) -> Result<ProofBundle, Error>;
    fn resume(
        &mut self,
        existing: ProofBundle,
        required_proofs: usize,
    ) -> Result<ProofBundle, Error>;
}

#[derive(Builder, Debug)]
#[builder(pattern = "owned")]
pub struct EquixEngine {
    pub bits: u32,
    pub threads: usize,
    pub required_proofs: usize,
    pub progress: Arc<AtomicU64>,
    #[builder(default = "Arc::new(Blake3TagHasher)")]
    pub hasher: Arc<dyn TagHasher>,
}

type ProofResult = Result<Proof, Error>;
type Solver = dyn Fn([u8; 32], u32) -> Result<Option<[u8; 16]>, Error> + Send + Sync;

impl EquixEngine {
    fn validate(&self) -> Result<(), Error> {
        if self.bits == 0 {
            return Err(Error::InvalidConfig("bits must be > 0".into()));
        }
        if self.threads == 0 {
            return Err(Error::InvalidConfig("threads must be >= 1".into()));
        }
        if self.required_proofs == 0 {
            return Err(Error::InvalidConfig("required_proofs must be >= 1".into()));
        }
        Ok(())
    }
}

impl EquixEngineBuilder {
    fn validate(&self) -> Result<(), Error> {
        if self.bits.unwrap_or(0) == 0 {
            return Err(Error::InvalidConfig("bits must be > 0".into()));
        }
        if self.threads.unwrap_or(0) == 0 {
            return Err(Error::InvalidConfig("threads must be >= 1".into()));
        }
        if self.required_proofs.unwrap_or(0) == 0 {
            return Err(Error::InvalidConfig("required_proofs must be >= 1".into()));
        }
        if self.progress.is_none() {
            return Err(Error::InvalidConfig("progress must be provided".into()));
        }
        Ok(())
    }

    pub fn build_validated(self) -> Result<EquixEngine, Error> {
        self.validate()?;
        self.build()
            .map_err(|e| Error::InvalidConfig(e.to_string()))
    }
}

impl PowEngine for EquixEngine {
    fn solve_bundle(&mut self, master_challenge: [u8; 32]) -> Result<ProofBundle, Error> {
        self.validate()?;
        self.progress.store(0, Ordering::SeqCst);
        let mut bundle = ProofBundle {
            proofs: Vec::new(),
            config: ProofConfig { bits: self.bits },
            master_challenge,
        };

        let new_proofs = solve_range(
            self.hasher.clone(),
            master_challenge,
            self.bits,
            self.threads,
            0,
            0,
            self.required_proofs,
            self.progress.clone(),
        )?;

        for proof in new_proofs {
            bundle
                .insert_proof(proof)
                .map_err(|err| Error::SolverFailed(err.to_string()))?;
        }

        Ok(bundle)
    }

    fn resume(
        &mut self,
        mut existing: ProofBundle,
        required_proofs: usize,
    ) -> Result<ProofBundle, Error> {
        self.validate()?;
        if existing.config.bits != self.bits {
            return Err(Error::InvalidConfig(
                "bundle difficulty does not match engine".into(),
            ));
        }
        verify_bundle_strict(&existing, self.hasher.as_ref())
            .map_err(|e| Error::SolverFailed(e.to_string()))?;
        if required_proofs < existing.len() {
            return Err(Error::InvalidConfig(
                "required_proofs must be >= existing proofs".into(),
            ));
        }
        self.required_proofs = required_proofs;
        self.progress.store(existing.len() as u64, Ordering::SeqCst);
        if existing.len() >= required_proofs {
            return Ok(existing);
        }
        let start_nonce = existing
            .proofs
            .iter()
            .map(|p| p.id)
            .max()
            .map(|m| m.saturating_add(1))
            .unwrap_or(existing.len());
        let new_proofs = solve_range(
            self.hasher.clone(),
            existing.master_challenge,
            self.bits,
            self.threads,
            start_nonce,
            existing.len(),
            required_proofs,
            self.progress.clone(),
        )?;

        for proof in new_proofs {
            existing
                .insert_proof(proof)
                .map_err(|err| Error::SolverFailed(err.to_string()))?;
        }
        Ok(existing)
    }
}

#[allow(clippy::too_many_arguments)]
fn solve_range(
    hasher: Arc<dyn TagHasher>,
    master_challenge: [u8; 32],
    bits: u32,
    threads: usize,
    start_nonce: usize,
    current_len: usize,
    target_total: usize,
    progress: Arc<AtomicU64>,
) -> Result<Vec<Proof>, Error> {
    solve_range_with(
        hasher,
        master_challenge,
        bits,
        threads,
        start_nonce,
        current_len,
        target_total,
        progress,
        Arc::new(solve_single as fn([u8; 32], u32) -> Result<Option<[u8; 16]>, Error>),
    )
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn solve_range_with(
    hasher: Arc<dyn TagHasher>,
    master_challenge: [u8; 32],
    bits: u32,
    threads: usize,
    start_nonce: usize,
    current_len: usize,
    target_total: usize,
    progress: Arc<AtomicU64>,
    solver: Arc<Solver>,
) -> Result<Vec<Proof>, Error> {
    if current_len > target_total {
        return Err(Error::InvalidConfig(
            "current proof count exceeds required proofs".into(),
        ));
    }

    let needed = target_total.saturating_sub(current_len);
    if needed == 0 {
        return Ok(Vec::new());
    }

    let nonce_source = Arc::new(NonceSource::new(start_nonce as u64));
    let stop = Arc::new(StopFlag::new());
    let bound = (threads.max(1) * 2).max(1);
    let (tx, rx): (Sender<ProofResult>, Receiver<ProofResult>) = flume::bounded(bound);
    let mut joins = Vec::with_capacity(threads.max(1));

    for _ in 0..threads.max(1) {
        let worker_hasher = hasher.clone();
        let worker_nonce = nonce_source.clone();
        let worker_stop = stop.clone();
        let worker_tx = tx.clone();
        let worker_solver = solver.clone();
        let join = thread::spawn(move || {
            worker_loop(
                worker_hasher,
                master_challenge,
                bits,
                worker_nonce,
                worker_stop,
                worker_tx,
                worker_solver,
            );
        });
        joins.push(join);
    }
    drop(tx);

    let mut proofs = Vec::with_capacity(needed);
    let mut seen = HashSet::with_capacity(needed * 2 + 1);

    while proofs.len() < needed {
        match rx.recv() {
            Ok(Ok(proof)) => {
                if !seen.insert(proof.id) {
                    continue;
                }
                proofs.push(proof);
                let current = progress.fetch_add(1, Ordering::SeqCst) + 1;
                if current >= target_total as u64 {
                    stop.force_stop();
                }
            }
            Ok(Err(err)) => {
                stop.force_stop();
                join_handles(joins);
                return Err(err);
            }
            Err(_) => break,
        }
    }

    stop.force_stop();
    join_handles(joins);

    if proofs.len() < needed {
        return Err(Error::ChannelClosed);
    }

    proofs.sort_by_key(|p| p.id);
    Ok(proofs)
}

fn worker_loop(
    hasher: Arc<dyn TagHasher>,
    master_challenge: [u8; 32],
    bits: u32,
    nonce_source: Arc<NonceSource>,
    stop: Arc<StopFlag>,
    tx: Sender<ProofResult>,
    solver: Arc<Solver>,
) {
    while !stop.should_stop() {
        let id = nonce_source.fetch() as usize;
        let challenge = derive_challenge(hasher.as_ref(), master_challenge, id);
        match solver(challenge, bits) {
            Ok(Some(solution)) => {
                let proof = Proof {
                    id,
                    challenge,
                    solution,
                };
                if tx.send(Ok(proof)).is_err() {
                    stop.force_stop();
                    break;
                }
            }
            Ok(None) => {
                continue;
            }
            Err(err) => {
                let _ = tx.send(Err(err));
                stop.force_stop();
                break;
            }
        }
    }
}

fn join_handles(joins: Vec<thread::JoinHandle<()>>) {
    for handle in joins {
        let _ = handle.join();
    }
}

fn solve_single(challenge: [u8; 32], bits: u32) -> Result<Option<[u8; 16]>, Error> {
    let equix =
        equix_crate::EquiX::new(&challenge).map_err(|err| Error::SolverFailed(err.to_string()))?;
    let solutions = equix.solve();
    let mut hasher = Sha256::new();
    for sol in solutions.iter() {
        let bytes = sol.to_bytes();
        hasher.update(bytes);
        let hash: [u8; 32] = hasher.finalize_reset().into();
        if leading_zero_bits(&hash) >= bits {
            return Ok(Some(bytes));
        }
    }
    Ok(None)
}

fn leading_zero_bits(hash: &[u8; 32]) -> u32 {
    let mut count = 0u32;
    for byte in hash {
        if *byte == 0 {
            count += 8;
            continue;
        }
        count += (*byte).leading_zeros();
        break;
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    #[derive(Debug)]
    struct DummyHasher;

    impl TagHasher for DummyHasher {
        fn hash(&self, data: &[u8]) -> [u8; 32] {
            blake3::hash(data).into()
        }
    }

    #[test]
    fn solve_single_returns_none_when_no_solution_meets_bits() {
        // Very high difficulty is unlikely to be met by any EquiX solution for this challenge.
        let challenge = [0u8; 32];
        let result = solve_single(challenge, 128).expect("solver should not error");
        assert!(result.is_none());
    }

    #[test]
    fn worker_skips_challenges_without_solutions() {
        let hasher: Arc<dyn TagHasher> = Arc::new(DummyHasher);
        let progress = Arc::new(AtomicU64::new(0));
        let attempts = Arc::new(AtomicUsize::new(0));
        let solver: Arc<Solver> = {
            let attempts = attempts.clone();
            Arc::new(move |_challenge: [u8; 32], _bits: u32| {
                let n = attempts.fetch_add(1, Ordering::SeqCst);
                if n < 2 {
                    Ok(None)
                } else {
                    Ok(Some([n as u8; 16]))
                }
            })
        };

        let proofs = solve_range_with(hasher, [1u8; 32], 0, 2, 0, 0, 3, progress.clone(), solver)
            .expect("solver should complete");

        assert_eq!(proofs.len(), 3);
        assert!(
            attempts.load(Ordering::SeqCst) >= 2,
            "should have skipped at least two attempts"
        );
        assert_eq!(progress.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn resume_starts_from_next_nonce() {
        let progress = Arc::new(AtomicU64::new(0));
        let hasher = Arc::new(Blake3TagHasher);
        let master = [7u8; 32];

        // Build an existing bundle with a non-zero starting nonce (5).
        let existing_proofs = solve_range(hasher.clone(), master, 1, 1, 5, 0, 1, progress.clone())
            .expect("seed bundle");

        let bundle = ProofBundle {
            proofs: existing_proofs,
            config: ProofConfig { bits: 1 },
            master_challenge: master,
        };

        // Resume should not re-use nonce 5; expect ids 5 and >=6 after resume.
        let mut engine = EquixEngineBuilder::default()
            .bits(1)
            .threads(1)
            .required_proofs(2)
            .progress(progress.clone())
            .hasher(hasher)
            .build()
            .expect("build engine");

        let resumed = engine.resume(bundle, 2).expect("resume should succeed");

        assert_eq!(resumed.len(), 2);
        assert!(resumed.proofs.iter().any(|p| p.id == 5));
        assert!(resumed.proofs.iter().any(|p| p.id >= 6));
    }

    #[test]
    fn resume_rejects_mismatched_bits() {
        let progress = Arc::new(AtomicU64::new(0));
        let mut engine_high = EquixEngineBuilder::default()
            .bits(2)
            .threads(1)
            .required_proofs(1)
            .progress(progress.clone())
            .build()
            .expect("build high bits engine");

        let bundle = engine_high
            .solve_bundle([9u8; 32])
            .expect("solve initial bundle");

        // Lower bits engine should refuse to resume a higher-difficulty bundle.
        let mut engine_low = EquixEngineBuilder::default()
            .bits(1)
            .threads(1)
            .required_proofs(2)
            .progress(Arc::new(AtomicU64::new(0)))
            .build()
            .expect("build low bits engine");

        let err = engine_low
            .resume(bundle, 2)
            .expect_err("should reject bits mismatch");
        matches!(err, Error::InvalidConfig(_));
    }
}
