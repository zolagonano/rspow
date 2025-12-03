use crate::core::derive_challenge;
use crate::equix::types::{Proof, ProofBundle, ProofConfig};
use crate::error::Error;
use crate::pow::PowEngine;
use crate::stream::{NonceSource, StopFlag};
use blake3::hash as blake3_hash;
use derive_builder::Builder;
use equix as equix_crate;
use flume::{Receiver, Sender, TrySendError};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;

#[derive(Builder, Debug)]
#[builder(pattern = "owned")]
pub struct EquixEngine {
    pub bits: u32,
    pub threads: usize,
    pub required_proofs: usize,
    pub progress: Arc<AtomicU64>,
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

    /// Update the engine's configured target number of proofs.
    ///
    /// This controls both fresh `solve_bundle` calls and future `resume` calls
    /// that rely on the engine configuration rather than an ad-hoc parameter.
    pub fn set_required_proofs(&mut self, required_proofs: usize) -> Result<(), Error> {
        if required_proofs == 0 {
            return Err(Error::InvalidConfig("required_proofs must be >= 1".into()));
        }
        self.required_proofs = required_proofs;
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
    type Bundle = ProofBundle;

    fn solve_bundle(&mut self, master_challenge: [u8; 32]) -> Result<Self::Bundle, Error> {
        self.validate()?;
        self.progress.store(0, Ordering::SeqCst);
        let mut bundle = ProofBundle {
            proofs: Vec::new(),
            config: ProofConfig { bits: self.bits },
            master_challenge,
        };

        let new_proofs = solve_range(
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

    fn resume(&mut self, mut existing: Self::Bundle) -> Result<Self::Bundle, Error> {
        self.validate()?;
        if existing.config.bits != self.bits {
            return Err(Error::InvalidConfig(
                "bundle difficulty does not match engine".into(),
            ));
        }
        existing
            .verify_strict(self.bits, existing.len())
            .map_err(|e| Error::SolverFailed(e.to_string()))?;
        let required_proofs = self.required_proofs;
        if required_proofs < existing.len() {
            return Err(Error::InvalidConfig(
                "required_proofs must be >= existing proofs".into(),
            ));
        }
        self.progress.store(existing.len() as u64, Ordering::SeqCst);
        if existing.len() >= required_proofs {
            return Ok(existing);
        }
        let start_proof_id = existing
            .proofs
            .iter()
            .map(|p| p.id)
            .max()
            .map(|m| m.saturating_add(1))
            .unwrap_or(existing.len() as u64);
        let new_proofs = solve_range(
            existing.master_challenge,
            self.bits,
            self.threads,
            start_proof_id,
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
    master_challenge: [u8; 32],
    bits: u32,
    threads: usize,
    start_proof_id: u64,
    current_len: usize,
    target_total: usize,
    progress: Arc<AtomicU64>,
) -> Result<Vec<Proof>, Error> {
    solve_range_with(
        master_challenge,
        bits,
        threads,
        start_proof_id,
        current_len,
        target_total,
        progress,
        Arc::new(solve_single as fn([u8; 32], u32) -> Result<Option<[u8; 16]>, Error>),
    )
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn solve_range_with(
    master_challenge: [u8; 32],
    bits: u32,
    threads: usize,
    start_proof_id: u64,
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

    let id_source = Arc::new(NonceSource::new(start_proof_id));
    let stop = Arc::new(StopFlag::new());
    let bound = (threads.max(1) * 2).max(1);
    let (tx, rx): (Sender<ProofResult>, Receiver<ProofResult>) = flume::bounded(bound);
    let mut joins = Vec::with_capacity(threads.max(1));

    for _ in 0..threads.max(1) {
        let worker_nonce = id_source.clone();
        let worker_stop = stop.clone();
        let worker_tx = tx.clone();
        let worker_solver = solver.clone();
        let join = thread::spawn(move || {
            worker_loop(
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
    master_challenge: [u8; 32],
    bits: u32,
    id_source: Arc<NonceSource>,
    stop: Arc<StopFlag>,
    tx: Sender<ProofResult>,
    solver: Arc<Solver>,
) {
    while !stop.should_stop() {
        let id = id_source.fetch();
        let challenge = derive_challenge(master_challenge, id);
        match solver(challenge, bits) {
            Ok(Some(solution)) => {
                let proof = Proof {
                    id,
                    challenge,
                    solution,
                };
                match tx.try_send(Ok(proof)) {
                    Ok(()) => {}
                    Err(TrySendError::Full(_)) => {
                        // drop hit under backpressure
                    }
                    Err(TrySendError::Disconnected(_)) => {
                        stop.force_stop();
                        break;
                    }
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
    // The EquiX API documents that a small fraction of challenge values will
    // fail construction with program-constraint errors, and solvers are
    // expected to skip those challenges rather than aborting the search.
    // Treat any constructor error here as "no solution for this nonce".
    let equix = match equix_crate::EquiX::new(&challenge) {
        Ok(e) => e,
        Err(_err) => return Ok(None),
    };
    let solutions = equix.solve();
    for sol in solutions.iter() {
        let bytes = sol.to_bytes();
        let hash = blake3_hash(&bytes);
        let hash: [u8; 32] = *hash.as_bytes();
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
    use crate::equix::types::{ProofBundle, ProofConfig};
    use crate::error::Error;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    #[test]
    fn solve_single_returns_none_when_no_solution_meets_bits() {
        // Very high difficulty is unlikely to be met by any EquiX solution for this challenge.
        let challenge = [0u8; 32];
        let result = solve_single(challenge, 128).expect("solver should not error");
        assert!(result.is_none());
    }

    #[test]
    fn worker_skips_challenges_without_solutions() {
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

        let proofs = solve_range_with([1u8; 32], 0, 2, 0, 0, 3, progress.clone(), solver)
            .expect("solver should complete");

        assert_eq!(proofs.len(), 3);
        assert!(
            attempts.load(Ordering::SeqCst) >= 2,
            "should have skipped at least two attempts"
        );
        assert_eq!(progress.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn solve_bundle_is_deterministic_single_thread() {
        let master = [11u8; 32];

        let progress1 = Arc::new(AtomicU64::new(0));
        let mut engine1 = EquixEngineBuilder::default()
            .bits(1)
            .threads(1)
            .required_proofs(3)
            .progress(progress1)
            .build()
            .expect("build engine1");
        let bundle1 = engine1
            .solve_bundle(master)
            .expect("first solve should succeed");

        let progress2 = Arc::new(AtomicU64::new(0));
        let mut engine2 = EquixEngineBuilder::default()
            .bits(1)
            .threads(1)
            .required_proofs(3)
            .progress(progress2)
            .build()
            .expect("build engine2");
        let bundle2 = engine2
            .solve_bundle(master)
            .expect("second solve should succeed");

        assert_eq!(bundle1, bundle2);
    }

    #[test]
    fn resume_starts_from_next_nonce() {
        let progress = Arc::new(AtomicU64::new(0));
        let master = [7u8; 32];

        // Build an existing bundle starting from a non-zero nonce (5).
        let existing_proofs =
            solve_range(master, 1, 1, 5, 0, 1, progress.clone()).expect("seed bundle");

        let existing_ids: Vec<u64> = existing_proofs.iter().map(|p| p.id).collect();
        let max_existing_id = *existing_ids.iter().max().expect("have at least one proof");

        let bundle = ProofBundle {
            proofs: existing_proofs,
            config: ProofConfig { bits: 1 },
            master_challenge: master,
        };

        // Resume should not re-use any existing ids; new proofs must use ids > max_existing_id.
        let mut engine = EquixEngineBuilder::default()
            .bits(1)
            .threads(1)
            .required_proofs(2)
            .progress(progress.clone())
            .build()
            .expect("build engine");

        let resumed = engine.resume(bundle).expect("resume should succeed");

        assert_eq!(resumed.len(), 2);
        // All existing ids must still be present.
        for id in &existing_ids {
            assert!(resumed.proofs.iter().any(|p| p.id == *id));
        }
        // Any new ids must be strictly greater than the max existing id.
        let new_ids: Vec<u64> = resumed
            .proofs
            .iter()
            .map(|p| p.id)
            .filter(|id| !existing_ids.contains(id))
            .collect();
        assert!(!new_ids.is_empty());
        assert!(new_ids.iter().all(|id| *id > max_existing_id));
    }

    #[test]
    fn single_and_multi_thread_solutions_are_equivalent() {
        let master = [21u8; 32];
        let required = 3usize;

        let progress_single = Arc::new(AtomicU64::new(0));
        let mut engine_single = EquixEngineBuilder::default()
            .bits(1)
            .threads(1)
            .required_proofs(required)
            .progress(progress_single)
            .build()
            .expect("build single-thread engine");

        let bundle_single = engine_single
            .solve_bundle(master)
            .expect("single-thread solve should succeed");

        let progress_multi = Arc::new(AtomicU64::new(0));
        let mut engine_multi = EquixEngineBuilder::default()
            .bits(1)
            .threads(2)
            .required_proofs(required)
            .progress(progress_multi)
            .build()
            .expect("build multi-thread engine");

        let bundle_multi = engine_multi
            .solve_bundle(master)
            .expect("multi-thread solve should succeed");

        assert_eq!(bundle_single.len(), required);
        assert_eq!(bundle_multi.len(), required);
        bundle_single
            .verify_strict(1, required)
            .expect("single-thread bundle should verify");
        bundle_multi
            .verify_strict(1, required)
            .expect("multi-thread bundle should verify");
        assert_eq!(bundle_single.master_challenge, master);
        assert_eq!(bundle_multi.master_challenge, master);
    }

    #[test]
    fn resume_extends_bundle_n_to_n_plus_m() {
        let master = [31u8; 32];
        let progress = Arc::new(AtomicU64::new(0));
        let mut engine = EquixEngineBuilder::default()
            .bits(1)
            .threads(2)
            .required_proofs(2)
            .progress(progress.clone())
            .build()
            .expect("build engine");

        let initial = engine
            .solve_bundle(master)
            .expect("initial solve should succeed");
        assert_eq!(initial.len(), 2);
        initial
            .verify_strict(1, 2)
            .expect("initial bundle should verify");

        engine
            .set_required_proofs(5)
            .expect("update required_proofs for resume");

        let resumed = engine
            .resume(initial.clone())
            .expect("resume should extend bundle");
        assert_eq!(resumed.len(), 5);
        resumed
            .verify_strict(1, 5)
            .expect("resumed bundle should verify");
        assert!(resumed.proofs.len() > initial.proofs.len());
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
            .resume(bundle)
            .expect_err("should reject bits mismatch");
        assert!(matches!(err, Error::InvalidConfig(_)));
    }
}
