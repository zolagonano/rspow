use crate::core::{derive_challenge, Blake3TagHasher, TagHasher};
use crate::error::Error;
use crate::stream::{NonceSource, StopFlag};
use crate::types::{Proof, ProofBundle, ProofConfig};
use crate::verify::verify_bundle_strict;
use derive_builder::Builder;
use equix as equix_crate;
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
        let new_proofs = solve_range(
            self.hasher.clone(),
            existing.master_challenge,
            self.bits,
            self.threads,
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

fn solve_range(
    hasher: Arc<dyn TagHasher>,
    master_challenge: [u8; 32],
    bits: u32,
    threads: usize,
    start_id: usize,
    target_total: usize,
    progress: Arc<AtomicU64>,
) -> Result<Vec<Proof>, Error> {
    if start_id > target_total {
        return Err(Error::InvalidConfig(
            "start id must not exceed required proofs".into(),
        ));
    }

    let needed = target_total.saturating_sub(start_id);
    if needed == 0 {
        return Ok(Vec::new());
    }

    let nonce_source = Arc::new(NonceSource::new(start_id as u64));
    let stop = Arc::new(StopFlag::new());
    let bound = (threads.max(1) * 2).max(1);
    let (tx, rx) = flume::bounded::<Result<Proof, Error>>(bound);
    let mut joins = Vec::with_capacity(threads.max(1));

    for _ in 0..threads.max(1) {
        let worker_hasher = hasher.clone();
        let worker_nonce = nonce_source.clone();
        let worker_stop = stop.clone();
        let worker_tx = tx.clone();
        let join = thread::spawn(move || {
            worker_loop(
                worker_hasher,
                master_challenge,
                bits,
                target_total,
                worker_nonce,
                worker_stop,
                worker_tx,
            );
        });
        joins.push(join);
    }
    drop(tx);

    let mut proofs = Vec::with_capacity(needed);
    let mut seen = HashSet::with_capacity(needed * 2);

    while proofs.len() < needed {
        match rx.recv() {
            Ok(Ok(proof)) => {
                if proof.id >= target_total {
                    continue;
                }
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
    target_total: usize,
    nonce_source: Arc<NonceSource>,
    stop: Arc<StopFlag>,
    tx: flume::Sender<Result<Proof, Error>>,
) {
    while !stop.should_stop() {
        let id = nonce_source.fetch() as usize;
        if id >= target_total {
            stop.force_stop();
            break;
        }
        let challenge = derive_challenge(hasher.as_ref(), master_challenge, id);
        match solve_single(challenge, bits) {
            Ok(solution) => {
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

fn solve_single(challenge: [u8; 32], bits: u32) -> Result<[u8; 16], Error> {
    let equix =
        equix_crate::EquiX::new(&challenge).map_err(|err| Error::SolverFailed(err.to_string()))?;
    let solutions = equix.solve();
    let mut hasher = Sha256::new();
    for sol in solutions.iter() {
        let bytes = sol.to_bytes();
        hasher.update(bytes);
        let hash: [u8; 32] = hasher.finalize_reset().into();
        if leading_zero_bits(&hash) >= bits {
            return Ok(bytes);
        }
    }
    Err(Error::SolverFailed("no solution meeting difficulty".into()))
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
