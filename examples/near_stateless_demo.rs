//! Minimal end-to-end demo of the near-stateless PoW flow.
//!
//! - Server issues deterministic nonce + config via `issue_params()`.
//! - Client derives master challenge, solves with EquiX, submits, server verifies.
//! - Uses Tokio for async message passing; heavy solve runs on a blocking thread.

use std::error::Error;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rspow::equix::engine::EquixEngineBuilder;
use rspow::near_stateless::client::solve_submission_from_params;
use rspow::near_stateless::prf::Blake3NonceProvider;
use rspow::near_stateless::server::NearStatelessVerifier;
use rspow::near_stateless::types::{SolveParams, Submission, VerifierConfig};
use rspow::near_stateless::{MokaReplayCache, SystemTimeProvider};
use tokio::sync::mpsc;
use tokio::task::{spawn_local, LocalSet};
use tokio::time::interval;

const SERVER_SECRET: [u8; 32] = [0x42; 32];

#[derive(Debug)]
enum Request {
    Params,
    Submit(Submission),
}

#[derive(Debug)]
enum Response {
    Params(SolveParams),
    Accepted,
    Rejected(String),
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let local = LocalSet::new();

    local
        .run_until(async move {
            // Shared config: make proofs >1 so the progress bar is visible.
            let verifier_cfg = VerifierConfig {
                time_window: Duration::from_secs(3600),
                min_difficulty: 7,
                min_required_proofs: 300,
            };

            let (req_tx, req_rx) = mpsc::channel::<Request>(1);
            let (resp_tx, mut resp_rx) = mpsc::channel::<Response>(1);

            // Spawn server task on the local set (non-Send future).
            spawn_local(server_task(req_rx, resp_tx, verifier_cfg.clone()));

            // Client: request params, solve, submit.
            req_tx.send(Request::Params).await?;
            let params = match resp_rx.recv().await.expect("params response") {
                Response::Params(p) => p,
                other => panic!("unexpected response: {other:?}"),
            };

            let client_nonce = blake3::hash(b"client-nonce-demo").into();
            let progress = Arc::new(AtomicU64::new(0));

            // Build engine matching server policy.
            let mut engine = EquixEngineBuilder::default()
                .bits(params.config.min_difficulty)
                .required_proofs(params.config.min_required_proofs)
                .threads(3)
                .progress(progress.clone())
                .build_validated()?;

            // Show a simple textual progress indicator with percentage and bar.
            let progress_watcher = tokio::task::spawn(progress_printer(
                progress.clone(),
                params.config.min_required_proofs,
            ));

            // Solve on a blocking thread to avoid starving Tokio.
            let solve_handle = tokio::task::spawn_blocking(move || {
                solve_submission_from_params(&mut engine, &params, client_nonce)
            });

            let submission = solve_handle.await??;
            progress_watcher.abort();

            println!(
                "Submitting bundle with {} proofs",
                submission.proof_bundle.len()
            );
            req_tx.send(Request::Submit(submission)).await?;

            match resp_rx.recv().await {
                Some(Response::Accepted) => println!("Server accepted submission ✅"),
                Some(Response::Rejected(err)) => println!("Server rejected submission: {err}"),
                None => println!("Server channel closed"),
                _ => {}
            }

            Ok::<(), Box<dyn Error>>(())
        })
        .await?;

    Ok(())
}

async fn server_task(
    mut req_rx: mpsc::Receiver<Request>,
    resp_tx: mpsc::Sender<Response>,
    cfg: VerifierConfig,
) {
    let verifier = match NearStatelessVerifier::new(
        cfg,
        SERVER_SECRET,
        Arc::new(Blake3NonceProvider),
        Arc::new(MokaReplayCache::new(1000)),
        Arc::new(SystemTimeProvider),
    ) {
        Ok(v) => Arc::new(v),
        Err(e) => {
            eprintln!("failed to create verifier: {e}");
            return;
        }
    };

    while let Some(req) = req_rx.recv().await {
        match req {
            Request::Params => {
                let params = verifier.issue_params();
                if resp_tx.send(Response::Params(params)).await.is_err() {
                    break;
                }
            }
            Request::Submit(sub) => {
                let resp = match verifier.verify_submission(&sub) {
                    Ok(()) => Response::Accepted,
                    Err(e) => Response::Rejected(e.to_string()),
                };
                if resp_tx.send(resp).await.is_err() {
                    break;
                }
            }
        }
    }
}

async fn progress_printer(progress: Arc<AtomicU64>, required_proofs: usize) {
    let mut ticker = interval(Duration::from_millis(100));
    let mut last = 0u64;
    let per_proof: u128 = 1u128;
    let bar_len = 30usize;
    loop {
        ticker.tick().await;
        let current = progress.load(Ordering::Relaxed);
        if current != last {
            let proofs_done = ((current as u128) / per_proof) as usize;
            let proofs_done = proofs_done.min(required_proofs);
            let pct = (proofs_done as f64 / required_proofs as f64 * 100.0).min(100.0);
            let filled = ((pct / 100.0) * bar_len as f64).round() as usize;
            let bar = "▩".repeat(filled);
            let empty = "·".repeat(bar_len.saturating_sub(filled));
            print!(
                "\r{:5.1}% [{}{}] {:>3}/{:<3})",
                pct, bar, empty, current, required_proofs
            );
            let _ = std::io::stdout().flush();
            last = current;
        }
    }
}
