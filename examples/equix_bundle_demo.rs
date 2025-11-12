use hex::encode as hex_encode;
use rspow::{equix_solve_parallel_hits, EquixProof, EquixProofBundle};
use sha2::{Digest, Sha256};
use std::time::Instant;

fn usage() -> String {
    "Usage: cargo run --release --example equix_bundle_demo -- \
      --data <str> --server-nonce <str> [--bits <u32>] [--hits <usize>] [--threads <usize>] [--start <u64>]\n\
     Defaults: --bits 1 --hits 4 --threads (nproc-1) --start 0\n".to_string()
}

fn main() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let mut data = String::from("hello");
    let mut server_nonce = String::from("nonce");
    let mut bits: u32 = 1;
    let mut hits: usize = 4;
    let mut threads: Option<usize> = None;
    let mut start: u64 = 0;

    while let Some(a) = args.next() {
        match a.as_str() {
            "--data" => data = args.next().ok_or_else(|| usage())?,
            "--server-nonce" => server_nonce = args.next().ok_or_else(|| usage())?,
            "--bits" => {
                bits = args
                    .next()
                    .ok_or_else(|| usage())?
                    .parse()
                    .map_err(|_| usage())?
            }
            "--hits" => {
                hits = args
                    .next()
                    .ok_or_else(|| usage())?
                    .parse()
                    .map_err(|_| usage())?
            }
            "--threads" => {
                threads = Some(
                    args.next()
                        .ok_or_else(|| usage())?
                        .parse()
                        .map_err(|_| usage())?,
                )
            }
            "--start" => {
                start = args
                    .next()
                    .ok_or_else(|| usage())?
                    .parse()
                    .map_err(|_| usage())?
            }
            _ => return Err(usage()),
        }
    }

    // Domain-separated seed once per request/session.
    let mut seed_h = Sha256::new();
    seed_h.update(b"rspow:equix:v1|");
    seed_h.update(&(server_nonce.len() as u64).to_le_bytes());
    seed_h.update(server_nonce.as_bytes());
    seed_h.update(&(data.len() as u64).to_le_bytes());
    seed_h.update(data.as_bytes());
    let seed: [u8; 32] = seed_h.finalize().into();

    let threads = threads.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|nz| nz.get())
            .unwrap_or(1)
            .saturating_sub(1)
            .max(1)
    });

    println!(
        "equix_bundle_demo: bits={}, hits={}, threads={}, data_len={}, nonce_len={}",
        bits,
        hits,
        threads,
        data.len(),
        server_nonce.len()
    );

    let t0 = Instant::now();
    let results = equix_solve_parallel_hits(&seed, bits, hits, threads, start)?;
    let dt_ms = t0.elapsed().as_millis();
    println!("solve_time_ms={}, found_hits={}", dt_ms, results.len());

    // Build bundle: base_tag derived from the first proof; others can be derived on server.
    let (first_proof, _h0) = &results[0];
    let mut tag_h = Sha256::new();
    tag_h.update(b"rspow:tag:v1|");
    tag_h.update(&(server_nonce.len() as u64).to_le_bytes());
    tag_h.update(server_nonce.as_bytes());
    tag_h.update(&(data.len() as u64).to_le_bytes());
    tag_h.update(data.as_bytes());
    tag_h.update(first_proof.work_nonce.to_le_bytes());
    tag_h.update(first_proof.solution.0);
    let base_tag: [u8; 32] = tag_h.finalize().into();

    let proofs_only: Vec<EquixProof> = results.into_iter().map(|(p, _)| p).collect();
    let bundle = EquixProofBundle {
        base_tag,
        proofs: proofs_only,
    };

    // Server-side O(1) verification (simulated here).
    let oks = bundle.verify_all(&seed, bits)?;
    assert!(oks.iter().all(|&b| b));
    println!(
        "bundle_ok=true, base_tag={}, derived_tags={}",
        hex_encode(bundle.base_tag),
        bundle
            .derived_tags()
            .iter()
            .map(hex_encode)
            .collect::<Vec<_>>()
            .join(";")
    );

    println!("proofs:");
    for (i, p) in bundle.proofs.iter().enumerate() {
        println!(
            "  #{} work_nonce={} solution_hex={}",
            i,
            p.work_nonce,
            hex_encode(p.solution.0)
        );
    }

    Ok(())
}
