use rspow::kpow::KPow;
use rspow::Argon2Params;

fn main() -> Result<(), String> {
    // Demo parameters (tune as needed)
    let bits: u32 = 5; // 2^bits = 32x compute/verify ratio
    let params = Argon2Params::new(64 * 1024, 3, 1, None).map_err(|e| e.to_string())?; // 64MiB, t=3, p=1
    let workers: usize = std::env::var("KPOW_WORKERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4);
    let seed: [u8; 32] = [0x11; 32]; // example seed; in production use a per-session random seed
    let payload: Vec<u8> = b"demo-payload".to_vec();

    // Construct KPoW and solve for k proofs
    let k: usize = std::env::var("KPOW_K")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8);
    let kpow = KPow::new(bits, params, workers, seed, payload);

    // Benchmark path: get proofs and overall stats
    let (proofs, stats) = kpow.solve_proofs_with_stats(k)?;
    println!(
        "KPoW done: bits={}, workers={}, k={} => time_ms={}, tries={}, successes={}",
        bits, workers, k, stats.total_time_ms, stats.total_tries, stats.successes
    );

    // Optionally, verify all proofs locally
    let all_ok = proofs.iter().all(|p| kpow.verify_proof(p));
    println!("verify_all={} ({} proofs)", all_ok, proofs.len());
    if !all_ok {
        return Err("verification failed".to_owned());
    }

    Ok(())
}
