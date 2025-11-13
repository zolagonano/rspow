use hex::encode as hex_encode;
use rspow::{equix_check_bits, equix_solve_with_bits, equix_verify_solution};
use sha2::{Digest, Sha256};
use std::time::Instant;

fn usage() -> String {
    "Usage: cargo run --release --example equix_proof_demo -- [--data <str>] [--server-nonce <str>] [--bits <u32>] [--start <u64>]\n\
     Defaults: --data \"hello\" --server-nonce \"nonce\" --bits 1 --start 0\n"
        .to_string()
}

fn seed_from(server_nonce: &str, data: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"rspow:equix:v1|");
    h.update(&(server_nonce.len() as u64).to_le_bytes());
    h.update(server_nonce.as_bytes());
    h.update(&(data.len() as u64).to_le_bytes());
    h.update(data.as_bytes());
    h.finalize().into()
}

fn main() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let mut data = String::from("hello");
    let mut server_nonce = String::from("nonce");
    let mut bits: u32 = 1;
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

    let seed = seed_from(&server_nonce, &data);
    let t0 = Instant::now();
    let (proof, hash) = equix_solve_with_bits(&seed, bits, start)?;
    let dt_ms = t0.elapsed().as_millis();

    println!("algo,equix,mode,leading_zero_bits");
    println!(
        "proof.work_nonce={}, time_ms={}, hash_hex={}",
        proof.work_nonce,
        dt_ms,
        hex_encode(hash)
    );

    // Verify (O(1))
    let vhash = equix_verify_solution(&seed, &proof)?;
    assert_eq!(vhash, hash);
    assert!(equix_check_bits(&seed, &proof, bits)?);
    println!("verify=ok");
    Ok(())
}
