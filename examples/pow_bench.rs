use hex::encode as hex_encode;
use ripemd::Ripemd320;
use rspow::{
    equix_challenge, meets_leading_zero_bits, EquixSolution, PoW, PoWAlgorithm, ScryptParams,
};
use sha2::{Digest, Sha256, Sha512};
use std::str::FromStr;
use std::time::Instant;

fn usage() -> String {
    "Usage: cargo run --release --example pow_bench -- \
      --algo <sha2_256|sha2_512|ripemd_320|scrypt|argon2id|equix> \
      --mode <ascii|bits> --difficulty <usize> [--repeats <u32>] [--data <str>] \
      [--scrypt-logn <u8> --scrypt-r <u32> --scrypt-p <u32>] \
      [--argon2-m-kib <u32> --argon2-t <u32> --argon2-p <u32>] \
      [--server-nonce <str>] [--start-work-nonce <u64>] [--seed-hex <64hex>]\n"
        .to_string()
}

#[derive(Clone, Copy, Debug)]
enum Mode {
    Ascii,
    Bits,
}

fn parse_next<T: FromStr>(it: &mut impl Iterator<Item = String>, flag: &str) -> Result<T, String> {
    let v = it.next().ok_or_else(|| usage())?;
    v.parse::<T>()
        .map_err(|_| format!("Invalid value for {flag}"))
}

fn main() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let mut algo = String::from("sha2_256");
    let mut mode = Mode::Bits;
    let mut difficulty: usize = 10;
    let mut repeats: u32 = 3;
    let mut data = String::from("hello");
    let mut s_log_n: u8 = 10;
    let mut s_r: u32 = 8;
    let mut s_p: u32 = 1;
    let mut a_m_kib: u32 = 64 * 1024;
    let mut a_t: u32 = 3;
    let mut a_p: u32 = 1;
    let mut server_nonce = String::from("nonce");
    let mut start_work_nonce: u64 = 0;
    let mut seed_hex: Option<String> = None;

    while let Some(a) = args.next() {
        match a.as_str() {
            "--algo" => algo = args.next().ok_or_else(|| usage())?,
            "--mode" => {
                let v = args.next().ok_or_else(|| usage())?;
                mode = match v.as_str() {
                    "ascii" => Mode::Ascii,
                    "bits" => Mode::Bits,
                    _ => return Err(usage()),
                };
            }
            "--difficulty" => difficulty = parse_next(&mut args, "--difficulty")?,
            "--repeats" => repeats = parse_next(&mut args, "--repeats")?,
            "--data" => data = args.next().ok_or_else(|| usage())?,
            "--scrypt-logn" => s_log_n = parse_next(&mut args, "--scrypt-logn")?,
            "--scrypt-r" => s_r = parse_next(&mut args, "--scrypt-r")?,
            "--scrypt-p" => s_p = parse_next(&mut args, "--scrypt-p")?,
            "--argon2-m-kib" => a_m_kib = parse_next(&mut args, "--argon2-m-kib")?,
            "--argon2-t" => a_t = parse_next(&mut args, "--argon2-t")?,
            "--argon2-p" => a_p = parse_next(&mut args, "--argon2-p")?,
            "--server-nonce" => server_nonce = args.next().ok_or_else(|| usage())?,
            "--start-work-nonce" => start_work_nonce = parse_next(&mut args, "--start-work-nonce")?,
            "--seed-hex" => seed_hex = Some(args.next().ok_or_else(|| usage())?),
            _ => return Err(usage()),
        }
    }

    println!("kind,algo,mode,difficulty,data_len,run_idx,time_ms,tries,nonce_or_work,hash_hex");

    for run_idx in 0..repeats {
        match algo.as_str() {
            "sha2_256" | "sha2_512" | "ripemd_320" | "scrypt" | "argon2id" => {
                let algorithm = match algo.as_str() {
                    "sha2_256" => PoWAlgorithm::Sha2_256,
                    "sha2_512" => PoWAlgorithm::Sha2_512,
                    "ripemd_320" => PoWAlgorithm::RIPEMD_320,
                    "scrypt" => {
                        let params =
                            ScryptParams::new(s_log_n, s_r, s_p, 32).map_err(|e| e.to_string())?;
                        PoWAlgorithm::Scrypt(params)
                    }
                    "argon2id" => {
                        let params = rspow::Argon2Params::new(a_m_kib, a_t, a_p, None)
                            .map_err(|e| e.to_string())?;
                        PoWAlgorithm::Argon2id(params)
                    }
                    _ => unreachable!(),
                };

                let pow = match mode {
                    Mode::Ascii => PoW::new(&data, difficulty, algorithm)?,
                    Mode::Bits => PoW::with_mode(
                        &data,
                        difficulty,
                        algorithm,
                        rspow::DifficultyMode::LeadingZeroBits,
                    )?,
                };
                let target = match mode {
                    Mode::Ascii => pow.calculate_target(),
                    Mode::Bits => Vec::new(),
                };
                let t0 = Instant::now();
                let (hash, nonce) = pow.calculate_pow(&target);
                let dt_ms = t0.elapsed().as_millis();
                let tries = (nonce as u128) + 1;
                println!(
                    "run,{},{},{},{},{},{},{},{},{}",
                    algo,
                    match mode {
                        Mode::Ascii => "ascii",
                        Mode::Bits => "leading_zero_bits",
                    },
                    difficulty,
                    data.len(),
                    run_idx,
                    dt_ms,
                    tries,
                    nonce,
                    hex_encode(hash)
                );
            }
            "equix" => {
                // Seed: either supplied, or domain-separated hash of (server_nonce, data, run_idx)
                let seed: [u8; 32] = if let Some(ref hex) = seed_hex {
                    let bytes = hex::decode(hex).map_err(|_| "invalid --seed-hex")?;
                    if bytes.len() != 32 {
                        return Err("--seed-hex must be 32 bytes".into());
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    arr
                } else {
                    let mut h = Sha256::new();
                    h.update(b"rspow:equix:bench|");
                    h.update(&(server_nonce.len() as u64).to_le_bytes());
                    h.update(server_nonce.as_bytes());
                    h.update(&(data.len() as u64).to_le_bytes());
                    h.update(data.as_bytes());
                    h.update(&(run_idx as u64).to_le_bytes());
                    h.finalize().into()
                };

                if !matches!(mode, Mode::Bits) {
                    return Err("equix bench currently supports --mode bits only".into());
                }
                let bits = difficulty as u32;
                let mut work = start_work_nonce;
                let t0 = Instant::now();
                let (mut found_hash_hex, mut found_work) = (String::new(), 0u64);
                let mut tries = 0u128;
                'outer: loop {
                    let challenge = equix_challenge(&seed, work);
                    let eq = match equix::EquiX::new(&challenge) {
                        Ok(e) => e,
                        Err(_) => {
                            work += 1;
                            tries += 1;
                            continue;
                        }
                    };
                    let sols = eq.solve();
                    for sol in sols.iter() {
                        let bytes = sol.to_bytes();
                        let mut hasher = Sha256::new();
                        hasher.update(bytes);
                        let hash: [u8; 32] = hasher.finalize().into();
                        if meets_leading_zero_bits(&hash, bits) {
                            found_hash_hex = hex_encode(hash);
                            found_work = work;
                            break 'outer;
                        }
                    }
                    work += 1;
                    tries += 1;
                }
                let dt_ms = t0.elapsed().as_millis();
                println!(
                    "run,{},{},{},{},{},{},{},{},{}",
                    "equix",
                    "leading_zero_bits",
                    bits,
                    data.len(),
                    run_idx,
                    dt_ms,
                    tries,
                    found_work,
                    found_hash_hex
                );
            }
            _ => return Err(usage()),
        }
    }

    Ok(())
}
