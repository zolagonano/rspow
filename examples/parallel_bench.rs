use hex::encode as hex_encode;
use rspow::{
    equix_solve_parallel_hits, pow_solve_parallel_hits, DifficultyMode, ParPowCfg, PoW,
    PoWAlgorithm, ScryptParams,
};
use sha2::{Digest, Sha256};
use std::str::FromStr;
use std::time::Instant;

fn usage() -> String {
    "Usage: cargo run --release --example parallel_bench -- \
      --algo <sha2_256|sha2_512|ripemd_320|scrypt|argon2id|equix> \
      --mode <ascii|bits> --difficulty <usize> --hits <usize> [--threads <usize>] \
      [--data <str>] [--scrypt-logn <u8> --scrypt-r <u32> --scrypt-p <u32>] \
      [--server-nonce <str>] [--start <u64>] [--seed-hex <64hex>]\n"
        .to_string()
}

#[derive(Clone, Copy, Debug)]
enum Mode {
    Ascii,
    Bits,
}

fn parse_next<T: FromStr>(it: &mut impl Iterator<Item = String>, flag: &str) -> Result<T, String> {
    let v = it.next().ok_or_else(|| usage())?;
    v.parse::<T>().map_err(|_| format!("Invalid {flag}"))
}

fn main() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let mut algo = String::from("equix");
    let mut mode = Mode::Bits;
    let mut difficulty: usize = 1;
    let mut hits: usize = 8;
    let mut threads: Option<usize> = None;
    let mut threads_list: Option<Vec<usize>> = None;
    let mut data = String::from("hello");
    let mut s_log_n: u8 = 10;
    let mut s_r: u32 = 8;
    let mut s_p: u32 = 1;
    let mut a_m_kib: u32 = 64 * 1024;
    let mut a_t: u32 = 3;
    let mut a_p: u32 = 1;
    let mut server_nonce = String::from("nonce");
    let mut start: u64 = 0;
    let mut seed_hex: Option<String> = None;
    let mut repeats: u32 = 1;

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
            "--hits" => hits = parse_next(&mut args, "--hits")?,
            "--threads" => threads = Some(parse_next(&mut args, "--threads")?),
            "--threads-list" => {
                let raw = args.next().ok_or_else(|| usage())?;
                let list = raw
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.parse::<usize>().map_err(|_| usage()))
                    .collect::<Result<Vec<_>, _>>()?;
                if list.is_empty() {
                    return Err(usage());
                }
                threads_list = Some(list);
            }
            "--data" => data = args.next().ok_or_else(|| usage())?,
            "--scrypt-logn" => s_log_n = parse_next(&mut args, "--scrypt-logn")?,
            "--scrypt-r" => s_r = parse_next(&mut args, "--scrypt-r")?,
            "--scrypt-p" => s_p = parse_next(&mut args, "--scrypt-p")?,
            "--argon2-m-kib" => a_m_kib = parse_next(&mut args, "--argon2-m-kib")?,
            "--argon2-t" => a_t = parse_next(&mut args, "--argon2-t")?,
            "--argon2-p" => a_p = parse_next(&mut args, "--argon2-p")?,
            "--server-nonce" => server_nonce = args.next().ok_or_else(|| usage())?,
            "--start" => start = parse_next(&mut args, "--start")?,
            "--seed-hex" => seed_hex = Some(args.next().ok_or_else(|| usage())?),
            "--repeats" => repeats = parse_next(&mut args, "--repeats")?,
            _ => return Err(usage()),
        }
    }

    let default_threads = std::thread::available_parallelism()
        .map(|nz| nz.get())
        .unwrap_or(1)
        .saturating_sub(1)
        .max(1);
    let run_threads: Vec<usize> = if let Some(list) = threads_list {
        list
    } else {
        vec![threads.unwrap_or(default_threads)]
    };
    println!(
        "algo={}, mode={:?}, bits_or_len={}, hits={}, threads_list={:?}, repeats={}",
        algo, mode, difficulty, hits, run_threads, repeats
    );
    println!("kind,algo,mode,bits_or_len,hits,threads,repeat_idx,first_time_ms,total_time_ms,throughput_hits_per_s");

    for th in run_threads {
        // accumulators for per-threads summary across repeats
        let mut first_ms: Vec<u128> = Vec::with_capacity(repeats as usize);
        let mut total_ms: Vec<u128> = Vec::with_capacity(repeats as usize);
        let mut thrpt: Vec<f64> = Vec::with_capacity(repeats as usize);

        for rep in 0..repeats {
            let mode_str = match mode {
                Mode::Ascii => "ascii",
                Mode::Bits => "bits",
            };
            match algo.as_str() {
                "equix" => {
                    if !matches!(mode, Mode::Bits) {
                        return Err("equix only supports bits mode".into());
                    }
                    let seed: [u8; 32] = if let Some(ref hex) = seed_hex {
                        let b = hex::decode(hex).map_err(|_| "bad seed")?;
                        if b.len() != 32 {
                            return Err("seed must be 32 bytes".into());
                        }
                        let mut a = [0u8; 32];
                        a.copy_from_slice(&b);
                        a
                    } else {
                        let mut h = Sha256::new();
                        h.update(b"rspow:equix:parbench|");
                        h.update(&(server_nonce.len() as u64).to_le_bytes());
                        h.update(server_nonce.as_bytes());
                        h.update(&(data.len() as u64).to_le_bytes());
                        h.update(data.as_bytes());
                        h.finalize().into()
                    };
                    let bits = difficulty as u32;
                    let t_first = Instant::now();
                    let _first = equix_solve_parallel_hits(&seed, bits, 1, th, start)?;
                    let dt_first = t_first.elapsed().as_millis();
                    let t_all = Instant::now();
                    let all = equix_solve_parallel_hits(&seed, bits, hits, th, start)?;
                    let dt_all = t_all.elapsed().as_millis();
                    let tp = (hits as f64) / ((dt_all as f64) / 1000.0);
                    let tp_s = format!("{:.6}", tp);
                    println!(
                        "run,{},{},{},{},{},{},{},{},{}",
                        algo, mode_str, difficulty, hits, th, rep, dt_first, dt_all, tp_s
                    );
                    first_ms.push(dt_first);
                    total_ms.push(dt_all);
                    thrpt.push(tp);
                    for (i, (p, h)) in all.iter().enumerate() {
                        println!("hit{},work={},hash_hex={}", i, p.work_nonce, hex_encode(h));
                    }
                }
                other => {
                    let algorithm = match other {
                        "sha2_256" => PoWAlgorithm::Sha2_256,
                        "sha2_512" => PoWAlgorithm::Sha2_512,
                        "ripemd_320" => PoWAlgorithm::RIPEMD_320,
                        "scrypt" => {
                            let params = ScryptParams::new(s_log_n, s_r, s_p, 32)
                                .map_err(|e| e.to_string())?;
                            PoWAlgorithm::Scrypt(params)
                        }
                        "argon2id" => {
                            let params = rspow::Argon2Params::new(a_m_kib, a_t, a_p, None)
                                .map_err(|e| e.to_string())?;
                            PoWAlgorithm::Argon2id(params)
                        }
                        _ => return Err(usage()),
                    };
                    let pow = match mode {
                        Mode::Ascii => PoW::new(&data, difficulty, algorithm)?,
                        Mode::Bits => PoW::with_mode(
                            &data,
                            difficulty,
                            algorithm,
                            DifficultyMode::LeadingZeroBits,
                        )?,
                    };
                    let t_first = Instant::now();
                    let _first = pow_solve_parallel_hits(
                        &pow,
                        &ParPowCfg {
                            threads: th,
                            hits: 1,
                            start_nonce: start,
                        },
                    )?;
                    let dt_first = t_first.elapsed().as_millis();
                    let t_all = Instant::now();
                    let all = pow_solve_parallel_hits(
                        &pow,
                        &ParPowCfg {
                            threads: th,
                            hits,
                            start_nonce: start,
                        },
                    )?;
                    let dt_all = t_all.elapsed().as_millis();
                    let tp = (hits as f64) / ((dt_all as f64) / 1000.0);
                    let tp_s = format!("{:.6}", tp);
                    println!(
                        "run,{},{},{},{},{},{},{},{},{}",
                        algo, mode_str, difficulty, hits, th, rep, dt_first, dt_all, tp_s
                    );
                    first_ms.push(dt_first);
                    total_ms.push(dt_all);
                    thrpt.push(tp);
                    for (i, h) in all.iter().enumerate() {
                        println!("hit{},nonce={},hash_hex={}", i, h.nonce, hex_encode(h.hash));
                    }
                }
            }
        } // end repeats

        // summary per threads value
        fn summarize_f64(xs: &[f64]) -> (f64, f64, f64, f64, f64) {
            let n = xs.len() as f64;
            let sum: f64 = xs.iter().sum();
            let mean = sum / n;
            let sumsq: f64 = xs.iter().map(|v| v * v).sum();
            let var = if xs.len() > 1 {
                (sumsq - sum * sum / n) / (n - 1.0)
            } else {
                0.0
            };
            let std = var.max(0.0).sqrt();
            let stderr = if n > 0.0 { std / n.sqrt() } else { 0.0 };
            let z = 1.959963984540054;
            (mean, std, stderr, mean - z * stderr, mean + z * stderr)
        }
        fn summarize_u128(xs: &[u128]) -> (f64, f64, f64, f64, f64) {
            summarize_f64(&xs.iter().map(|&v| v as f64).collect::<Vec<_>>())
        }
        let (mf, sf, sef, cf_l, cf_h) = summarize_u128(&first_ms);
        let (mt, st, set, ct_l, ct_h) = summarize_u128(&total_ms);
        let (mp, sp, sep, cp_l, cp_h) = summarize_f64(&thrpt);
        let mode_str = match mode {
            Mode::Ascii => "ascii",
            Mode::Bits => "bits",
        };
        println!("kind,algo,mode,bits_or_len,hits,threads,mean_first_ms,std_first_ms,stderr_first_ms,ci95_low_first_ms,ci95_high_first_ms,mean_total_ms,std_total_ms,stderr_total_ms,ci95_low_total_ms,ci95_high_total_ms,mean_throughput,std_throughput,stderr_throughput,ci95_low_throughput,ci95_high_throughput");
        println!(
            "summary,{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            algo,
            mode_str,
            difficulty,
            hits,
            th,
            format!("{:.6}", mf),
            format!("{:.6}", sf),
            format!("{:.6}", sef),
            format!("{:.6}", cf_l),
            format!("{:.6}", cf_h),
            format!("{:.6}", mt),
            format!("{:.6}", st),
            format!("{:.6}", set),
            format!("{:.6}", ct_l),
            format!("{:.6}", ct_h),
            format!("{:.6}", mp),
            format!("{:.6}", sp),
            format!("{:.6}", sep),
            format!("{:.6}", cp_l),
            format!("{:.6}", cp_h)
        );
    }
    Ok(())
}
