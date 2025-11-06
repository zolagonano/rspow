use rspow::kpow::KPow;
use rspow::Argon2Params;
use sha2::{Digest, Sha256};
use std::env;
use std::io::{self, BufWriter, Write};
use std::str::FromStr;

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let cfg = parse_args()?;

    let mut out = BufWriter::new(io::stdout().lock());
    writeln!(
        out,
        "kind,algo,mode,m_kib,t_cost,p_cost,bits,workers,k,repeats,run_idx,seed_hex,time_ms,tries,successes,mean_time_ms,std_time_ms,stderr_time_ms,ci95_low_time_ms,ci95_high_time_ms,ci99_low_time_ms,ci99_high_time_ms,mean_tries,std_tries,stderr_tries,ci95_low_tries,ci95_high_tries,ci99_low_tries,ci99_high_tries"
    )
    .map_err(io_err)?;

    let algo = "argon2id";
    let mode = "leading_zero_bits";
    let params = argon2_params_kib(cfg.m_kib, cfg.t_cost, cfg.p_cost)?;

    let mut times = Vec::with_capacity(cfg.repeats as usize);
    let mut tries = Vec::with_capacity(cfg.repeats as usize);

    for run_idx in 0..cfg.repeats {
        let seed = derive_seed(cfg.seed_hex.as_deref(), run_idx)?;
        let kpow = KPow::new(
            cfg.bits,
            params.clone(),
            cfg.workers,
            seed,
            cfg.payload.clone(),
        );
        let (_proofs, stats) = kpow.solve_proofs_with_stats(cfg.k as usize)?;
        times.push(stats.total_time_ms as f64);
        tries.push(stats.total_tries as f64);
        writeln!(
            out,
            "run,{algo},{mode},{},{},{},{},{},{},{},{},{},{},{},{}",
            cfg.m_kib,
            cfg.t_cost,
            cfg.p_cost,
            cfg.bits,
            cfg.workers,
            cfg.k,
            cfg.repeats,
            run_idx,
            hex_seed(&seed),
            stats.total_time_ms,
            stats.total_tries,
            stats.successes
        )
        .map_err(io_err)?;
        out.flush().map_err(io_err)?;
    }

    let s_time = summarize(&times);
    let s_tries = summarize(&tries);
    writeln!(
        out,
        "summary,{algo},{mode},{},{},{},{},{},{},{} ,,,,,{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6}",
        cfg.m_kib,
        cfg.t_cost,
        cfg.p_cost,
        cfg.bits,
        cfg.workers,
        cfg.k,
        cfg.repeats,
        s_time.mean,
        s_time.std,
        s_time.stderr,
        s_time.ci95_low,
        s_time.ci95_high,
        s_time.ci99_low,
        s_time.ci99_high,
        s_tries.mean,
        s_tries.std,
        s_tries.stderr,
        s_tries.ci95_low,
        s_tries.ci95_high,
        s_tries.ci99_low,
        s_tries.ci99_high
    )
    .map_err(io_err)?;
    out.flush().map_err(io_err)?;
    Ok(())
}

#[derive(Clone)]
struct Cfg {
    bits: u32,
    m_kib: u32,
    t_cost: u32,
    p_cost: u32,
    workers: usize,
    k: u32,
    repeats: u32,
    payload: Vec<u8>,
    seed_hex: Option<String>,
}

fn parse_args() -> Result<Cfg, String> {
    let mut args = env::args().skip(1);
    let mut bits: u32 = 5;
    let mut m_kib: Option<u32> = Some(64 * 1024);
    let mut m_mib: Option<u32> = None;
    let mut t_cost: u32 = 3;
    let mut p_cost: u32 = 1;
    let mut workers: usize = 4;
    let mut k: u32 = 8;
    let mut repeats: u32 = 5;
    let mut payload = b"kpow-bench".to_vec();
    let mut seed_hex: Option<String> = None;

    while let Some(a) = args.next() {
        match a.as_str() {
            "--bits" => bits = parse_next(&mut args, "--bits")?,
            "--m-kib" => {
                m_kib = Some(parse_next(&mut args, "--m-kib")?);
                m_mib = None;
            }
            "--m-mib" => {
                m_mib = Some(parse_next(&mut args, "--m-mib")?);
                m_kib = None;
            }
            "--t-cost" => t_cost = parse_next(&mut args, "--t-cost")?,
            "--p-cost" => p_cost = parse_next(&mut args, "--p-cost")?,
            "--workers" => workers = parse_next(&mut args, "--workers")?,
            "--k" => k = parse_next(&mut args, "--k")?,
            "--repeats" => repeats = parse_next(&mut args, "--repeats")?,
            "--payload" => payload = parse_next::<String>(&mut args, "--payload")?.into_bytes(),
            "--seed-hex" => seed_hex = Some(parse_next(&mut args, "--seed-hex")?),
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    let m_kib = match (m_kib, m_mib) {
        (Some(kib), None) => kib,
        (None, Some(mib)) => mib
            .checked_mul(1024)
            .ok_or_else(|| "--m-mib value too large".to_owned())?,
        (Some(_), Some(_)) => return Err("use either --m-kib or --m-mib".to_owned()),
        (None, None) => 64 * 1024,
    };

    Ok(Cfg {
        bits,
        m_kib,
        t_cost,
        p_cost,
        workers,
        k,
        repeats,
        payload,
        seed_hex,
    })
}

fn parse_next<T: FromStr>(it: &mut impl Iterator<Item = String>, flag: &str) -> Result<T, String> {
    let v = it
        .next()
        .ok_or_else(|| format!("{flag} requires a value"))?;
    v.parse::<T>()
        .map_err(|_| format!("invalid value for {flag}"))
}

fn print_help() {
    println!(
        "Usage: cargo run --release --example kpow_bench_argon2_leading_bits -- [options]\n\
Options:\n  --bits <u32>        Leading-zero bits (default 5)\n  --k <u32>           Number of proofs to collect (default 8)\n  --workers <usize>   Worker threads (default 4)\n  --repeats <u32>     Repetitions (default 5)\n  --m-kib <u32>       Argon2 memory (KiB) (default 65536)\n  --m-mib <u32>       Argon2 memory (MiB)\n  --t-cost <u32>      Argon2 t_cost (default 3)\n  --p-cost <u32>      Argon2 p_cost (default 1)\n  --payload <string>  Arbitrary payload mixed into puzzles (default \"kpow-bench\")\n  --seed-hex <64hex>  Base seed; if omitted, per-run seed is SHA256(\"KPOW_BENCH|run_idx\")\n"
    );
}

fn io_err(e: io::Error) -> String {
    e.to_string()
}

fn argon2_params_kib(m_kib: u32, t: u32, p: u32) -> Result<Argon2Params, String> {
    Argon2Params::new(m_kib, t, p, None).map_err(|e| e.to_string())
}

fn derive_seed(seed_hex_opt: Option<&str>, run_idx: u32) -> Result<[u8; 32], String> {
    if let Some(h) = seed_hex_opt {
        let bytes = hex::decode(h).map_err(|e| e.to_string())?;
        if bytes.len() != 32 {
            return Err("--seed-hex must be 32 bytes hex".to_owned());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        // make per-run deterministic tweak to avoid identical seeds across repeats
        let mut tweak = [0u8; 32];
        tweak[0..4].copy_from_slice(&run_idx.to_le_bytes());
        let mut hasher = Sha256::new();
        hasher.update(&arr);
        hasher.update(&tweak);
        let d = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&d);
        return Ok(out);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"KPOW_BENCH|");
    hasher.update(run_idx.to_le_bytes());
    let d = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    Ok(out)
}

fn hex_seed(seed: &[u8; 32]) -> String {
    hex::encode(seed)
}

struct Summary {
    mean: f64,
    std: f64,
    stderr: f64,
    ci95_low: f64,
    ci95_high: f64,
    ci99_low: f64,
    ci99_high: f64,
}

fn summarize(xs: &[f64]) -> Summary {
    let n = xs.len() as f64;
    let sum: f64 = xs.iter().copied().sum();
    let mean = sum / n.max(1.0);
    let std = if xs.len() > 1 {
        let sumsq: f64 = xs.iter().map(|&x| x * x).sum();
        let var = (sumsq - sum * sum / n) / (n - 1.0);
        var.max(0.0).sqrt()
    } else {
        0.0
    };
    let stderr = if n > 0.0 { std / n.sqrt() } else { 0.0 };
    const Z95: f64 = 1.959_963_984_540_054;
    const Z99: f64 = 2.575_829_303_548_900_4;
    let (ci95_low, ci95_high) = (mean - Z95 * stderr, mean + Z95 * stderr);
    let (ci99_low, ci99_high) = (mean - Z99 * stderr, mean + Z99 * stderr);
    Summary {
        mean,
        std,
        stderr,
        ci95_low,
        ci95_high,
        ci99_low,
        ci99_high,
    }
}
