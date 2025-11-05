use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use rspow::bench::{
    argon2_params_kib, bench_argon2_leading_bits_once, csv_header, csv_row_run, csv_row_summary,
    summarize,
};
use std::env;
use std::io::{self, BufWriter, Write};
use std::str::FromStr;

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

struct Config {
    start_bits: u32,
    max_bits: u32,
    repeats: u32,
    random_start: bool,
    seed: Option<u64>,
    data: Vec<u8>,
    m_kib: u32,
    t_cost: u32,
    p_cost: u32,
}

fn run() -> Result<(), String> {
    let config = parse_args()?;
    let params = argon2_params_kib(config.m_kib, config.t_cost, config.p_cost)?;

    let mut stdout = BufWriter::new(io::stdout().lock());
    writeln!(stdout, "{}", csv_header()).map_err(io_err)?;

    let algo = "argon2id";
    let mode = "leading_zero_bits";

    let mut rng = if config.random_start {
        Some(match config.seed {
            Some(seed) => StdRng::seed_from_u64(seed),
            None => StdRng::from_entropy(),
        })
    } else {
        None
    };

    for bits in config.start_bits..=config.max_bits {
        let mut outcomes = Vec::new();
        for run_idx in 0..config.repeats {
            let start_nonce = if let Some(rng) = rng.as_mut() {
                rng.gen::<u64>()
            } else {
                u64::from(run_idx)
            };

            let outcome = bench_argon2_leading_bits_once(&config.data, bits, &params, start_nonce)?;
            writeln!(stdout, "{}", csv_row_run(&outcome, algo, mode, run_idx)).map_err(io_err)?;
            stdout.flush().map_err(io_err)?;
            outcomes.push(outcome);
        }

        let summary = summarize(&outcomes)?;
        writeln!(
            stdout,
            "{}",
            csv_row_summary(
                bits,
                config.data.len(),
                config.m_kib,
                config.t_cost,
                config.p_cost,
                &summary,
                algo,
                mode,
            )
        )
        .map_err(io_err)?;
        stdout.flush().map_err(io_err)?;
    }

    Ok(())
}

fn parse_args() -> Result<Config, String> {
    let mut args = env::args().skip(1);

    let mut start_bits: u32 = 1;
    let mut max_bits: Option<u32> = None;
    let mut repeats: u32 = 5;
    let mut random_start = true;
    let mut seed: Option<u64> = None;
    let mut data = b"hello world".to_vec();
    let mut m_kib: Option<u32> = Some(65_535);
    let mut m_mib: Option<u32> = None;
    let mut t_cost: u32 = 3;
    let mut p_cost: u32 = 1;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--start-bits" => {
                start_bits = parse_next::<u32>(&mut args, "--start-bits")?;
            }
            "--max-bits" => {
                max_bits = Some(parse_next::<u32>(&mut args, "--max-bits")?);
            }
            "--repeats" => {
                repeats = parse_next::<u32>(&mut args, "--repeats")?;
            }
            "--random-start" => {
                random_start = parse_next::<bool>(&mut args, "--random-start")?;
            }
            "--seed" => {
                seed = Some(parse_next::<u64>(&mut args, "--seed")?);
            }
            "--data" => {
                let value = parse_next::<String>(&mut args, "--data")?;
                data = value.into_bytes();
            }
            "--m-kib" => {
                m_kib = Some(parse_next::<u32>(&mut args, "--m-kib")?);
                m_mib = None;
            }
            "--m-mib" => {
                m_mib = Some(parse_next::<u32>(&mut args, "--m-mib")?);
                m_kib = None;
            }
            "--t-cost" => {
                t_cost = parse_next::<u32>(&mut args, "--t-cost")?;
            }
            "--p-cost" => {
                p_cost = parse_next::<u32>(&mut args, "--p-cost")?;
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            other => {
                return Err(format!("unknown argument: {other}"));
            }
        }
    }

    let max_bits = max_bits.ok_or_else(|| "--max-bits is required".to_owned())?;
    if max_bits == 0 {
        return Err("--max-bits must be > 0".to_owned());
    }
    if start_bits == 0 {
        return Err("--start-bits must be > 0".to_owned());
    }
    if max_bits < start_bits {
        return Err("--max-bits must be >= --start-bits".to_owned());
    }
    if repeats == 0 {
        return Err("--repeats must be > 0".to_owned());
    }

    let derived_m_kib = match (m_kib, m_mib) {
        (Some(kib), None) => kib,
        (None, Some(mib)) => mib
            .checked_mul(1024)
            .ok_or_else(|| "--m-mib value is too large".to_owned())?,
        (Some(_), Some(_)) => {
            return Err("use either --m-kib or --m-mib, not both".to_owned());
        }
        (None, None) => 65_535,
    };

    Ok(Config {
        start_bits,
        max_bits,
        repeats,
        random_start,
        seed,
        data,
        m_kib: derived_m_kib,
        t_cost,
        p_cost,
    })
}

fn parse_next<T: FromStr>(
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<T, String> {
    let value = args
        .next()
        .ok_or_else(|| format!("{flag} requires a value"))?;
    value
        .parse::<T>()
        .map_err(|_| format!("invalid value for {flag}"))
}

fn print_help() {
    println!(
        "Usage: cargo run --release --example bench_argon2_leading_bits -- [options]\n\
Options:\n  --start-bits <u32>    Starting difficulty in bits (default 1)\n  --max-bits <u32>      Maximum difficulty in bits (required)\n  --repeats <u32>       Repetitions per difficulty (default 5)\n  --random-start <bool> Randomize start nonce per run (default true)\n  --seed <u64>          Optional RNG seed\n  --data <string>       Input payload (default \"hello world\")\n  --m-kib <u32>         Argon2 memory cost in KiB (default 65535)\n  --m-mib <u32>         Argon2 memory cost in MiB (mutually exclusive with --m-kib)\n  --t-cost <u32>        Argon2 time cost (default 3)\n  --p-cost <u32>        Argon2 lanes/parallelism (default 1)\n  --help                Show this message"
    );
}

fn io_err(err: io::Error) -> String {
    err.to_string()
}
