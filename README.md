# RSPOW

[![b](https://img.shields.io/crates/l/rspow)](https://crates.io/crates/rspow)
[![b](https://img.shields.io/crates/d/rspow)](https://crates.io/crates/rspow)
[![b](https://img.shields.io/crates/v/rspow)](https://crates.io/crates/rspow)
[![b](https://img.shields.io/badge/keep_the_project_alive-%E2%9D%A4%EF%B8%8F-white)](https://zolagonano.github.io/support)

A simple multi-algorithm proof-of-work library for Rust.

## Algorithms

- [x] SHA-256
- [x] SHA-512
- [x] RIPEMD-320
- [x] Scrypt
- [x] Argon2id
- [x] EquiX (Tor's Equi‑X puzzle; hash = sha256(solution-bytes))

API references are available at [docs.rs/rspow](https://docs.rs/rspow).

## Difficulty Modes

RSPOW supports two difficulty modes:

- AsciiZeroPrefix (default): the hash must start with `difficulty` bytes of ASCII `'0'` (`0x30`).
  - Expected attempts grow by ~256 per additional byte.
  - Simple to explain, but coarse-grained and often too steep for memory-hard hashes.
- LeadingZeroBits: the hash must have at least `difficulty` leading zero bits.
  - Expected attempts ≈ `2^difficulty`.
  - Fine-grained control suitable for tuning across a wide range.

Notes:
- `PoW::calculate_target()` returns the ASCII `'0'` prefix and is meaningful only for `AsciiZeroPrefix`.
- In `LeadingZeroBits` mode, the `target` slice is ignored; pass an empty slice for clarity.

## Examples

### ASCII `'0'` prefix (default)

```rust
use rspow::{PoW, PoWAlgorithm};

let data = "hello world";
let difficulty = 2; // requires prefix "00"
let algorithm = PoWAlgorithm::Sha2_512;
let pow = PoW::new(data, difficulty, algorithm).unwrap();

let target = pow.calculate_target(); // [0x30; difficulty]
let (hash, nonce) = pow.calculate_pow(&target);
assert!(hash.starts_with(&target[..difficulty]));
assert!(pow.verify_pow(&target, (hash, nonce)));
```

### Leading zero bits (fine-grained)

```rust
use rspow::{PoW, PoWAlgorithm, DifficultyMode};

let data = "hello world";
let bits = 12; // expected attempts ~ 2^12 = 4096
let algorithm = PoWAlgorithm::Sha2_256;
let pow = PoW::with_mode(data, bits, algorithm, DifficultyMode::LeadingZeroBits).unwrap();

let (hash, nonce) = pow.calculate_pow(&[]); // target is ignored in bits mode
assert!(rspow::meets_leading_zero_bits(&hash, bits as u32));
assert!(pow.verify_pow(&[], (hash, nonce)));
```

### EquiX (Tor Equi‑X puzzle)

```rust
use rspow::{PoW, PoWAlgorithm, DifficultyMode};

let data = b"hello world";
let bits = 1; // expected attempts ≈ 2^bits; EquiX solver may yield 0+ solutions per challenge
let pow = PoW::with_mode(data, bits, PoWAlgorithm::EquiX, DifficultyMode::LeadingZeroBits).unwrap();

// For demonstrations/tests you can also use bits=0 to avoid long loops
let (hash, nonce) = pow.calculate_pow(&[]);
assert!(hash.len() == 32);
```

### EquiX proof-carrying API (O(1) verification)

For production use, prefer a proof that carries the EquiX solution bytes so the server verifies in constant time without solving:

```rust
use rspow::{EquixProof, EquixSolution, equix_solve_with_bits, equix_verify_solution, equix_check_bits};
use sha2::{Digest, Sha256};

// Derive a domain-separated seed once per request
let server_nonce = b"signed-token"; // signed & time-limited by the server
let data = b"payload";
let mut h = Sha256::new();
h.update(b"rspow:equix:v1|");
h.update(&(server_nonce.len() as u64).to_le_bytes());
h.update(server_nonce);
h.update(&(data.len() as u64).to_le_bytes());
h.update(data);
let seed: [u8; 32] = h.finalize().into();

// Client: search by varying work_nonce
let bits: u32 = 8;
let (proof, hash) = equix_solve_with_bits(&seed, bits, 0)?;

// Server: verify O(1)
let vhash = equix_verify_solution(&seed, &proof)?;
assert_eq!(hash, vhash);
assert!(equix_check_bits(&seed, &proof, bits)?);
```

Notes:
- Recommended seed: `SHA256("rspow:equix:v1|" || encode(server_nonce) || encode(data))`. Then build `challenge = seed || LE(work_nonce)` per attempt.
- Submit `{ server_nonce, work_nonce, solution_bytes }`. The server rebuilds `seed` and verifies via `equix_verify_solution` and `equix_check_bits`.
- To increase pressure under attack, require `m` independent proofs with distinct `work_nonce` values; each proof still verifies in O(1).

## Examples and Benchmarks

- Proof-carrying EquiX demo:
  ```
  cargo run --release --example equix_proof_demo -- --data hello --server-nonce sn --bits 1 --start 0
  ```

- General PoW benchmark (select algorithm and mode):
  ```
  # Default repeats is 300 to reduce measurement noise.
  cargo run --release --example pow_bench -- --algo sha2_256 --mode bits --difficulty 12 --data hello
  cargo run --release --example pow_bench -- --algo scrypt --mode ascii --difficulty 2 --scrypt-logn 10 --scrypt-r 8 --scrypt-p 1
  cargo run --release --example pow_bench -- --algo argon2id --mode bits --difficulty 8 --argon2-m-kib 65536 --argon2-t 3 --argon2-p 1
  cargo run --release --example pow_bench -- --algo equix --mode bits --difficulty 1 --server-nonce sn --start-work-nonce 0
  ```

- CSV columns:
  - Per-run rows: `kind,algo,mode,difficulty,data_len,run_idx,time_ms,tries,nonce_or_work,hash_hex`.
    - For EquiX, `tries` equals the number of challenges (work_nonce values) attempted per found solution — this directly measures “attempts per solution”.
  - Summary row (appended at the end with its own header):
    `kind,algo,mode,difficulty,data_len,mean_time_ms,std_time_ms,stderr_time_ms,ci95_low_time_ms,ci95_high_time_ms,mean_tries,std_tries,stderr_tries,ci95_low_tries,ci95_high_tries`.


### Argon2id with custom parameters

```rust
use rspow::{PoW, PoWAlgorithm, Argon2Params, DifficultyMode};

let data = b"hello world";
// Example parameters only; tune for your threat model.
let params = Argon2Params::new(/* m_cost KiB */ 64 * 1024, /* t_cost */ 3, /* p */ 1, None).unwrap();
let algorithm = PoWAlgorithm::Argon2id(params);

// Prefer LeadingZeroBits for smoother tuning with memory-hard functions
let bits = 8; // expected attempts ~ 256
let pow = PoW::with_mode(data, bits, algorithm, DifficultyMode::LeadingZeroBits).unwrap();
let (hash, nonce) = pow.calculate_pow(&[]);
assert!(rspow::meets_leading_zero_bits(&hash, bits as u32));
```

## Benchmarking

### CLI benchmark (Argon2id, leading zero bits)

The crate ships an example that measures Argon2id proof-of-work time across bit difficulties with configurable parameters.

```
cargo run --release --example bench_argon2_leading_bits -- \
  --start-bits 1 --max-bits 12 --repeats 5 \
  --m-mib 128 --t-cost 3 --p-cost 1 \
  --data "hello world"
```

- Results stream as CSV: each run emits a `run` row immediately, followed by a `summary` row per difficulty.
- `--random-start=true` (default) draws a random starting nonce for every repetition so that tries follow the expected geometric distribution. Disable with `--random-start false` if you only want runtime variation.
- `--seed <u64>` fixes the random sequence for reproducibility.
- Additional options: `--m-kib`, `--repeats`, `--start-bits`, `--max-bits`, `--data`. Run with `--help` for the full list.

### WASM build & browser demo

Use the helper script to drive formatting/tests, build the wasm bundle, and (optionally) launch a local server:

```
./scripts/wasm_pipeline.sh --offline --serve --port 8080
```

Flags:

- `--offline` keeps Cargo/wasm-pack from hitting the network (`CARGO_NET_OFFLINE=1`).
- `--dev` switches to debug profile (default is release).
- `--skip-test` skips `cargo test`.
- `--serve` launches `python3 -m http.server` inside `wasm-demo/www`.

After the script completes, open `http://127.0.0.1:8080` (or your chosen port). The browser UI lets you configure start/max bits, repeats, Argon2 parameters, and whether to randomize the nonce. Results append to the textarea as CSV and include mean, standard deviation, standard error, plus 95% and 99% confidence intervals for both time (ms) and tries.

### KPoW (k-of-puzzles) — concurrent PoW with predictable wall time

KPoW lets you solve `k` independent puzzles concurrently with a worker pool of size `workers` (alpha), collecting the first `k` successes. This keeps verification cheap (≈ one Argon2 per proof) while improving wall‑time predictability (variance ~ 1/√k) and utilizing multiple cores.

- Library API

```rust
use rspow::kpow::{KPow, KProof};
use rspow::Argon2Params;

let bits = 5; // compute/verify ≈ 2^bits = 32x
let params = Argon2Params::new(64*1024, 3, 1, None)?; // 64MiB, t=3, p=1
let workers = 4;
let seed = [0u8; 32];
let payload = b"ctx".to_vec();
let kpow = KPow::new(bits, params, workers, seed, payload);

// Production: compute k proofs (no timing/tries overhead)
let proofs: Vec<KProof> = kpow.solve_proofs(8)?;
assert!(proofs.iter().all(|p| kpow.verify_proof(p)));

// Benchmarking: compute proofs and get total stats
let (proofs, stats) = kpow.solve_proofs_with_stats(8)?;
println!("time_ms={} tries={} successes={}", stats.total_time_ms, stats.total_tries, stats.successes);
```

- Demo example

```
cargo run --release --example kpow_demo

# Environment overrides (optional):
#   KPOW_WORKERS=<usize>  number of worker threads (default 4)
#   KPOW_K=<usize>        number of proofs to collect (default 8)
```

- KPoW benchmark example (CSV streaming + summary)

```
cargo run --release --example kpow_bench_argon2_leading_bits -- \
  --bits 5 --k 8 --workers 4 --repeats 10 \
  --m-mib 64 --t-cost 3 --p-cost 1 --payload demo | tee kpow_64mib.csv
```

Notes:
- Compute/verify ratio is governed by `bits`: ≈ `2^bits` (independent of Argon2 params). With `bits=5`, ratio ≈ 32x.
- Wall‑time predictability improves with `k` (roughly ~ 1/√k). Verification cost grows linearly with `k` (≈ `k` Argon2 runs).
- `m_kib/t_cost/p_cost` decide the per‑hash cost `c`. Larger memory or t_cost increases `c` roughly linearly.

### WASM (browser) threading quick note

To use KPoW with true threads in the browser (std::thread over Web Workers):
- Build with target features `+atomics,+bulk-memory,+mutable-globals` for `wasm32-unknown-unknown`.
- Serve pages under cross‑origin isolation (COOP: same-origin, COEP: require-corp) so SharedArrayBuffer is enabled.
- This crate enforces threaded‑WASM by default; single‑thread fallback on wasm32 is only allowed if you explicitly build with `--cfg kpow_allow_single_thread`.

## Tuning Guidance

- LeadingZeroBits: each additional bit doubles expected attempts; choose `bits` to match your time budget.
- AsciiZeroPrefix: each additional byte multiplies attempts by ~256; easy but coarse.
- Memory-hard algorithms (e.g., Argon2id, Scrypt) may make multi-byte ASCII prefix targets impractical; prefer `LeadingZeroBits`.

## Compatibility

- Existing code using `PoW::new` and `calculate_target()` keeps the legacy behavior by default.
- New code is encouraged to adopt `DifficultyMode::LeadingZeroBits` for precise difficulty control.
