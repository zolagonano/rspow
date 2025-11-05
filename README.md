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

## Tuning Guidance

- LeadingZeroBits: each additional bit doubles expected attempts; choose `bits` to match your time budget.
- AsciiZeroPrefix: each additional byte multiplies attempts by ~256; easy but coarse.
- Memory-hard algorithms (e.g., Argon2id, Scrypt) may make multi-byte ASCII prefix targets impractical; prefer `LeadingZeroBits`.

## Compatibility

- Existing code using `PoW::new` and `calculate_target()` keeps the legacy behavior by default.
- New code is encouraged to adopt `DifficultyMode::LeadingZeroBits` for precise difficulty control.
