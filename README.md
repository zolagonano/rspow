# rspow

> A proof-of-work toolbox for Rust with optional backends and a near-stateless protocol helper. **Enable `features = ["equix"]` to use the EquiX solver.**

## 0.5.0 at a glance (breaking)

- **Default features are now empty.** Opt in to algorithms and toolkits explicitly to keep compile size and transitive deps small.
- **EquiX backend is feature-gated** (`features = ["equix"]`). Other algorithms will be added behind their own features once the public API stabilizes.
- **Near-stateless PoW toolkit** (`features = ["near-stateless"]`) offers helper traits and types for the time-bound, replay-protected workflow described below (time windows must be whole seconds to avoid silent truncation). The verifier now owns the `server_secret`, so helpers (`issue_params`) require no extra secret arguments.
- **Progress reporting**: `EquixEngine` exposes an `Arc<AtomicU64>` counter you can wire into a progress bar during long searches.

## Feature flags

| Feature          | Default | What it enables                                         |
|------------------|:-------:|---------------------------------------------------------|
| `equix`          |   ❌    | EquiX engine, proofs, bundles, tests                    |
| `near-stateless` |   ❌    | Near-stateless server/client helpers (depends on equix) |

Add the crate with the features you need:

```toml
rspow = { version = "0.4", features = ["equix"] }
# rspow = { version = "0.4", features = ["equix", "near-stateless"] }
```

## Why bundles instead of “more bits”?

Raising leading-zero difficulty increases expected attempts exponentially (`2^bits`) and also widens variance, so different clients see very different solve times. Bundling proofs scales linearly: requiring **N** independent proofs gives roughly **N×** work and shrinks relative variance, yielding steadier user experience. `ProofBundle` encodes the required proof count and the master challenge, letting servers verify each proof in O(1) time.

## Quick start (EquiX)

> Enable `features = ["equix"]`. Examples require explicit features.

Progress bars: read `progress.load(Ordering::Relaxed)` to track how many challenges have been attempted (when provided to `EquixEngine`).

## Near-stateless PoW toolkit (opt-in)

`features = ["near-stateless"]` exposes building blocks for a time-windowed, replay-protected flow where servers keep almost no issuance state:

- **Deterministic nonce provider** (`DeterministicNonceProvider`): default is keyed BLAKE3 with tag `"rspow:nonce:v1"`.
- **Replay cache** (`ReplayCache`): default in-memory `MokaReplayCache`; pluggable for Redis/Memcached. If the cache is capacity-bound, evictions can allow replays—size it for your load or provide your own implementation.
- **Time provider** (`TimeProvider`): injectable clock for tests.
- **Verifier configuration** (`VerifierConfig`): `time_window >= 1s` and an *integral* number of seconds, `min_difficulty`, `min_required_proofs`; hot-swappable at runtime via `set_config` (internally lock-free reads with left-right).
- **Submission**: `{ timestamp, client_nonce, ProofBundle }` from the client.

Protocol sketch (details in the design doc [docs/near_stateless_pow.md](docs/near_stateless_pow.md), which covers the threat model, nonce derivation, time-window rules, and replay protection):

1) Server computes `deterministic_nonce = F(secret, timestamp)` (keyed BLAKE3) for requested `timestamp` within `[now - time_window, now]`.
2) Client samples a random `client_nonce`, derives `master_challenge = BLAKE3("rspow:challenge:v1" || deterministic_nonce || client_nonce)`, solves for a `ProofBundle`.
3) Client submits `{timestamp, client_nonce, proof_bundle}`. Server recomputes the nonce/challenge, enforces time window, verifies proofs against policy, then records `client_nonce` in the replay cache until `timestamp + time_window`.

Server-side flow in brief: derive deterministic nonce with your secret, enforce the (integral-seconds) time window, check replay cache, recompute master challenge, and call `verify_submission`; see `docs/near_stateless_pow.md` for the full walk-through and helper APIs (including `issue_params`/`solve_submission_from_params`).

### Example: end-to-end demo

The `examples/near_stateless_demo.rs` program shows a minimal async client/server flow using the toolkit:

- Server issues deterministic nonce + config (`issue_params`), verifies submissions, and blocks replays.
- Client derives the master challenge, solves with EquiX, reports progress, and submits a proof bundle.
- Progress bar shows percentage, bar, proofs done, and attempts.
- Uses a single-thread Tokio runtime plus `spawn_blocking` for the CPU-heavy solve.

Run it (features must be enabled explicitly):

```bash
cargo r --release -F equix,near-stateless --example near_stateless_demo
```

You can reuse it as a reference when wiring rspow into your own service: copy the parameter issuance, solve, submit, and verify steps to fit your transport/protocol.

### Example

Run the async end-to-end demo (requires `--features "equix near-stateless"`):

```bash
cargo run --example near_stateless_demo --features "equix near-stateless"
```

## Testing & linting

```bash
cargo fmt --all
cargo clippy --workspace --all-features -- -D warnings
cargo test --all-features
```

Running tests without features will compile only the core types; enable the features you use to exercise their code paths.

## License

Apache-2.0 or MIT, at your option.
