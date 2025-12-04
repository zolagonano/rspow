# EquiX-Only Rewrite Plan (Doc v4) — Sync Solve, Progress, Resume

> Fresh, breaking rewrite; EquiX only. No legacy compatibility. Synchronous solve with precise progress; resume by continuing from an existing bundle.

## Principles
- `PowEngine` trait handles solving (and resume); verification lives on data types (`Proof::verify`, `ProofBundle::verify_strict`).
- Builder-first, simple call: build engine once, call `solve_bundle(master_seed)`; no extra config args.
- No streaming of proofs; progress via atomic counter; stop immediately when `required_proofs` reached.
- Dedup proofs to avoid inflated counts / replay tricks.
- Resume by supplying an existing `ProofBundle` and a higher `required_proofs`.
- Tag hashing pluggable (`TagHasher`), default **BLAKE3**.

## Public API (EquiX only)
- Trait (crate-visible):
  ```rust
  trait PowEngine {
      fn solve_bundle(&mut self, challenge: [u8; 32]) -> Result<ProofBundle, Error>;
      fn resume(&mut self, existing: ProofBundle, required_proofs: usize)
          -> Result<ProofBundle, Error>;
  }
  ```
- `EquixEngine` via `EquixEngineBuilder` (derive_builder):
  - `bits: u32`
  - `threads: usize`
  - `required_proofs: usize` (>=1)
  - `progress: Arc<AtomicU64>` (required; counts accepted proofs)
  - `hasher: Hasher` (default BLAKE3; alternatives e.g., SHA-256)

## Types (serde-friendly)
  - `Proof { id: usize, challenge: [u8; 32], solution: [u8; 16] }` (Copy)
    - `id` is the proof index (0-based); `challenge` is the per-proof seed/tag derived for this index.
- `ProofConfig { bits: u32 }`
  - `ProofBundle { proofs: Vec<Proof>, config: ProofConfig, master_challenge: [u8; 32] }`
  - Methods:
    - `insert_proof(&mut self, proof: Proof) -> Result<(), VerifyError>` (dedup; preserves order by index)
    - `verify_strict(&self) -> Result<(), VerifyError>` (uses embedded master_challenge; dedup + short-circuit on first failure)
    - `len(), is_empty()`
- Errors:
  - `VerifyError { DuplicateProof, InvalidDifficulty, Malformed }`
  - Solve `Error`: minimal `InvalidConfig`, `SolverFailed(String)`, `ChannelClosed`

## Semantics
- Per-proof deterministic challenge: `challenge_i = TagHasher::hash("rspow:challenge:v1|" || master_challenge || proof_id)`.
- EquiX search still varies `work_nonce` internally; store the winning `challenge` and `solution` with its `id`.
- Dedup: client-side set of `(work_nonce, solution)`; existing bundle pre-populates dedup and progress.
- Progress: `progress` increments on each accepted proof; front-end polls e.g., every 50ms.
- Resume: provide previous `ProofBundle` and a larger `required_proofs`; engine starts with `proofs.len()` done, continues from next proof index; no separate token.
- `required_proofs=1` yields a bundle of one; no special APIs.

## Concurrency & Stop
- Worker pool with `NonceSource` + stop flag + flume bounded channel (internal); collector drains until `required_proofs` reached; stop is signaled to workers immediately.

## Tests (minimum)
- Determinism: per_proof_seed, challenge.
- Verification: bundle strict rejects duplicate/tamper; short-circuit behavior.
- Concurrency: single vs multi-thread small required_proofs match; progress reaches exact target.
- Resume: N proofs bundle → resume with target N+M → total N+M, no dups.
- required_proofs=1 produces len 1 bundle; verify passes.

## Out of scope (this branch)
- Other algorithms; legacy APIs; README/docs rewrite until API stabilizes.***
