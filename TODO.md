# EquiX Multi-thread & Bundle Improvements

- [x] Document a clear seed/anti-replay protocol (server nonce + client work nonce), mandate `LeadingZeroBits`, and expose it via official sdk && doc so integrators don’t guess.
- [x] Deduplicate EquiX hits (work_nonce, solution/tag) both during parallel collection and inside `EquixProofBundle::verify_all` to block duplicates and skewed stats.
- [x] Add property/concurrency tests: single vs multi-thread hit sets match; tampered `base_tag`/derived tags or duplicated proofs fail verification.
- [x] Provide a higher-level EquiX solver API that can stream hits and emit an `EquixProofBundle` directly, reducing caller assembly mistakes.
- [x] Share a common nonce dispatcher/early-stop workflow between EquiX and `kpow` to avoid divergent thread logic and simplify maintenance.
