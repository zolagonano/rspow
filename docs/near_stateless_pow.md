# Near-Stateless Proof-of-Work Protocol

This document describes the design of the "near-stateless" proof-of-work (PoW) protocol used by `rspow`. The protocol is designed to protect backend services from Denial-of-Service (DoS) and abuse by requiring clients to perform computational work, while minimizing the state storage requirements on the server.

## Overview

Traditional PoW protocols often require the server to issue and store random nonces. Attackers can exploit this by hoarding issued nonces and exhausting server memory. The `near-stateless` feature of `rspow` offers a helper toolkit for the protocol outlined below:

1.  **Deterministic server nonces**: Derived from a server secret and timestamp; no issuance store is needed.
2.  **Client-derived challenges**: Clients mix the server nonce with their own random `client_nonce`.
3.  **Strict time windows**: Submissions are only accepted when `timestamp` lies within `[now - time_window, now]`.
4.  **Minimal state**: The server caches only accepted `client_nonce` values for the duration of the window to block replay.

The toolkit is feature-gated (`features = ["near-stateless"]`) and depends on the EquiX backend. Helper traits are pluggable so you can swap implementations without touching protocol logic.

## Threat Model & Goals

The protocol is designed to mitigate the following threats:

*   **Resource Exhaustion (DoS)**: Attackers spamming requests to exhaust server CPU or memory.
    *   *Mitigation*: Pre-verification is cheap (hash checks). Challenge verification is computationally expensive for the client but efficient for the server to verify.
*   **State Exhaustion**: Attackers requesting millions of nonces to fill up the server's session store.
    *   *Mitigation*: The server stores no state for issuing nonces. State is only stored *after* a valid proof is submitted.
*   **Replay Attacks**: Attackers resubmitting the same valid proof multiple times.
    *   *Mitigation*: The server caches the `client_nonce` of accepted solutions until the time window expires.
*   **Precomputation**: Attackers accumulating valid proofs over a long period to flood the server instantly.
    *   *Mitigation*: Proofs are cryptographically bound to a timestamp. The server rejects timestamps older than the configured `time_window` (e.g., 1 hour).

## Protocol Flow

The protocol consists of three phases: **GetNonce**, **Solve**, and **Submit & Verify**.

### 1. GetNonce (Client -> Server)

The client requests current parameters (or you expose them through any transport/API you like).

1.  **Server** determines the current timestamp `ts` (UTC integer seconds).
2.  **Server** computes `deterministic_nonce = F(server_secret, ts)`.
    *   `F` is a high-performance PRF: default is keyed BLAKE3 with tag `"rspow:nonce:v1"`.
    *   `server_secret` is a 32-byte secret you manage; all frontends must share it.
3.  **Server** returns `{ ts, deterministic_nonce, difficulty, min_required_proofs }`.

### 2. Solve (Client)

The client performs the computational work.

1.  **Client** generates a random 32-byte `client_nonce`.
2.  **Client** computes the `master_challenge`:
    ```text
    master_challenge = BLAKE3("rspow:challenge:v1" || deterministic_nonce || client_nonce)
    ```
    *   The string `"rspow:challenge:v1"` acts as a domain separation tag.
3.  **Client** runs the **EquiX** engine using `master_challenge` to find a `ProofBundle` that meets the target `difficulty`.

### 3. Submit & Verify (Client -> Server)

1.  **Client** sends `{ ts, client_nonce, proof_bundle }`.
2.  **Server** checks:
    1.  **Time window**: `now - time_window <= ts <= now` (`time_window` must be ≥ 1s; the helper rejects smaller windows up front).
    2.  **Replay**: look up `client_nonce` in the replay cache; if present and unexpired, reject.
    3.  **Challenge**: recompute `deterministic_nonce` and `master_challenge` exactly as the client did.
    4.  **Proofs**: verify the bundle with `verify_strict(min_difficulty, min_required_proofs)`.
3.  **If valid**: insert `client_nonce` into the replay cache with expiry at `ts + time_window`.

## PRF & Deterministic Nonce Design

The server derives the `deterministic_nonce` using a keyed BLAKE3 hash. BLAKE3 is chosen for its exceptional performance and security properties; the helper exposes this as `Blake3NonceProvider`, but you can provide any `DeterministicNonceProvider`.

```rust
// Pseudocode
fn deterministic_nonce(server_secret: [u8; 32], ts: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(&server_secret);
    hasher.update(b"rspow:nonce:v1"); // Domain separation
    hasher.update(&ts.to_le_bytes());
    hasher.finalize().into()
}
```

*   **Determinism**: Ensures that for a given second, all servers (sharing the same secret) generate the same nonce, facilitating load balancing without shared state.
*   **Unpredictability**: An attacker cannot predict future nonces without the `server_secret`, preventing precomputation beyond the current time.

## Caching Strategy

To balance CPU usage and memory, we employ a two-tiered strategy:

### 1. Server-Side Nonce Caching (Optional)
`F(secret, ts)` is intentionally cheap; in most deployments recomputation is faster and simpler than maintaining a cache. If you still prefer caching, implement it inside your `DeterministicNonceProvider`.

### 2. Replay Protection (Required)
The server **must** track used `client_nonce` values to prevent replay attacks.
*   **Storage**: Redis/Memcached, or the built-in `MokaReplayCache` for single-node use. If you use a capacity-bound cache, evictions can allow replays; size it for your expected QPS or provide your own `ReplayCache` implementation.
*   **Key**: `client_nonce` bytes.
*   **Expiry**: `ts + time_window`.

## Security Analysis

### Precomputation
The attacker is limited to the `time_window`. If the window is 1 hour, an attacker can at best compute 1 hour's worth of proofs ahead of time. They cannot accumulate months of work to launch a massive spike attack.

### Replay Attacks
Since the `master_challenge` commits to the `client_nonce`, and the server enforces uniqueness of the `client_nonce` within the validity window, a proof cannot be reused.

### Statelessness Trade-off
The protocol is "near-stateless" because the server does not store *issued* challenges—only *fulfilled* ones for replay protection. Storage grows with successful requests instead of attacker traffic.

## Helper APIs (feature = "near-stateless")

- `DeterministicNonceProvider`: derive deterministic nonces; default `Blake3NonceProvider`.
- `ReplayCache`: prevent replays; default `MokaReplayCache::insert_if_absent`.
- `TimeProvider`: injectable clock for tests.
- `VerifierConfig`: validated config (`time_window >= 1s`); hot-updatable via `NearStatelessVerifier::set_config` (lock-free reads with left-right).
- `Submission`: `{ timestamp, client_nonce, ProofBundle }`; build manually or with `build_submission`/`solve_submission`.

## Implementation Notes

*   **Domain Separation**: The tag `"rspow:challenge:v1"` must be used strictly when generating the master challenge to avoid collisions with other protocols or versions.
*   **EquiX Backend**: This design assumes the use of the `rspow` EquiX implementation. The `ProofBundle` verification should use the strict verification mode.
