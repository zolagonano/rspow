# Near-Stateless Proof-of-Work Protocol

This document describes the design of the "near-stateless" proof-of-work (PoW) protocol used by `rspow`. The protocol is designed to protect backend services from Denial-of-Service (DoS) and abuse by requiring clients to perform computational work, while minimizing the state storage requirements on the server.

## Overview

Traditional PoW protocols often require the server to issue a random nonce to each client and store it to verify the solution later. This introduces a statefulness that can be exploited (e.g., by exhausting server memory with nonce requests).

The `rspow` near-stateless protocol solves this by:
1.  **Deterministic Server Nonces**: The server generates nonces deterministically based on the current time and a secret key. This eliminates the need to store issued nonces.
2.  **Client-derived Challenges**: The client combines the server's time-based nonce with its own random nonce to create a unique challenge.
3.  **Strict Time Windows**: Solutions are only accepted within a specific time window, limiting the effectiveness of precomputed work.
4.  **Minimal State**: The server only needs to cache successful `client_nonce` submissions for the duration of the time window to prevent replay attacks.

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

The client asks the server for the current deterministic nonce details.

1.  **Client** requests: `GET /pow/params`
2.  **Server** determines the current timestamp `ts` (UTC integer seconds).
3.  **Server** computes `deterministic_nonce = F(server_secret, ts)`.
    *   `F` is a high-performance Pseudo-Random Function (PRF), specifically Keyed BLAKE3 (see *PRF Design* below).
    *   `server_secret` is a long-lived 32-byte secret managed by the server.
4.  **Server** returns: `{ ts, deterministic_nonce, difficulty, ... }`.

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

The client submits the solution to access the protected resource.

1.  **Client** sends payload: `{ ts, client_nonce, proof_bundle, ... }`
2.  **Server** performs checks in order:
    1.  **Time Window Check**: Verify `now - time_window <= ts <= now`. If `ts` is too old or in the future, reject.
    2.  **Replay Check**: Check if `client_nonce` exists in the replay cache (e.g., Redis). If it exists, reject.
    3.  **Reconstruct Challenge**:
        *   Recompute `deterministic_nonce = F(server_secret, ts)` (or fetch from a short-lived cache).
        *   Recompute `master_challenge = BLAKE3("rspow:challenge:v1" || deterministic_nonce || client_nonce)`.
    4.  **Verify Proof**:
        *   Verify that `proof_bundle` is valid for `master_challenge`.
        *   Verify that the solution meets the required `difficulty`.
3.  **Server** finalizes:
    *   If valid: Store `client_nonce` in the replay cache with a TTL of `time_window`.
    *   Allow the request to proceed.

## PRF & Deterministic Nonce Design

The server derives the `deterministic_nonce` using a keyed BLAKE3 hash. BLAKE3 is chosen for its exceptional performance and security properties.

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
While `F(secret, ts)` is fast, a high-traffic server can cache the result of `deterministic_nonce(ts)` in memory for the duration of the second (or slightly longer) to avoid re-hashing for every request. This is purely an optimization.

### 2. Replay Protection (Required)
The server **must** track used `client_nonce` values to prevent replay attacks.
*   **Storage**: Redis, Memcached, or an in-memory LRU cache (for single-instance deployments).
*   **Key**: `"rspow:seen:" + client_nonce.to_hex()`
*   **TTL**: `time_window` (e.g., 3600 seconds). After the timestamp expires, the nonce is no longer valid anyway, so the record can be dropped.

## Security Analysis

### Precomputation
The attacker is limited to the `time_window`. If the window is 1 hour, an attacker can at best compute 1 hour's worth of proofs ahead of time. They cannot accumulate months of work to launch a massive spike attack.

### Replay Attacks
Since the `master_challenge` commits to the `client_nonce`, and the server enforces uniqueness of the `client_nonce` within the validity window, a proof cannot be reused.

### Statelessness Trade-off
The protocol is "near-stateless" because the server does not store *issued* challenges. It only stores *fulfilled* challenges. This ensures that the storage cost is linear with the number of *successful* requests (valid users), not the number of *attempted* requests (attackers).

## Implementation Notes

*   **Domain Separation**: The tag `"rspow:challenge:v1"` must be used strictly when generating the master challenge to avoid collisions with other protocols or versions.
*   **EquiX Backend**: This design assumes the use of the `rspow` EquiX implementation. The `ProofBundle` verification should use the strict verification mode.
