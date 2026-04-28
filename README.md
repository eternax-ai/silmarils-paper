# SILMARILS — reference implementation

Reference Rust code for the **two-party transferable designated-verifier (TDV)** mode of **SILMARILS**, the information-theoretic signature framework in:

**SILMARILS: Information-Theoretic and Quantum-Secure Designated-Verifier Signatures**

**Authors:** Hassan Khodaiemehr, Khadijeh Bagheri, Chen Feng (University of British Columbia Okanagan); Dariia Porechna (EternaX Labs).

This repository is cited in the paper as the open implementation for reproducing the key generation and algebraic signing/verification core.

## What SILMARILS is (in one paragraph)

SILMARILS builds a compact signature from arithmetic over a prime field **F_p**, true randomness (in the formal treatment), and perfect **2-out-of-2 Shamir** sharing. In **two-party mode**, only the **designated verifier**—who shares a **channel secret** with the signer—can check signatures in the strong sense of Jakobsson–Sako–Impagliazzo (the verifier can simulate accepting transcripts, so third parties are not “cryptographically convinced” without extra protocol). The paper proves **EUF-CMA¬DV**: unforgeability for everyone who does **not** hold the channel key, in the ROM and QROM. **Transferable verification** is supported by publishing a **receipt** `r` after designated verification; third parties can verify using `(message, signature, r)`.

For motivation (e.g. compact records in PQ blockchain designs), see Section 1.2 of the paper; full ledger integration is explicitly **out of scope** there and in this repo.

## What this code implements

- Two-party **sign** / **designated verify** / **receipt verify**
- Shamir **split** / **reconstruct** over the chosen field
- Tests for correct use, message binding, and **algebraic forgery** when `r` is mishandled

Arithmetic is implemented over **secp256k1’s base field** (`ark_secp256k1::Fq`) as a concrete **p ≈ 2^256** choice. The verification predicate is the same **Shamir-reconstruction-equals-zero** check as in Section 4.2, with an explicit guard to block a degenerate algebraic bypass documented in tests.

### Message digest and receipt (matches Section 4.2 intent)

- **Nonce:** `n = HMAC_{k_sig}( "silmarils-nonce" || M )` (never sent on the wire in the ideal picture).
- **Receipt field:** `r = SHA-256(M || encode(n))` reduced into **F_p** (see `compute_receipt_hash`).
- **Per-message signing key:** `K' = HMAC_K( "silmarils-pmk" || M )` reduced into **F_p**.

The demo binary derives a **32-byte channel key** from the user seed for convenience; in deployment this should be the pairwise secret you intend the paper’s **`k_sig`** to represent (e.g. from a TLS exporter).

### Public parameters `w0`, `w1`

The paper samples **`w0`, `w1`** as independent public interpolation points. For reproducibility, this reference derives **`(w0, w1) = HKDF_expand(sk, "silmarils-public-key")`** into two field elements (see `derive_public_key`). The signing and verification equations are otherwise aligned with the two-party description.

## Building and running

```bash
cargo build --release
cargo run --release
```

The binary prompts for a **seed** and **message**, then prints keys, a signature, designated verification, and receipt-based verification.

## Tests

```bash
cargo test
```

Tests include round-trips, wrong-key rejection, **receipt misuse** across messages, the **public-`r` algebraic forgery** when verification uses `H(M)` only (must not be used in production).

## Benchmarks (SILMARILS vs PQ baselines)

```bash
cargo bench
```

Criterion compares **SILMARILS** sign/verify against **Dilithium2/3**, **Falcon-512**, **SPHINCS+** (simple/fast variants), and **ECDSA secp256k1** for several message sizes.

## Disclaimer

This is **research reference code**. It has not undergone a production security audit. Use a **proper channel key** and **do not** verify with `r = H(M)` alone; the tests exist to show why.
