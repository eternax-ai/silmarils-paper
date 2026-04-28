# Signature Scheme Benchmarks

This directory contains benchmarks comparing SILMARILS (Information-Theoretic Signature) against several other signature schemes:

- **ECDSA secp256k1** (`k256`) — classical elliptic curve signatures
- **Dilithium2** (`pqcrypto-dilithium::dilithium2`) — lattice-based signatures
- **Dilithium3** (`pqcrypto-dilithium::dilithium3`) — higher-parameter Dilithium variant
- **Falcon-512** (`pqcrypto-falcon::falcon512`) — lattice-based signatures with compact signatures
- **SPHINCS+ SHA256 128s simple** (`pqcrypto-sphincsplus::sphincssha256128ssimple`) — hash-based signatures (small signature variant)
- **SPHINCS+ SHA256 128f simple** (`pqcrypto-sphincsplus::sphincssha256128fsimple`) — hash-based signatures (fast signing variant)

These parameter tiers align with common NIST naming for comparison only: ML-DSA-44 / ML-DSA-65 (FIPS 204), FN-DSA-512 (FIPS 206), SLH-DSA-SHA2-128s / SLH-DSA-SHA2-128f (FIPS 205). This benchmark invokes **pqclean-style APIs** from the crates above; wire formats are not necessarily identical to certified FIPS encodings.

## Running Benchmarks

To run all benchmarks:

```bash
cargo bench
```

**Note:** Benchmarks use `SAMPLE_SIZE = 1000` (Criterion default is ~100) for more accurate measurements. To change it, edit the `SAMPLE_SIZE` constant in `benches/signature_bench.rs`. Use `cargo bench -- --quick` for a faster run with lower statistical guarantees.

To run a specific benchmark group:

```bash
cargo bench --bench signature_bench -- SILMARILS
cargo bench --bench signature_bench -- ECDSA-secp256k1
cargo bench --bench signature_bench -- Dilithium2
cargo bench --bench signature_bench -- Dilithium3
cargo bench --bench signature_bench -- Falcon-512
cargo bench --bench signature_bench -- SPHINCS+-128s
cargo bench --bench signature_bench -- SPHINCS+-128f
```

## Benchmark Metrics

Each benchmark measures:
- **Signing time** - Time to generate a signature for messages of different sizes (64, 128, 256, 512, 1024 bytes)
- **Verification time** - Time to verify a signature

Message sizes are chosen to reflect realistic blockchain transaction sizes:
- **64 bytes** - Minimal transaction (header + minimal data)
- **128 bytes** - Small transaction (typical for simple transfers)
- **256 bytes** - Typical transaction (standard blockchain operations)
- **512 bytes** - Large transaction (complex operations with additional data)
- **1024 bytes** - Very large transaction (rare but possible in complex applications)

Results are reported with statistical analysis including:
- Mean execution time
- Standard deviation
- Confidence intervals
- Throughput (operations per second)

## Viewing Results

After running benchmarks, detailed HTML reports are generated in `target/criterion/`. Open `target/criterion/report/index.html` in a web browser to view interactive charts and comparisons.

## Analyzing Results

Criterion automatically saves results in JSON format in `target/criterion/`. You can analyze them directly without copying:

### JSON Files (Automatic)
JSON files are automatically generated in `target/criterion/<benchmark-name>/<function>/<value>/new/`. Each benchmark run creates:
- `estimates.json` - Statistical estimates (mean, median, std dev, confidence intervals)
- `sample.json` - Raw sample data with iteration counts and measured times
- `tukey.json` - Outlier detection data
- `benchmark.json` - Benchmark configuration and metadata

These JSON files contain detailed statistical data including:
- Mean execution time with confidence intervals
- Median execution time
- Standard deviation
- Throughput calculations
- Raw sample measurements

## Results snapshot (at time of publication)

The tables below reproduce **fixed results** captured at the time of publication. **They are not live or CI-updated:** expect different figures if you change code, toolchain, or run on other hardware. Re-run `cargo bench` and inspect `target/criterion/` for fresh measurements.

**Environment (recorded run).** Apple M1 Pro (ARM64, 10 cores, 3.2 GHz performance cores), 16 GB LPDDR5, macOS 26.3 (Darwin 25.3.0). Rust `rustc 1.88.0`, `cargo 1.88.0`, release profile default optimizations (`opt-level = 3`). Criterion 0.5 with mean, standard deviation, and 95% confidence intervals, Tukey-fence outlier handling, **1,000 samples** per configuration (see `SAMPLE_SIZE` in `signature_bench.rs`). Compared schemes use the crates and modules listed [above](#signature-scheme-benchmarks).

**Methodology.** Five message sizes (64–1024 bytes) reflecting representative blockchain payload lengths; each entry measures **sign** or **verify** only, with keys and signatures prepared outside the timed loop.

### Table 1 — Mean signing time (µs)

| Scheme\Message Size     |    64 B |   128 B |   256 B |   512 B |  1024 B |
|-------------------------|--------:|--------:|--------:|--------:|--------:|
| SILMARILS               |    25.9 |    26.4 |    27.5 |    29.7 |    34.2 |
| ECDSA-secp256k1         |    40.9 |    41.0 |    41.4 |    42.1 |    43.6 |
| Dilithium2              |    98.8 |    64.7 |    71.6 |    76.4 |    90.9 |
| Dilithium3              |   163.8 |   188.6 |   171.7 |   145.5 |   244.9 |
| Falcon-512              |   152.5 |   155.2 |   153.5 |   153.8 |   155.1 |
| SPHINCS+-128s           | 537,897 | 535,526 | 537,721 | 536,656 | 536,592 |
| SPHINCS+-128f           |  36,121 |  35,263 |  35,300 |  35,303 |  35,381 |

### Table 2 — Mean verification time (µs)

| Scheme\Message Size     |    64 B |   128 B |   256 B |   512 B |  1024 B |
|-------------------------|--------:|--------:|--------:|--------:|--------:|
| SILMARILS               |     4.8 |     5.2 |     5.9 |     7.4 |    10.4 |
| ECDSA-secp256k1         |    65.2 |    65.1 |    65.5 |    65.4 |    65.5 |
| Dilithium2              |    21.4 |    21.7 |    22.1 |    23.1 |    25.1 |
| Dilithium3              |    32.6 |    32.9 |    33.5 |    34.6 |    36.4 |
| Falcon-512              |    23.4 |    23.2 |    23.8 |    24.6 |    26.3 |
| SPHINCS+-128s           |   621.0 |   600.9 |   602.3 |   667.4 |   620.6 |
| SPHINCS+-128f           | 1,499.6 | 1,423.8 | 1,464.5 | 1,498.2 | 1,505.4 |

**Summary** SILMARILS showed the lowest signing latency in this table (about 1.2×–1.7× faster than ECDSA signing and several times faster than the lattice PQ baselines shown). Verification stayed in single-digit to low tens of µs for SILMARILS versus tens of µs for ECDSA verify in this dataset. Among PQ options, Dilithium2 and Falcon-512 had the lowest verify times here; SPHINCS+ variants had very high signing cost but moderate verify times relative to signing. Dilithium3 increased cost versus Dilithium2, consistent with a higher parameter tier.

## Dependencies

The benchmarks require the following crates:
- `criterion` - Benchmarking framework
- `k256` - ECDSA secp256k1 implementation
- `pqcrypto-dilithium` - Dilithium (`dilithium2`, `dilithium3`)
- `pqcrypto-falcon` - Falcon (`falcon512`)
- `pqcrypto-sphincsplus` - SPHINCS+ (`sphincssha256128ssimple`, `sphincssha256128fsimple`)

All dependencies are automatically managed by Cargo.

