# Signature Scheme Benchmarks

This directory contains benchmarks comparing SILMARILS (Information-Theoretic Signature) against several other signature schemes:

- **ECDSA secp256k1** - Classical elliptic curve signature scheme
- **Dilithium2 (ML-DSA-44)** - Post-quantum lattice-based signature
- **Dilithium3 (ML-DSA-65)** - Higher security level variant of Dilithium
- **Falcon-512** - Post-quantum lattice-based signature with smaller signatures
- **SPHINCS+-128s** - Post-quantum hash-based signature (small variant)
- **SPHINCS+-128f** - Post-quantum hash-based signature (fast variant)

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
cargo bench --bench signature_bench -- Dilithium2-ML-DSA-44
cargo bench --bench signature_bench -- Dilithium3-ML-DSA-65
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

### Analyzing Results

All analysis scripts work directly with `target/criterion/` - no copying needed:

1. **Summarize results** (text summary from JSON files):
```bash
# Uses target/criterion by default
python3 scripts/summarize_results.py

# Or specify a directory
python3 scripts/summarize_results.py target/criterion
```

2. **Generate publication-quality plots**:
```bash
# Install Python dependencies (recommended: use a virtual environment)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r scripts/requirements.txt

# Uses target/criterion by default
python3 scripts/plot_benchmarks.py

# Or specify a directory and output file
python3 scripts/plot_benchmarks.py target/criterion benchmark_comparison.pdf
```

This generates two types of comparison plots:
- **Bar charts** (`benchmark_comparison.pdf/png`) - Side-by-side comparison of signing and verification times
- **Line charts** (`benchmark_comparison_line.pdf/png`) - Line plots showing performance across message sizes

Both plots are suitable for inclusion in academic papers with:
- Log scale for better visualization of wide performance ranges
- Professional styling with clear labels and legends
- High-resolution output (300 DPI)
- PDF and PNG formats


## Dependencies

The benchmarks require the following crates:
- `criterion` - Benchmarking framework
- `k256` - ECDSA secp256k1 implementation
- `pqcrypto-dilithium` - Dilithium implementations
- `pqcrypto-falcon` - Falcon implementation
- `pqcrypto-sphincsplus` - SPHINCS+ implementations

All dependencies are automatically managed by Cargo.

