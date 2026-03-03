//! Field arithmetic benchmark: arkworks secp256k1::Fr  vs  blst BLS12-381 Fr
//!
//! arkworks  –  secp256k1 scalar field (256-bit prime)
//!   r = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
//! blst      –  BLS12-381 scalar field (255-bit prime, hand-written assembly)
//!   r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
//!
//! Benchmarks:
//!   field-add      – 1000× chained additions  (amortises call overhead)
//!   field-mul      – 1000× chained multiplications
//!   field-inv      – single modular inversion  (Fermat / Euclidean)
//!   lagrange-2pt   – 2-point Lagrange interpolation, the core of SILMARILS verify

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use ark_ff::{Field as ArkField, UniformRand};
use ark_secp256k1::Fr as ArkFr;

use blstrs::Scalar as BlstFr;
use ff::Field as FfField;

use rand::SeedableRng;
use rand_chacha::ChaChaRng;

const SEED: [u8; 32] = [0x42u8; 32];
const BATCH: usize = 1000;

// ---------------------------------------------------------------------------
// 2-point Lagrange interpolation  f(0) = L0(0)·y0 + L1(0)·y1
//   L0(0) = -x1 / (x0 - x1)
//   L1(0) = -x0 / (x1 - x0)
// ---------------------------------------------------------------------------

fn lagrange_ark(x0: ArkFr, y0: ArkFr, x1: ArkFr, y1: ArkFr) -> ArkFr {
    let l0 = (-x1) * (x0 - x1).inverse().unwrap();
    let l1 = (-x0) * (x1 - x0).inverse().unwrap();
    l0 * y0 + l1 * y1
}

fn lagrange_blst(x0: BlstFr, y0: BlstFr, x1: BlstFr, y1: BlstFr) -> BlstFr {
    let l0 = (-x1) * Option::<BlstFr>::from((x0 - x1).invert()).unwrap();
    let l1 = (-x0) * Option::<BlstFr>::from((x1 - x0).invert()).unwrap();
    l0 * y0 + l1 * y1
}

// ---------------------------------------------------------------------------

fn bench_add(c: &mut Criterion) {
    let mut rng = ChaChaRng::from_seed(SEED);

    let ark_a: Vec<ArkFr> = (0..BATCH).map(|_| ArkFr::rand(&mut rng)).collect();
    let ark_b: Vec<ArkFr> = (0..BATCH).map(|_| ArkFr::rand(&mut rng)).collect();
    let blst_a: Vec<BlstFr> = (0..BATCH).map(|_| BlstFr::random(&mut rng)).collect();
    let blst_b: Vec<BlstFr> = (0..BATCH).map(|_| BlstFr::random(&mut rng)).collect();

    let mut group = c.benchmark_group("field-add");
    group.sample_size(200);

    group.bench_function("arkworks/secp256k1-Fr", |b| {
        b.iter(|| {
            let mut acc = black_box(ark_a[0]);
            for i in 0..BATCH {
                acc += black_box(ark_b[i]);
            }
            acc
        })
    });

    group.bench_function("blst/BLS12-381-Fr", |b| {
        b.iter(|| {
            let mut acc = black_box(blst_a[0]);
            for i in 0..BATCH {
                acc += black_box(blst_b[i]);
            }
            acc
        })
    });

    group.finish();
}

fn bench_mul(c: &mut Criterion) {
    let mut rng = ChaChaRng::from_seed(SEED);

    let ark_a: Vec<ArkFr> = (0..BATCH).map(|_| ArkFr::rand(&mut rng)).collect();
    let ark_b: Vec<ArkFr> = (0..BATCH).map(|_| ArkFr::rand(&mut rng)).collect();
    let blst_a: Vec<BlstFr> = (0..BATCH).map(|_| BlstFr::random(&mut rng)).collect();
    let blst_b: Vec<BlstFr> = (0..BATCH).map(|_| BlstFr::random(&mut rng)).collect();

    let mut group = c.benchmark_group("field-mul");
    group.sample_size(200);

    group.bench_function("arkworks/secp256k1-Fr", |b| {
        b.iter(|| {
            let mut acc = black_box(ark_a[0]);
            for i in 0..BATCH {
                acc *= black_box(ark_b[i]);
            }
            acc
        })
    });

    group.bench_function("blst/BLS12-381-Fr", |b| {
        b.iter(|| {
            let mut acc = black_box(blst_a[0]);
            for i in 0..BATCH {
                acc *= black_box(blst_b[i]);
            }
            acc
        })
    });

    group.finish();
}

fn bench_inv(c: &mut Criterion) {
    let mut rng = ChaChaRng::from_seed(SEED);

    let ark_x = ArkFr::rand(&mut rng);
    let blst_x = BlstFr::random(&mut rng);

    let mut group = c.benchmark_group("field-inv");
    group.sample_size(200);

    group.bench_function("arkworks/secp256k1-Fr", |b| {
        b.iter(|| black_box(ark_x).inverse().unwrap())
    });

    group.bench_function("blst/BLS12-381-Fr", |b| {
        b.iter(|| Option::<BlstFr>::from(black_box(blst_x).invert()).unwrap())
    });

    group.finish();
}

fn bench_lagrange(c: &mut Criterion) {
    let mut rng = ChaChaRng::from_seed(SEED);

    let ark_x0 = ArkFr::rand(&mut rng);
    let ark_y0 = ArkFr::rand(&mut rng);
    let ark_x1 = ArkFr::rand(&mut rng);
    let ark_y1 = ArkFr::rand(&mut rng);

    let blst_x0 = BlstFr::random(&mut rng);
    let blst_y0 = BlstFr::random(&mut rng);
    let blst_x1 = BlstFr::random(&mut rng);
    let blst_y1 = BlstFr::random(&mut rng);

    let mut group = c.benchmark_group("lagrange-2pt");
    group.sample_size(200);

    group.bench_function("arkworks/secp256k1-Fr", |b| {
        b.iter(|| {
            lagrange_ark(
                black_box(ark_x0),
                black_box(ark_y0),
                black_box(ark_x1),
                black_box(ark_y1),
            )
        })
    });

    group.bench_function("blst/BLS12-381-Fr", |b| {
        b.iter(|| {
            lagrange_blst(
                black_box(blst_x0),
                black_box(blst_y0),
                black_box(blst_x1),
                black_box(blst_y1),
            )
        })
    });

    group.finish();
}

criterion_group!(benches, bench_add, bench_mul, bench_inv, bench_lagrange);
criterion_main!(benches);
