use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use it_sig::signature::{sign, verify_designated, derive_private_key, derive_public_key, ChannelKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

// Blockchain-relevant message sizes: 64B (minimal), 128B (small tx), 256B (typical tx), 512B (large tx)
const INPUT_SIZES: &[usize] = &[64, 128, 256, 512, 1024];

// Configure sample size for more accurate measurements (default is ~100)
// Increase this for more statistical confidence, but benchmarks will take longer
// ECDSA secp256k1
use k256::ecdsa::{SigningKey, VerifyingKey, Signature, signature::Signer, signature::Verifier};

// Post-quantum schemes
use pqcrypto_dilithium::dilithium3::{
    keypair as dilithium3_keypair,
    detached_sign as dilithium3_sign,
    verify_detached_signature as dilithium3_verify,
};
use pqcrypto_dilithium::dilithium2::{
    keypair as dilithium2_keypair,
    detached_sign as dilithium2_sign,
    verify_detached_signature as dilithium2_verify,
};
use pqcrypto_falcon::falcon512::{
    keypair as falcon512_keypair,
    detached_sign as falcon512_sign,
    verify_detached_signature as falcon512_verify,
};
use pqcrypto_sphincsplus::sphincssha256128fsimple::{
    keypair as sphincsplus128f_keypair,
    sign as sphincsplus128f_sign,
    open as sphincsplus128f_verify,
};
use pqcrypto_sphincsplus::sphincssha256128ssimple::{
    keypair as sphincsplus128s_keypair,
    sign as sphincsplus128s_sign,
    open as sphincsplus128s_verify,
};


fn generate_test_message(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 256) as u8).collect()
}

fn demo_channel_key(seed: &str) -> ChannelKey {
    let mut hasher = Sha256::new();
    hasher.update(b"channel-key-derivation:");
    hasher.update(seed.as_bytes());
    let hash = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash);
    key
}

// SILMARILS benchmarks
fn bench_silmarils_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("SILMARILS");
    
    for size in INPUT_SIZES.iter() {
        let message = generate_test_message(*size);
        let private_key = derive_private_key("bench-seed");
        let channel_key = demo_channel_key("bench-seed");
        
        group.bench_with_input(
            BenchmarkId::new("sign", size),
            &message,
            |b, msg| {
                b.iter(|| {
                    sign(black_box(msg), &private_key, &channel_key)
                });
            },
        );
    }
    group.finish();
}

fn bench_silmarils_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("SILMARILS");
    
    for size in INPUT_SIZES.iter() {
        let message = generate_test_message(*size);
        let private_key = derive_private_key("bench-seed");
        let public_key = derive_public_key(&private_key);
        let channel_key = demo_channel_key("bench-seed");
        let signature = sign(&message, &private_key, &channel_key);
        
        group.bench_with_input(
            BenchmarkId::new("verify", size),
            &(&message, &signature, &public_key, &channel_key),
            |b, (msg, sig, pk, ck)| {
                b.iter(|| {
                    verify_designated(black_box(msg), black_box(sig), black_box(pk), black_box(ck))
                });
            },
        );
    }
    group.finish();
}

// ECDSA secp256k1 benchmarks
fn bench_ecdsa_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDSA-secp256k1");
    
    for size in INPUT_SIZES.iter() {
        let message = generate_test_message(*size);
        let signing_key = SigningKey::random(&mut OsRng);
        
        group.bench_with_input(
            BenchmarkId::new("sign", size),
            &message,
            |b, msg| {
                b.iter(|| {
                    let digest = Sha256::digest(msg);
                    let signature: Signature = signing_key.sign(&digest);
                    signature
                });
            },
        );
    }
    group.finish();
}

fn bench_ecdsa_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDSA-secp256k1");
    
    for size in INPUT_SIZES.iter() {
        let message = generate_test_message(*size);
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = VerifyingKey::from(&signing_key);
        let digest = Sha256::digest(&message);
        let signature: Signature = signing_key.sign(&digest);
        
        group.bench_with_input(
            BenchmarkId::new("verify", size),
            size,
            |b, _| {
                b.iter(|| {
                    verifying_key.verify(black_box(&digest), black_box(&signature)).is_ok()
                });
            },
        );
    }
    group.finish();
}

// Dilithium2 (ML-DSA-44) benchmarks
fn bench_dilithium2_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("Dilithium2-ML-DSA-44");
    
    for size in INPUT_SIZES.iter() {
        let message = generate_test_message(*size);
        let (_public_key, secret_key) = dilithium2_keypair();
        
        group.bench_with_input(
            BenchmarkId::new("sign", size),
            &message,
            |b, msg| {
                b.iter(|| {
                    dilithium2_sign(msg, &secret_key)
                });
            },
        );
    }
    group.finish();
}

fn bench_dilithium2_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("Dilithium2-ML-DSA-44");
    
    for size in INPUT_SIZES.iter() {
        let message = generate_test_message(*size);
        let (public_key, secret_key) = dilithium2_keypair();
        let signature = dilithium2_sign(&message, &secret_key);
        
        group.bench_with_input(
            BenchmarkId::new("verify", size),
            size,
            |b, _| {
                b.iter(|| {
                    dilithium2_verify(black_box(&signature), black_box(&message), black_box(&public_key))
                });
            },
        );
    }
    group.finish();
}

// Dilithium3 benchmarks
fn bench_dilithium3_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("Dilithium3-ML-DSA-65");
    
    for size in INPUT_SIZES.iter() {
        let message = generate_test_message(*size);
        let (_public_key, secret_key) = dilithium3_keypair();
        
        group.bench_with_input(
            BenchmarkId::new("sign", size),
            &message,
            |b, msg| {
                b.iter(|| {
                    dilithium3_sign(msg, &secret_key)
                });
            },
        );
    }
    group.finish();
}

fn bench_dilithium3_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("Dilithium3-ML-DSA-65");
    
    for size in INPUT_SIZES.iter() {
        let message = generate_test_message(*size);
        let (public_key, secret_key) = dilithium3_keypair();
        let signature = dilithium3_sign(&message, &secret_key);
        
        group.bench_with_input(
            BenchmarkId::new("verify", size),
            size,
            |b, _| {
                b.iter(|| {
                    dilithium3_verify(black_box(&signature), black_box(&message), black_box(&public_key))
                });
            },
        );
    }
    group.finish();
}

// Falcon-512 benchmarks
fn bench_falcon512_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("Falcon-512");
    
    for size in INPUT_SIZES.iter() {
        let message = generate_test_message(*size);
        let (_public_key, secret_key) = falcon512_keypair();
        
        group.bench_with_input(
            BenchmarkId::new("sign", size),
            &message,
            |b, msg| {
                b.iter(|| {
                    falcon512_sign(msg, &secret_key)
                });
            },
        );
    }
    group.finish();
}

fn bench_falcon512_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("Falcon-512");
    
    for size in INPUT_SIZES.iter() {
        let message = generate_test_message(*size);
        let (public_key, secret_key) = falcon512_keypair();
        let signature = falcon512_sign(&message, &secret_key);
        
        group.bench_with_input(
            BenchmarkId::new("verify", size),
            size,
            |b, _| {
                b.iter(|| {
                    falcon512_verify(black_box(&signature), black_box(&message), black_box(&public_key))
                });
            },
        );
    }
    group.finish();
}

// SPHINCS+-128s benchmarks

fn bench_sphincsplus128s_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("SPHINCS+-128s");
    
    for size in INPUT_SIZES.iter() {
        let message = generate_test_message(*size);
        let (_public_key, secret_key) = sphincsplus128s_keypair();
        
        group.bench_with_input(
            BenchmarkId::new("sign", size),
            &message,
            |b, msg| {
                b.iter(|| {
                    sphincsplus128s_sign(msg, &secret_key)
                });
            },
        );
    }
    group.finish();
}

fn bench_sphincsplus128s_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("SPHINCS+-128s");
    
    for size in INPUT_SIZES.iter() {
        let message = generate_test_message(*size);
        let (public_key, secret_key) = sphincsplus128s_keypair();
        let signature = sphincsplus128s_sign(&message, &secret_key);
        
        group.bench_with_input(
            BenchmarkId::new("verify", size),
            &(&signature, &public_key),
            |b, (sig, pk)| {
                b.iter(|| {
                    sphincsplus128s_verify(black_box(sig), black_box(pk))
                });
            },
        );
    }
    group.finish();
}

// SPHINCS+-128f benchmarks
fn bench_sphincsplus128f_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("SPHINCS+-128f");
    
    for size in INPUT_SIZES.iter() {
        let message = generate_test_message(*size);
        let (_public_key, secret_key) = sphincsplus128f_keypair();
        
        group.bench_with_input(
            BenchmarkId::new("sign", size),
            &message,
            |b, msg| {
                b.iter(|| {
                    sphincsplus128f_sign(msg, &secret_key)
                });
            },
        );
    }
    group.finish();
}

fn bench_sphincsplus128f_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("SPHINCS+-128f");
    
    for size in INPUT_SIZES.iter() {
        let message = generate_test_message(*size);
        let (public_key, secret_key) = sphincsplus128f_keypair();
        let signature = sphincsplus128f_sign(&message, &secret_key);
        
        group.bench_with_input(
            BenchmarkId::new("verify", size),
            &(&signature, &public_key),
            |b, ( sig, pk)| {
                b.iter(|| {
                    sphincsplus128f_verify(black_box(sig), black_box(pk))
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_silmarils_sign,
    bench_silmarils_verify,
    bench_ecdsa_sign,
    bench_ecdsa_verify,
    bench_dilithium2_sign,
    bench_dilithium2_verify,
    bench_dilithium3_sign,
    bench_dilithium3_verify,
    bench_falcon512_sign,
    bench_falcon512_verify,
    bench_sphincsplus128s_sign,
    bench_sphincsplus128s_verify,
    bench_sphincsplus128f_sign,
    bench_sphincsplus128f_verify
);
criterion_main!(benches);
