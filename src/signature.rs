use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, PrimeField, UniformRand};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use sha2::{Digest, Sha256};

use crate::shamir::{reconstruct, split, Share};

pub struct PrivateKey {
    pub k: Fr,
    pub omega: Fr,
}

pub type PublicKey = Fr;

pub struct Signature {
    pub sigma_1: Fr,
    pub sigma_2: Fr,
    pub sigma_3: Fr,
    pub sigma_4: Fr,
    pub sigma_5: Fr,
}

pub fn derive_private_key(seed: &str) -> PrivateKey {
    // Convert seed string to bytes for RNG
    let seed_bytes: Vec<u8> = if seed.starts_with("0x") {
        // Handle hex input
        hex::decode(&seed[2..])
            .unwrap_or_else(|_| seed.as_bytes().to_vec())
    } else {
        // Use string bytes as seed
        seed.as_bytes().to_vec()
    };

    // Pad or truncate to 32 bytes for ChaChaRng seed
    let mut seed_array = [0u8; 32];
    let copy_len = seed_bytes.len().min(32);
    seed_array[..copy_len].copy_from_slice(&seed_bytes[..copy_len]);

    // Initialize RNG from seed
    let mut rng = ChaChaRng::from_seed(seed_array);

    // Generate 2 random numbers in Fp (where p is the modulus of Fr, ~2^254)
    // Fr in BN254 curve uses a 254-bit prime, which is close to 2^256
    let random1 = Fr::rand(&mut rng);
    let random2 = Fr::rand(&mut rng);

    PrivateKey {
        k: random1,
        omega: random2,
    }
}

fn derive_private_key_shares(private_key: &PrivateKey) -> (Share, Share) {
    let mut hasher = Sha256::new();
    hasher.update(private_key.k.into_bigint().to_bytes_be());
    hasher.update(private_key.omega.into_bigint().to_bytes_be());
    let hash = hasher.finalize();
    
    let mut rng = ChaChaRng::from_seed(hash.into());
    let shares = split(private_key.k, 2, 2, &mut rng);

    assert_eq!(shares[0].x, Fr::from(1 as u64), "Share 0 x does not equal 1");
    assert_eq!(shares[1].x, Fr::from(2 as u64), "Share 1 x does not equal 2");

    assert_eq!(private_key.k, reconstruct(&[shares[0].clone(), shares[1].clone()]), "Private key does not equal share 0 y + share 1 y");

    (shares[0].clone(), shares[1].clone())
}

pub fn derive_public_key(private_key: &PrivateKey) -> PublicKey {
    let shares = derive_private_key_shares(private_key);

    shares.1.y * private_key.omega
}

pub fn sign(message: &[u8], private_key: &PrivateKey) -> Signature {
    // Create RNG seeded from message hash for deterministic signing
    let mut hasher = Sha256::new();
    hasher.update(message);
    let hash = hasher.finalize();
    let hash_fp: Fr = Fr::from_be_bytes_mod_order(&hash[..]);
    
    let mut rng = ChaChaRng::from_seed(hash.into());

    let key_shares = derive_private_key_shares(private_key);
    
    // Generate 4 random numbers in Fp: alpha, beta, b, d_prime
    let alpha = Fr::rand(&mut rng);
    let beta = Fr::rand(&mut rng);
    let b = Fr::rand(&mut rng);
    let d_prime = Fr::rand(&mut rng);

    let epsilon = alpha * beta;
    let epsilon_shares = split(epsilon, 2, 2, &mut rng);

    let d = d_prime + private_key.omega;
    
    let sigma_1 = b * (private_key.k + hash_fp);
    let sigma_2 = d/b;
    let sigma_3 = key_shares.1.y * d_prime;
    let sigma_4 = epsilon_shares[1].y * d/epsilon;
    let sigma_5 = d * (key_shares.0.y - epsilon_shares[0].y * hash_fp/epsilon);

    // verify
    let public_key = derive_public_key(private_key);

    assert_eq!(public_key + sigma_3, key_shares.1.y * d, "Public key + sigma_3 does not equal K_1 * d");
    let v_0 = sigma_1 * sigma_2 - sigma_5;
    let v_1 = sigma_1 * sigma_2 - (public_key + sigma_3) + hash_fp * sigma_4;

    let exp_v_0 =  d * ((private_key.k + hash_fp) - (key_shares.0.y - epsilon_shares[0].y * hash_fp/epsilon));
    let exp_v_1 = d * ((private_key.k + hash_fp) - (key_shares.1.y - epsilon_shares[1].y * hash_fp/epsilon));

    assert_eq!(v_0, exp_v_0, "V_0 does not equal d * ((K + r) - (K_0 - epsilon_0 * r/epsilon))");
    assert_eq!(v_1, exp_v_1, "V_1 does not equal d * ((K + r) - (K_1 - epsilon_1 * r/epsilon))");

    let v_0_share = Share { x: Fr::from(1 as u64), y: v_0 };
    let v_1_share = Share { x: Fr::from(2 as u64), y: v_1 };
    let result = reconstruct(&[v_0_share, v_1_share]);

    println!("Result: {}", result);

    Signature {
        sigma_1,
        sigma_2,
        sigma_3,
        sigma_4,
        sigma_5,
    }
}

pub fn verify(message: &[u8], signature: &Signature, public_key: &PublicKey) -> bool {
    // Create RNG seeded from message hash for deterministic signing
    let mut hasher = Sha256::new();
    hasher.update(message);
    let hash = hasher.finalize();
    let hash_fp: Fr = Fr::from_be_bytes_mod_order(&hash[..]);

    let v_0 = signature.sigma_1 * signature.sigma_2 - signature.sigma_5;
    let v_1 = signature.sigma_1 * signature.sigma_2 - (*public_key + signature.sigma_3) + hash_fp * signature.sigma_4;

    let v_0_share = Share { x: Fr::from(1 as u64), y: v_0 };
    let v_1_share = Share { x: Fr::from(2 as u64), y: v_1 };

    reconstruct(&[v_0_share, v_1_share]) == Fr::ZERO
}
