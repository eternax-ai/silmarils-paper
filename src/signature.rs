use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, PrimeField, UniformRand};
use rand::SeedableRng;
use rand::rngs::OsRng;
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
    // Hash message for r (QROM security)
    let mut hasher = Sha256::new();
    hasher.update(message);
    let hash = hasher.finalize();
    let hash_fp: Fr = Fr::from_be_bytes_mod_order(&hash[..]);
    
    let mut rng = OsRng;

    let key_shares = derive_private_key_shares(private_key);
    
    // Generate 4 random numbers in Fp: alpha, beta, b, d_prime
    let alpha = Fr::rand(&mut rng);
    let beta = Fr::rand(&mut rng);
    let b = Fr::rand(&mut rng);
    let d_prime = Fr::rand(&mut rng);

    let epsilon = alpha * beta;
    let mut rng_epsilon = OsRng;
    let epsilon_shares = split(epsilon, 2, 2, &mut rng_epsilon);

    let d = d_prime + private_key.omega;
    
    let sigma_1 = b * (private_key.k - hash_fp);
    let sigma_2 = d/b;
    let sigma_3 = key_shares.1.y * d_prime;
    let sigma_4 = epsilon_shares[1].y * d/epsilon;
    let sigma_5 = d * (key_shares.0.y - epsilon_shares[0].y * hash_fp/epsilon);

    // verify
    let public_key = derive_public_key(private_key);

    assert_eq!(public_key + sigma_3, key_shares.1.y * d, "Public key + sigma_3 does not equal K_1 * d");
    let v_0 = sigma_1 * sigma_2 - sigma_5;
    let v_1 = sigma_1 * sigma_2 - (public_key + sigma_3) + hash_fp * sigma_4;

    let exp_v_0 =  d * ((private_key.k - hash_fp) - (key_shares.0.y - epsilon_shares[0].y * hash_fp/epsilon));
    let exp_v_1 = d * ((private_key.k - hash_fp) - (key_shares.1.y - epsilon_shares[1].y * hash_fp/epsilon));

    assert_eq!(v_0, exp_v_0, "V_0 does not equal d * ((K - r) - (K_0 - epsilon_0 * r/epsilon))");
    assert_eq!(v_1, exp_v_1, "V_1 does not equal d * ((K - r) - (K_1 - epsilon_1 * r/epsilon))");

    let v_0_share = Share { x: Fr::from(1 as u64), y: v_0 };
    let v_1_share = Share { x: Fr::from(2 as u64), y: v_1 };
    let result = reconstruct(&[v_0_share, v_1_share]);

    assert_eq!(result, Fr::ZERO, "Verification check does not equal 0");

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_private_key_deterministic() {
        let seed = "test-seed-123";
        let key1 = derive_private_key(seed);
        let key2 = derive_private_key(seed);
        
        assert_eq!(key1.k, key2.k, "Private key k should be deterministic");
        assert_eq!(key1.omega, key2.omega, "Private key omega should be deterministic");
    }

    #[test]
    fn test_derive_private_key_different_seeds() {
        let key1 = derive_private_key("seed1");
        let key2 = derive_private_key("seed2");
        
        assert_ne!(key1.k, key2.k, "Different seeds should produce different k");
        assert_ne!(key1.omega, key2.omega, "Different seeds should produce different omega");
    }

    #[test]
    fn test_derive_private_key_hex_seed() {
        let hex_seed = "0x1234567890abcdef";
        let key = derive_private_key(hex_seed);
        
        // Should not panic and produce valid keys
        assert_ne!(key.k, Fr::ZERO);
        assert_ne!(key.omega, Fr::ZERO);
    }

    #[test]
    fn test_derive_public_key_deterministic() {
        let private_key = derive_private_key("test-seed");
        let public_key1 = derive_public_key(&private_key);
        let public_key2 = derive_public_key(&private_key);
        
        assert_eq!(public_key1, public_key2, "Public key should be deterministic");
    }

    #[test]
    fn test_derive_public_key_different_private_keys() {
        let key1 = derive_private_key("seed1");
        let key2 = derive_private_key("seed2");
        
        let pub1 = derive_public_key(&key1);
        let pub2 = derive_public_key(&key2);
        
        assert_ne!(pub1, pub2, "Different private keys should produce different public keys");
    }

    #[test]
    fn test_sign_deterministic() {
        let private_key = derive_private_key("test-seed");
        let message = b"test message";
        
        let sig1 = sign(message, &private_key);
        let sig2 = sign(message, &private_key);
        
        assert_eq!(sig1.sigma_1, sig2.sigma_1, "Signatures should be deterministic");
        assert_eq!(sig1.sigma_2, sig2.sigma_2);
        assert_eq!(sig1.sigma_3, sig2.sigma_3);
        assert_eq!(sig1.sigma_4, sig2.sigma_4);
        assert_eq!(sig1.sigma_5, sig2.sigma_5);
    }

    #[test]
    fn test_sign_different_messages() {
        let private_key = derive_private_key("test-seed");
        let message1 = b"message 1";
        let message2 = b"message 2";
        
        let sig1 = sign(message1, &private_key);
        let sig2 = sign(message2, &private_key);
        
        assert_ne!(sig1.sigma_1, sig2.sigma_1, "Different messages should produce different signatures");
    }

    #[test]
    fn test_sign_different_keys() {
        let key1 = derive_private_key("seed1");
        let key2 = derive_private_key("seed2");
        let message = b"same message";
        
        let sig1 = sign(message, &key1);
        let sig2 = sign(message, &key2);
        
        assert_ne!(sig1.sigma_1, sig2.sigma_1, "Different keys should produce different signatures");
    }

    #[test]
    fn test_verify_valid_signature() {
        let private_key = derive_private_key("test-seed");
        let public_key = derive_public_key(&private_key);
        let message = b"test message";
        
        let signature = sign(message, &private_key);
        let is_valid = verify(message, &signature, &public_key);
        
        assert!(is_valid, "Valid signature should verify correctly");
    }

    #[test]
    fn test_verify_wrong_message() {
        let private_key = derive_private_key("test-seed");
        let public_key = derive_public_key(&private_key);
        let message = b"original message";
        let wrong_message = b"wrong message";
        
        let signature = sign(message, &private_key);
        let is_valid = verify(wrong_message, &signature, &public_key);
        
        assert!(!is_valid, "Signature for wrong message should be rejected");
    }

    #[test]
    fn test_verify_wrong_public_key() {
        let private_key1 = derive_private_key("seed1");
        let private_key2 = derive_private_key("seed2");
        let _public_key1 = derive_public_key(&private_key1);
        let public_key2 = derive_public_key(&private_key2);
        let message = b"test message";
        
        let signature = sign(message, &private_key1);
        let is_valid = verify(message, &signature, &public_key2);
        
        assert!(!is_valid, "Signature with wrong public key should be rejected");
    }

    #[test]
    fn test_verify_tampered_signature() {
        let private_key = derive_private_key("test-seed");
        let public_key = derive_public_key(&private_key);
        let message = b"test message";
        
        let mut signature = sign(message, &private_key);
        signature.sigma_1 = signature.sigma_1 + Fr::ONE; // Tamper with signature
        
        let is_valid = verify(message, &signature, &public_key);
        
        assert!(!is_valid, "Tampered signature should be rejected");
    }

    #[test]
    fn test_verify_empty_message() {
        let private_key = derive_private_key("test-seed");
        let public_key = derive_public_key(&private_key);
        let message = b"";
        
        let signature = sign(message, &private_key);
        let is_valid = verify(message, &signature, &public_key);
        
        assert!(is_valid, "Empty message should verify correctly");
    }

    #[test]
    fn test_verify_long_message() {
        let private_key = derive_private_key("test-seed");
        let public_key = derive_public_key(&private_key);
        let message = b"This is a very long message that tests if the signature scheme works with longer messages. It should still work correctly.";
        
        let signature = sign(message, &private_key);
        let is_valid = verify(message, &signature, &public_key);
        
        assert!(is_valid, "Long message should verify correctly");
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let private_key = derive_private_key("test-seed");
        let public_key = derive_public_key(&private_key);
        let messages: Vec<&[u8]> = vec![
            b"message 1",
            b"message 2",
            b"another message",
            b"",
        ];
        
        for message in messages {
            let signature = sign(message, &private_key);
            let is_valid = verify(message, &signature, &public_key);
            assert!(is_valid, "Roundtrip sign/verify should work for message: {:?}", message);
        }
    }
}
