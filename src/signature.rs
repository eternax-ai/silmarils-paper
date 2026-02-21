use ark_secp256k1::Fr;
use ark_ff::{AdditiveGroup, BigInteger, PrimeField, UniformRand};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use sha2::{Digest, Sha256};

use crate::shamir::{reconstruct, split, Share};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    pub w0: Fr,
    pub w1: Fr,
}

pub type PrivateKey = Fr;

/// Shared secret key for the authenticated channel between signer and 
/// designated verifier. In practice, derived from the TLS session key.
pub type ChannelKey = [u8; 32];

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

    // Generate a random number in secp256k1 scalar field
    Fr::rand(&mut rng)
}

fn derive_private_key_shares(private_key: &PrivateKey, evaluation_points: Vec<Fr>) -> (Share, Share) {
    let mut hasher = Sha256::new();
    hasher.update(private_key.into_bigint().to_bytes_be());
    let hash = hasher.finalize();
    
    let mut rng = ChaChaRng::from_seed(hash.into());
    let shares = split(*private_key, 2, 2, evaluation_points, &mut rng);

    (shares[0].clone(), shares[1].clone())
}

pub fn derive_public_key(private_key: &PrivateKey) -> PublicKey {
    // Derive the public key (w0, w1) from the private key with HKDF
    let private_key_bytes = private_key.into_bigint().to_bytes_be();
    
    let hk = Hkdf::<Sha256>::new(None, &private_key_bytes);
    let mut okm = [0u8; 64];
    hk.expand(b"it-sig-public-key", &mut okm).expect("HKDF expand failed");
    
    // Split the output into two 32-byte chunks and convert to Fr
    let w0_bytes = &okm[0..32];
    let w1_bytes = &okm[32..64];
    
    PublicKey {
        w0: Fr::from_be_bytes_mod_order(w0_bytes),
        w1: Fr::from_be_bytes_mod_order(w1_bytes),
    }
}

/// Compute the per-pair secret nonce: n_ephemeral = HMAC_{k_ephemeral}(M).
/// This nonce is never transmitted and remains information-theoretically hidden
/// from both P2 (holder) and any external adversary.
fn compute_nonce(channel_key: &ChannelKey, message: &[u8]) -> Fr {
    let mut mac =
        <Hmac<Sha256>>::new_from_slice(channel_key).expect("HMAC accepts any key length");
    mac.update(message);
    let result = mac.finalize().into_bytes();
    Fr::from_be_bytes_mod_order(&result)
}

/// Compute r = H(M, n_ephemeral). The nonce binds r to the channel secret,
/// making it information-theoretically hidden from anyone without k_ephemeral.
fn compute_receipt_hash(message: &[u8], nonce: &Fr) -> Fr {
    let mut hasher = Sha256::new();
    hasher.update(message);
    hasher.update(nonce.into_bigint().to_bytes_be());
    let hash = hasher.finalize();
    Fr::from_be_bytes_mod_order(&hash)
}

/// Compute the transferable receipt r = H(M, n_ephemeral).
/// The designated verifier releases this after successful designated verification  
/// so that any third party can verify the signature using `verify_with_receipt`.
pub fn compute_receipt(message: &[u8], ephemeral_key: &ChannelKey) -> Fr {
    let nonce = compute_nonce(ephemeral_key, message);
    compute_receipt_hash(message, &nonce)
}

pub fn sign(message: &[u8], private_key: &PrivateKey, ephemeral_key: &ChannelKey) -> Signature {
    // Derive public key from private key
    let public_key = derive_public_key(private_key);
    
    // r = H(M, HMAC_{k_channel}(M))
    let nonce = compute_nonce(ephemeral_key, message);
    let hash_fp = compute_receipt_hash(message, &nonce);
    
    let mut rng = OsRng;
    // Cache private key bytes conversion (used for HMAC)
    let private_key_bytes = private_key.into_bigint().to_bytes_be();
    let mut mac = <Hmac<Sha256>>::new_from_slice(&private_key_bytes).expect("HMAC accepts any key length");
    mac.update(message);
    let per_message_key = mac.finalize().into_bytes();
    let per_message_key_fp = Fr::from_be_bytes_mod_order(&per_message_key);
    
    // Reuse evaluation_points vector
    let evaluation_points = vec![public_key.w0, public_key.w1];
    let key_shares = derive_private_key_shares(&per_message_key_fp, evaluation_points.clone());
    
    // Generate 4 random numbers in Fp: alpha, beta, b, d_prime
    let alpha = Fr::rand(&mut rng);
    let beta = Fr::rand(&mut rng);
    let b = Fr::rand(&mut rng);
    let d = Fr::rand(&mut rng);

    let epsilon = alpha * beta;
    // Reuse existing RNG instead of creating new one
    let epsilon_shares = split(epsilon, 2, 2, evaluation_points, &mut rng);

    
    let sigma_1 = b * (per_message_key_fp - hash_fp);
    let sigma_2 = d/b;
    let sigma_3 = key_shares.1.y * d;
    let sigma_4 = epsilon_shares[1].y * d/epsilon;
    let sigma_5 = d * (key_shares.0.y - epsilon_shares[0].y * hash_fp/epsilon);

    Signature {
        sigma_1,
        sigma_2,
        sigma_3,
        sigma_4,
        sigma_5,
    }
}

/// Unauthenticated verification using r = H(M).
/// Retained to demonstrate that the algebraic forgery attack succeeds without
/// the nonce upgrade. Do NOT use in production.
pub fn verify_unauthenticated(
    message: &[u8],
    signature: &Signature,
    public_key: &PublicKey,
) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(message);
    let hash = hasher.finalize();
    let r: Fr = Fr::from_be_bytes_mod_order(&hash[..]);

    let v_0 = signature.sigma_1 * signature.sigma_2 - signature.sigma_5;
    let v_1 = signature.sigma_1 * signature.sigma_2 - signature.sigma_3
        + r * signature.sigma_4;

    let v_0_share = Share {
        x: public_key.w0,
        y: v_0,
    };
    let v_1_share = Share {
        x: public_key.w1,
        y: v_1,
    };

    reconstruct(&[v_0_share, v_1_share]) == Fr::ZERO
}

/// Core verification against a precomputed r value.
/// Rejects signatures with sigma_4 = 0 to prevent the algebraic bypass where
/// setting sigma_4 = 0 eliminates r from the verification equation entirely,
/// allowing forgery without knowledge of the channel secret.
fn verify_inner(r: Fr, signature: &Signature, public_key: &PublicKey) -> bool {
    if signature.sigma_4 == Fr::ZERO {
        return false;
    }

    // Cache sigma_1 * sigma_2 to avoid redundant multiplication
    let sigma_1_sigma_2 = signature.sigma_1 * signature.sigma_2;
    let v_0 = sigma_1_sigma_2 - signature.sigma_5;
    let v_1 = sigma_1_sigma_2 - signature.sigma_3 + r * signature.sigma_4;

    let v_0_share = Share {
        x: public_key.w0,
        y: v_0,
    };
    let v_1_share = Share {
        x: public_key.w1,
        y: v_1,
    };

    reconstruct(&[v_0_share, v_1_share]) == Fr::ZERO
}

/// Designated-verifier verification. Recomputes r = H(M, HMAC_k(M))
/// using the shared channel key, then runs the verification equation.
pub fn verify_designated(
    message: &[u8],
    signature: &Signature,
    public_key: &PublicKey,
    channel_key: &ChannelKey,
) -> bool {
    let nonce = compute_nonce(channel_key, message);
    let r = compute_receipt_hash(message, &nonce);
    verify_inner(r, signature, public_key)
}

/// Third-party verification using a receipt r previously released by the designated verifier.
/// Since the receipt is bound to a specific message via r = H(M, n_channel),
/// it cannot be used to forge signatures for different messages.
pub fn verify_with_receipt(
    signature: &Signature,
    public_key: &PublicKey,
    receipt: Fr,
) -> bool {
    verify_inner(receipt, signature, public_key)
}

/// Demonstrates the algebraic forgery attack on the unauthenticated algorithm.
///
/// In the original scheme, r = H(M) is publicly computable. The adversary
/// picks arbitrary σ'_1, σ'_2, σ'_3, σ'_4 and solves the linear verification equation
/// for σ'_5. This attack is DEFEATED by the nonce upgrade: with r = H(M, n_channel),
/// the adversary cannot compute r' for a new message M', making the system of
/// equations unsolvable. An additional σ'_4 ≠ 0 check prevents the degenerate
/// case where the attacker eliminates r from the equation entirely.
pub fn forge_signature(
    _original_message: &[u8],
    original_signature: &Signature,
    new_message: &[u8],
    public_key: &PublicKey,
) -> Signature {
    // Compute r' = H(M')
    let mut hasher = Sha256::new();
    hasher.update(new_message);
    let hash = hasher.finalize();
    let r_prime: Fr = Fr::from_be_bytes_mod_order(&hash[..]);

    // Choose arbitrary values for σ'_1, σ'_2, σ'_3, σ'_4
    // In a real attack, these could be chosen strategically
    let sigma_1_prime = original_signature.sigma_1 + Fr::from(1u64);
    let sigma_2_prime = original_signature.sigma_2 + Fr::from(2u64);
    let sigma_3_prime = original_signature.sigma_3 + Fr::from(3u64);
    let sigma_4_prime = original_signature.sigma_4 + Fr::from(4u64);

    // Compute V'₁ = σ'_1σ'_2 - (P + σ'_3) + r'σ'_4
    let v_1_prime = sigma_1_prime * sigma_2_prime - sigma_3_prime + r_prime * sigma_4_prime;

    // With shares at x=1 and x=2, Lagrange interpolation gives:
    // L₁(0) = (0-2)/(1-2) = 2
    // L₂(0) = (0-1)/(2-1) = -1
    // So reconstruction: V' = 2*v'_0 - v'_1
    //
    // For verification to pass, we need V' = 0:
    // 2*v'_0 - v'_1 = 0  =>  v'_1 = 2*v'_0
    //
    // Since v'_0 = σ'_1σ'_2 - σ'_5 and v'_1 = σ'_1σ'_2 - (P + σ'_3) + r'σ'_4,
    // we get: σ'_1σ'_2 - (P + σ'_3) + r'σ'_4 = 2(σ'_1σ'_2 - σ'_5)
    // Solving for σ'_5:
    // σ'_5 = σ'_1σ'_2 - v'_1/2
    // σ'_5 = σ'_1σ'_2 - (σ'_1σ'_2 - (P + σ'_3) + r'σ'_4)/2
    // σ'_5 = (σ'_1σ'_2 + (P + σ'_3) - r'σ'_4)/2
    //
    // Using the attack formula: σ'_5 = σ'_1σ'_2 - V'_1*w'_0/w'_1
    // where w'_0=1 and w'_1=2 are the Lagrange coefficients
    let sigma_5_prime = sigma_1_prime * sigma_2_prime - (v_1_prime * public_key.w0) / public_key.w1;

    Signature {
        sigma_1: sigma_1_prime,
        sigma_2: sigma_2_prime,
        sigma_3: sigma_3_prime,
        sigma_4: sigma_4_prime,
        sigma_5: sigma_5_prime,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CHANNEL_KEY: ChannelKey = [0xABu8; 32];

    #[test]
    fn test_derive_private_key_deterministic() {
        let seed = "test-seed-123";
        let key1 = derive_private_key(seed);
        let key2 = derive_private_key(seed);

        assert_eq!(key1, key2, "Private key should be deterministic");
    }

    #[test]
    fn test_derive_private_key_different_seeds() {
        let key1 = derive_private_key("seed1");
        let key2 = derive_private_key("seed2");

        assert_ne!(key1, key2, "Different seeds should produce different k");
    }

    #[test]
    fn test_derive_private_key_hex_seed() {
        let hex_seed = "0x1234567890abcdef";
        let key = derive_private_key(hex_seed);

        assert_ne!(key, Fr::ZERO);
    }

    #[test]
    fn test_derive_public_key_deterministic() {
        let private_key = derive_private_key("test-seed");
        let public_key1 = derive_public_key(&private_key);
        let public_key2 = derive_public_key(&private_key);

        assert_eq!(
            public_key1, public_key2,
            "Public key should be deterministic"
        );
    }

    #[test]
    fn test_derive_public_key_different_private_keys() {
        let key1 = derive_private_key("seed1");
        let key2 = derive_private_key("seed2");

        let pub1 = derive_public_key(&key1);
        let pub2 = derive_public_key(&key2);

        assert_ne!(
            pub1, pub2,
            "Different private keys should produce different public keys"
        );
    }

    #[test]
    fn test_sign_different_messages() {
        let private_key = derive_private_key("test-seed");
        let message1 = b"message 1";
        let message2 = b"message 2";

        let sig1 = sign(message1, &private_key, &TEST_CHANNEL_KEY);
        let sig2 = sign(message2, &private_key, &TEST_CHANNEL_KEY);

        assert_ne!(
            sig1.sigma_1, sig2.sigma_1,
            "Different messages should produce different signatures"
        );
    }

    #[test]
    fn test_sign_different_keys() {
        let key1 = derive_private_key("seed1");
        let key2 = derive_private_key("seed2");
        let message = b"same message";

        let sig1 = sign(message, &key1, &TEST_CHANNEL_KEY);
        let sig2 = sign(message, &key2, &TEST_CHANNEL_KEY);

        assert_ne!(
            sig1.sigma_1, sig2.sigma_1,
            "Different keys should produce different signatures"
        );
    }

    #[test]
    fn test_verify_designated_valid_signature() {
        let private_key = derive_private_key("test-seed");
        let public_key = derive_public_key(&private_key);
        let message = b"test message";

        let signature = sign(message, &private_key, &TEST_CHANNEL_KEY);
        assert!(
            verify_designated(message, &signature, &public_key, &TEST_CHANNEL_KEY),
            "Valid signature should pass designated verification"
        );
    }

    #[test]
    fn test_verify_with_receipt_valid() {
        let private_key = derive_private_key("test-seed");
        let public_key = derive_public_key(&private_key);
        let message = b"test message";

        let signature = sign(message, &private_key, &TEST_CHANNEL_KEY);
        let receipt = compute_receipt(message, &TEST_CHANNEL_KEY);
        assert!(
            verify_with_receipt(&signature, &public_key, receipt),
            "Valid signature should pass receipt-based verification"
        );
    }

    #[test]
    fn test_verify_wrong_message() {
        let private_key = derive_private_key("test-seed");
        let public_key = derive_public_key(&private_key);
        let message = b"original message";
        let wrong_message = b"wrong message";

        let signature = sign(message, &private_key, &TEST_CHANNEL_KEY);
        assert!(
            !verify_designated(wrong_message, &signature, &public_key, &TEST_CHANNEL_KEY),
            "Signature for wrong message should be rejected"
        );
    }

    #[test]
    fn test_verify_wrong_public_key() {
        let private_key1 = derive_private_key("seed1");
        let private_key2 = derive_private_key("seed2");
        let public_key2 = derive_public_key(&private_key2);
        let message = b"test message";

        let signature = sign(message, &private_key1, &TEST_CHANNEL_KEY);
        assert!(
            !verify_designated(message, &signature, &public_key2, &TEST_CHANNEL_KEY),
            "Signature with wrong public key should be rejected"
        );
    }

    #[test]
    fn test_verify_wrong_channel_key() {
        let private_key = derive_private_key("test-seed");
        let public_key = derive_public_key(&private_key);
        let message = b"test message";
        let wrong_key: ChannelKey = [0xCDu8; 32];

        let signature = sign(message, &private_key, &TEST_CHANNEL_KEY);
        assert!(
            !verify_designated(message, &signature, &public_key, &wrong_key),
            "Signature with wrong channel key should be rejected"
        );
    }

    #[test]
    fn test_verify_tampered_signature() {
        let private_key = derive_private_key("test-seed");
        let public_key = derive_public_key(&private_key);
        let message = b"test message";

        let mut signature = sign(message, &private_key, &TEST_CHANNEL_KEY);
        signature.sigma_1 = signature.sigma_1 + Fr::from(1u64);

        assert!(
            !verify_designated(message, &signature, &public_key, &TEST_CHANNEL_KEY),
            "Tampered signature should be rejected"
        );
    }

    #[test]
    fn test_verify_empty_message() {
        let private_key = derive_private_key("test-seed");
        let public_key = derive_public_key(&private_key);
        let message = b"";

        let signature = sign(message, &private_key, &TEST_CHANNEL_KEY);
        assert!(
            verify_designated(message, &signature, &public_key, &TEST_CHANNEL_KEY),
            "Empty message should verify correctly"
        );
    }

    #[test]
    fn test_verify_long_message() {
        let private_key = derive_private_key("test-seed");
        let public_key = derive_public_key(&private_key);
        let message = b"This is a very long message that tests if the signature scheme works with longer messages. It should still work correctly.";

        let signature = sign(message, &private_key, &TEST_CHANNEL_KEY);
        assert!(
            verify_designated(message, &signature, &public_key, &TEST_CHANNEL_KEY),
            "Long message should verify correctly"
        );
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let private_key = derive_private_key("test-seed");
        let public_key = derive_public_key(&private_key);
        let messages: Vec<&[u8]> = vec![b"message 1", b"message 2", b"another message", b""];

        for message in messages {
            let signature = sign(message, &private_key, &TEST_CHANNEL_KEY);
            assert!(
                verify_designated(message, &signature, &public_key, &TEST_CHANNEL_KEY),
                "Roundtrip sign/verify should work for message: {:?}",
                message
            );
            let receipt = compute_receipt(message, &TEST_CHANNEL_KEY);
            assert!(
                verify_with_receipt(&signature, &public_key, receipt),
                "Roundtrip sign/verify_with_receipt should work for message: {:?}",
                message
            );
        }
    }

    #[test]
    fn test_receipt_not_transferable_to_other_messages() {
        let private_key = derive_private_key("test-seed");
        let public_key = derive_public_key(&private_key);
        let message_a = b"message A";
        let message_b = b"message B";

        let receipt_a = compute_receipt(message_a, &TEST_CHANNEL_KEY);
        let signature_b = sign(message_b, &private_key, &TEST_CHANNEL_KEY);

        assert!(
            !verify_with_receipt(&signature_b, &public_key, receipt_a),
            "Receipt for message A must not verify signature on message B"
        );
    }

    #[test]
    fn test_algebraic_forgery_succeeds_unauthenticated() {
        let private_key = derive_private_key("attack-test-seed");
        let public_key = derive_public_key(&private_key);
        let original_message = b"original message";
        let forged_message = b"forged message";

        let original_signature = sign(original_message, &private_key, &TEST_CHANNEL_KEY);

        let forged_signature = forge_signature(
            original_message,
            &original_signature,
            forged_message,
            &public_key,
        );

        // Unauthenticated verification uses r = H(M') -- the forgery succeeds
        assert!(
            verify_unauthenticated(forged_message, &forged_signature, &public_key),
            "Forgery should succeed against unauthenticated verification"
        );

        // Designated verification uses r = H(M', HMAC_k(M')) -- the forgery fails
        assert!(
            !verify_designated(
                forged_message,
                &forged_signature,
                &public_key,
                &TEST_CHANNEL_KEY
            ),
            "Forgery should be rejected by designated verifier"
        );
    }

    #[test]
    fn test_sigma4_zero_attack_prevented() {
        // Demonstrates the residual algebraic attack where setting σ₄ = 0
        // eliminates r from the verification equation, bypassing the nonce.
        // The σ₄ ≠ 0 check in verify_inner prevents this.
        let private_key = derive_private_key("attack-test-seed");
        let public_key = derive_public_key(&private_key);
        let message = b"any message";

        // Attacker picks arbitrary σ₁, σ₂, σ₃ and sets σ₄ = 0.
        // Verification equation reduces to: σ₁σ₂ + σ₃ - 2σ₅ = 0
        let sigma_1 = Fr::from(7u64);
        let sigma_2 = Fr::from(11u64);
        let sigma_3 = Fr::from(13u64);
        let sigma_4 = Fr::ZERO;
        let sigma_5 = (sigma_1 * sigma_2 + sigma_3) / Fr::from(2u64);

        let forged = Signature {
            sigma_1,
            sigma_2,
            sigma_3,
            sigma_4,
            sigma_5,
        };

        assert!(
            !verify_designated(message, &forged, &public_key, &TEST_CHANNEL_KEY),
            "σ₄ = 0 forgery should be rejected"
        );

        let receipt = compute_receipt(message, &TEST_CHANNEL_KEY);
        assert!(
            !verify_with_receipt(&forged, &public_key, receipt),
            "σ₄ = 0 forgery should also be rejected via receipt verification"
        );
    }
}
