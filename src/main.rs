mod shamir;
mod signature;

use ark_ff::{BigInteger, PrimeField};
use sha2::{Digest, Sha256};
use signature::{
    compute_receipt, derive_private_key, derive_public_key, forge_signature, sign,
    verify_designated, verify_unauthenticated, verify_with_receipt, ChannelKey,
};
use std::io::{self, Write};

/// Derive a demo channel key from a seed (in production this comes from TLS).
fn demo_channel_key(seed: &str) -> ChannelKey {
    let mut hasher = Sha256::new();
    hasher.update(b"channel-key-derivation:");
    hasher.update(seed.as_bytes());
    let hash = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash);
    key
}

fn main() {
    println!("Digital Signature Demo");
    println!("=============================================================\n");

    // Ask user for seed value
    print!("Enter a seed value: ");
    io::stdout().flush().expect("Failed to flush stdout");

    let mut seed_input = String::new();
    io::stdin()
        .read_line(&mut seed_input)
        .expect("Failed to read input");
    let seed_input = seed_input.trim();

    print!("Enter a message: ");
    io::stdout().flush().expect("Failed to flush stdout");

    let mut message_input = String::new();
    io::stdin()
        .read_line(&mut message_input)
        .expect("Failed to read input");
    let message_input = message_input.trim();

    let private_key = derive_private_key(seed_input);
    let public_key = derive_public_key(&private_key);
    let channel_key = demo_channel_key(seed_input);

    let sig = sign(message_input.as_bytes(), &private_key, &channel_key);

    let is_valid = verify_designated(message_input.as_bytes(), &sig, &public_key, &channel_key);
    let is_forged = verify_designated(&[1, 2, 3], &sig, &public_key, &channel_key);

    println!("Private Key: ({}, {})", private_key.k, private_key.omega);
    println!(
        "Private Key (hex): (0x{}, 0x{})",
        hex::encode(private_key.k.into_bigint().to_bytes_be()),
        hex::encode(private_key.omega.into_bigint().to_bytes_be())
    );
    println!("Public Key: {}", public_key);
    println!(
        "Public Key (hex): 0x{}",
        hex::encode(public_key.into_bigint().to_bytes_be())
    );
    println!(
        "Signature: ({}, {}, {}, {}, {})",
        sig.sigma_1, sig.sigma_2, sig.sigma_3, sig.sigma_4, sig.sigma_5
    );
    println!("Designated-verifier check: {}", is_valid);
    println!("Invalid for wrong message [1,2,3]: {}", is_forged);

    // Demonstrate receipt-based (transferable) verification
    let receipt = compute_receipt(message_input.as_bytes(), &channel_key);
    let receipt_valid = verify_with_receipt(&sig, &public_key, receipt);
    println!("Receipt-based third-party check: {}", receipt_valid);

    println!("\n\nALGEBRAIC FORGERY ATTACK DEMONSTRATION (should fail)");
    println!("====================================================\n");
    println!("The attacker uses r' = H(M') but the verifier uses r' = H(M', HMAC_k(M')).");
    println!("The mismatch causes verification to fail.\n");

    print!("Enter a message to forge (different from original): ");
    io::stdout().flush().expect("Failed to flush stdout");

    let mut forged_message_input = String::new();
    io::stdin()
        .read_line(&mut forged_message_input)
        .expect("Failed to read input");
    let forged_message_input = forged_message_input.trim();

    if forged_message_input == message_input {
        println!("Warning: Forged message is the same as original.");
    }

    let forged_sig = forge_signature(
        message_input.as_bytes(),
        &sig,
        forged_message_input.as_bytes(),
        &public_key,
    );

    let forged_unauth = verify_unauthenticated(
        forged_message_input.as_bytes(),
        &forged_sig,
        &public_key,
    );
    let forged_designated = verify_designated(
        forged_message_input.as_bytes(),
        &forged_sig,
        &public_key,
        &channel_key,
    );

    println!("\nOriginal message: {}", message_input);
    println!("Forged message: {}", forged_message_input);
    println!(
        "\nForged signature: ({}, {}, {}, {}, {})",
        forged_sig.sigma_1,
        forged_sig.sigma_2,
        forged_sig.sigma_3,
        forged_sig.sigma_4,
        forged_sig.sigma_5
    );
    println!(
        "\nUnauthenticated verify (r = H(M)):           {}",
        forged_unauth
    );
    println!(
        "Designated verify (r = H(M, HMAC_k(M))):     {}",
        forged_designated
    );

    if forged_unauth && !forged_designated {
        println!("\nForgery SUCCEEDS against the old scheme but is DEFEATED by the nonce upgrade.");
    } else if forged_designated {
        println!("\nATTACK SUCCESSFUL -- this should not happen with the nonce upgrade.");
    } else {
        println!("\nBoth verifications rejected the forgery.");
    }
}
