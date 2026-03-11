mod shamir;
mod signature;

use ark_ff::{BigInteger, PrimeField};
use sha2::{Digest, Sha256};
use signature::{
    compute_receipt, derive_private_key, derive_public_key, sign,
    verify_designated, verify_with_receipt, ChannelKey,
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
    println!("SILMARILS Signature Demo");
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

    println!("Private Key: {}", private_key);
    println!(
        "Private Key (hex): 0x{}",
        hex::encode(private_key.into_bigint().to_bytes_be())
    );
    println!("Public Key: (w0={}, w1={})", public_key.w0, public_key.w1);
    println!(
        "Public Key (hex): w0=0x{}, w1=0x{}",
        hex::encode(public_key.w0.into_bigint().to_bytes_be()),
        hex::encode(public_key.w1.into_bigint().to_bytes_be())
    );
    println!(
        "Signature: ( {}, {}, {}, {})",
        sig.sigma_1, sig.sigma_2, sig.sigma_3, sig.sigma_4
    );
    println!("Designated-verifier check: {}", is_valid);
    println!("Invalid for wrong message [1,2,3] (should fail): {}", is_forged);

    // Demonstrate receipt-based (transferable) verification
    let receipt = compute_receipt(message_input.as_bytes(), &channel_key);
    let receipt_valid = verify_with_receipt(&sig, &public_key, receipt);
    println!("Receipt-based third-party check: {}", receipt_valid);

}
