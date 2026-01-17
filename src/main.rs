mod signature;
mod shamir;

use ark_ff::{BigInteger, PrimeField};
use signature::{derive_private_key, derive_public_key, sign, verify};
use std::io::{self, Write};

fn main() {
    println!("Digital Signature Demo - Finite Field Random Number Generator");
    println!("=============================================================\n");

    // Ask user for seed value
    print!("Enter a seed value: ");
    io::stdout().flush().expect("Failed to flush stdout");

    let mut seed_input = String::new();
    io::stdin()
        .read_line(&mut seed_input)
        .expect("Failed to read input");

    let seed_input = seed_input.trim();
     // Ask user for message
     print!("Enter a message: ");
     io::stdout().flush().expect("Failed to flush stdout");

    let mut message_input = String::new();
    io::stdin()
        .read_line(&mut message_input)
        .expect("Failed to read input");

    let message_input = message_input.trim();

    // Derive private key from seed
    let private_key = derive_private_key(seed_input);

    // Derive public key from private key
    let public_key = derive_public_key(&private_key);

    // Sign message
    let signature = sign(message_input.as_bytes(), &private_key);

    // Verify signature
    let is_valid = verify(message_input.as_bytes(), &signature, &public_key);

    let is_forged = verify(&[1, 2, 3], &signature, &public_key);

    println!("Private Key: ({}, {})", private_key.k, private_key.omega);
    println!(
        "Private Key (hex): (0x{}, 0x{})",
        hex::encode(private_key.k.into_bigint().to_bytes_be()),
        hex::encode(private_key.omega.into_bigint().to_bytes_be())
    );
    println!("Public Key: {}", public_key);
    println!("Public Key (hex): 0x{}", hex::encode(public_key.into_bigint().to_bytes_be()));
    println!("Signature: ({}, {}, {}, {}, {})", signature.sigma_1, signature.sigma_2, signature.sigma_3, signature.sigma_4, signature.sigma_5);
    println!("Signature (hex): (0x{}, 0x{}, 0x{}, 0x{}, 0x{})", hex::encode(signature.sigma_1.into_bigint().to_bytes_be()), hex::encode(signature.sigma_2.into_bigint().to_bytes_be()), hex::encode(signature.sigma_3.into_bigint().to_bytes_be()), hex::encode(signature.sigma_4.into_bigint().to_bytes_be()), hex::encode(signature.sigma_5.into_bigint().to_bytes_be()));
    println!("Is valid: {}", is_valid);
    println!("Invalid for wrong message [1, 2, 3]: {}", is_forged);
}
