use ark_bn254::Fr;
use ark_ff::{Field, UniformRand};
use rand::RngCore;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Share {
    pub x: Fr,
    pub y: Fr,
}

pub fn split(secret: Fr, threshold: usize, num_shares: usize, rng: &mut dyn RngCore) -> Vec<Share> {
    if threshold < 1 {
        panic!("Threshold must be at least 1");
    }
    if num_shares < threshold {
        panic!("Number of shares must be at least the threshold");
    }

    // Generate random coefficients for polynomial f(x) = secret + a1*x + ... + a_{k-1}*x^{k-1}
    let mut coefficients = vec![secret];
    for _ in 1..threshold {
        coefficients.push(Fr::rand(rng));
    }

    // Generate shares by evaluating polynomial at distinct x values
    let mut shares = Vec::new();
    for i in 1..=num_shares {
        let x = Fr::from(i as u64);
        let y = evaluate_polynomial(&coefficients, x);
        shares.push(Share { x, y });
    }

    shares
}

pub fn reconstruct(shares: &[Share]) -> Fr {
    if shares.is_empty() {
        panic!("Cannot reconstruct from empty shares");
    }

    // Use Lagrange interpolation to compute f(0)
    let zero = Fr::ZERO;
    let mut secret = Fr::ZERO;

    for (i, share_i) in shares.iter().enumerate() {
        let mut numerator = Fr::ONE;
        let mut denominator = Fr::ONE;

        for (j, share_j) in shares.iter().enumerate() {
            if i != j {
                numerator = numerator * (zero - share_j.x);
                denominator = denominator * (share_i.x - share_j.x);
            }
        }

        let lagrange_basis = numerator / denominator;
        secret = secret + (lagrange_basis * share_i.y);
    }

    secret
}

fn evaluate_polynomial(coefficients: &[Fr], x: Fr) -> Fr {
    // Horner's method: f(x) = a0 + x*(a1 + x*(a2 + ...))
    let mut result = Fr::ZERO;
    for &coeff in coefficients.iter().rev() {
        result = result * x + coeff;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    #[test]
    fn test_shamir_basic() {
        let mut rng = ChaChaRng::from_seed([0u8; 32]);
        let secret = Fr::from(42u64);

        let shares = split(secret, 3, 5, &mut rng);
        assert_eq!(shares.len(), 5);

        // Reconstruct with exactly threshold shares
        let reconstructed = reconstruct(&shares[0..3]);
        assert_eq!(reconstructed, secret);

        // Reconstruct with more than threshold shares
        let reconstructed = reconstruct(&shares);
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_shamir_2_of_2() {
        let mut rng = ChaChaRng::from_seed([0u8; 32]);
        let secret = Fr::from(42u64);

        let shares = split(secret, 2, 2, &mut rng);
        assert_eq!(shares.len(), 2);
        
        let reconstructed = reconstruct(&shares);
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_shamir_different_combinations() {
        let mut rng = ChaChaRng::from_seed([1u8; 32]);
        let secret = Fr::rand(&mut rng);

        let shares = split(secret, 3, 5, &mut rng);

        // Test different combinations of 3 shares
        let reconstructed1 = reconstruct(&[shares[0].clone(), shares[1].clone(), shares[2].clone()]);
        let reconstructed2 = reconstruct(&[shares[1].clone(), shares[3].clone(), shares[4].clone()]);
        let reconstructed3 = reconstruct(&[shares[0].clone(), shares[2].clone(), shares[4].clone()]);

        assert_eq!(reconstructed1, secret);
        assert_eq!(reconstructed2, secret);
        assert_eq!(reconstructed3, secret);
    }
}
