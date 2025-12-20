//! Polynomial operations for KZG verification (zkVM version)
//!
//! This module provides the same functionality as poly.rs but uses
//! the `bls12_381` crate instead of `blst`, allowing it to run inside
//! RISC Zero's zkVM with accelerated BLS12-381 operations.

extern crate alloc;
use alloc::vec::Vec;

use bls12_381::{G1Affine, G1Projective, Scalar};
use ff::PrimeField;

/// Domain size for Avail (must be power of 2)
pub const DOMAIN_SIZE: usize = 256;

/// Number of SRS points embedded
pub const SRS_POINT_COUNT: usize = 256;

/// Size of compressed G1 point
pub const G1_COMPRESSED_SIZE: usize = 48;

/// 256th root of unity for BLS12-381 scalar field
///
/// Computed as: omega_256 = 7^((r-1)/256) mod r
/// This is ROOT_OF_UNITY^(2^24) where ROOT_OF_UNITY is the 2^32 root.
///
/// Value: 0x4f9b4098e2e9f12e6b368121ac0cf4ad0a0865a899e8deff4935bd2f817f694b
fn get_omega() -> Scalar {
    // The bls12_381 crate's ROOT_OF_UNITY is a 2^32 root of unity
    // We need the 256th root, which is ROOT_OF_UNITY^(2^24)
    let root_of_unity = Scalar::ROOT_OF_UNITY;

    // Compute ROOT_OF_UNITY^(2^24) by repeated squaring 24 times
    let mut omega = root_of_unity;
    for _ in 0..24 {
        omega = omega.square();
    }
    omega
}

/// Get the inverse of omega for iFFT
fn get_omega_inv() -> Scalar {
    get_omega().invert().unwrap()
}

/// Convert 32-byte cell data to scalar field element
fn bytes_to_scalar(bytes: &[u8; 32]) -> Scalar {
    // bls12_381 uses little-endian, Avail uses big-endian
    let mut le_bytes = *bytes;
    le_bytes.reverse();

    // from_bytes returns CtOption, unwrap since we trust Avail data format
    Scalar::from_bytes(&le_bytes).unwrap_or(Scalar::zero())
}

/// Inverse FFT to recover polynomial coefficients from evaluations
///
/// Given evaluations [p(1), p(omega), p(omega^2), ..., p(omega^(n-1))],
/// compute coefficients [a_0, a_1, ..., a_(n-1)] where p(x) = sum(a_i * x^i)
fn ifft(evaluations: &[Scalar]) -> Vec<Scalar> {
    let n = evaluations.len();
    assert!(n.is_power_of_two(), "Domain size must be power of 2");

    if n == 1 {
        return evaluations.to_vec();
    }

    // Standard Cooley-Tukey iFFT
    let mut coeffs: Vec<Scalar> = evaluations.to_vec();

    // Bit-reversal permutation
    let mut j = 0usize;
    for i in 1..n {
        let mut bit = n >> 1;
        while j & bit != 0 {
            j ^= bit;
            bit >>= 1;
        }
        j ^= bit;
        if i < j {
            coeffs.swap(i, j);
        }
    }

    // Inverse butterfly operations
    let omega_inv = get_omega_inv();

    let mut len = 2;
    while len <= n {
        // Compute omega_inv^(n/len) for this stage
        let step = n / len;
        let mut omega_step = Scalar::one();
        let mut temp = omega_inv;
        for _ in 1..step {
            omega_step = omega_step * temp;
            temp = temp * omega_inv;
        }
        // Actually we want omega_inv^step
        omega_step = omega_inv;
        for _ in 1..(step) {
            omega_step = omega_step * omega_inv;
        }

        for start in (0..n).step_by(len) {
            let mut w = Scalar::one();

            for k in 0..(len / 2) {
                let t = w * coeffs[start + k + len / 2];
                let u = coeffs[start + k];

                coeffs[start + k] = u + t;
                coeffs[start + k + len / 2] = u - t;

                w = w * omega_step;
            }
        }

        len *= 2;
    }

    // Divide by n
    let n_inv = Scalar::from(n as u64).invert().unwrap();
    for coeff in &mut coeffs {
        *coeff = *coeff * n_inv;
    }

    coeffs
}

/// Embedded SRS G1 points from Avail's trusted setup
/// First 256 compressed G1 points from Filecoin's Powers of Tau (challenge_19)
#[rustfmt::skip]
static SRS_G1_POINTS: [u8; SRS_POINT_COUNT * G1_COMPRESSED_SIZE] = *include_bytes!("srs_g1_points.bin");

/// Load SRS point at index i
fn get_srs_point(index: usize) -> Option<G1Affine> {
    if index >= SRS_POINT_COUNT {
        return None;
    }

    let offset = index * G1_COMPRESSED_SIZE;
    let point_bytes: [u8; 48] = SRS_G1_POINTS[offset..offset + G1_COMPRESSED_SIZE]
        .try_into()
        .ok()?;

    G1Affine::from_compressed(&point_bytes).into()
}

/// Compute MSM: sum(scalars[i] * srs_points[i])
fn msm(scalars: &[Scalar]) -> G1Projective {
    let mut acc = G1Projective::identity();

    for (i, scalar) in scalars.iter().enumerate() {
        let Some(point) = get_srs_point(i) else {
            break;
        };

        // scalar * point (G1Affine implements Mul<Scalar>)
        let product = G1Projective::from(point) * scalar;
        acc = acc + product;
    }

    acc
}

/// Verify a row's data against its commitment from the header
///
/// Algorithm (matches Avail's kate-recovery):
/// 1. Convert cell data to field elements
/// 2. iFFT to get polynomial coefficients
/// 3. Compute commitment via MSM with SRS
/// 4. Compare to expected commitment
pub fn verify_row(
    cells: &[[u8; 32]],
    expected_commitment: &[u8; 48],
) -> bool {
    // Convert cells to field elements
    let evaluations: Vec<Scalar> = cells.iter()
        .map(|cell| {
            let mut data = *cell;
            // Avail uses big-endian, first 31 bytes are data
            data[31] = 0; // Clear padding byte
            bytes_to_scalar(&data)
        })
        .collect();

    // iFFT to get coefficients
    let coefficients = ifft(&evaluations);

    // Compute commitment via MSM
    let commitment = msm(&coefficients);

    // Compress the result
    let computed: [u8; 48] = G1Affine::from(commitment).to_compressed();

    // Compare
    computed == *expected_commitment
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_omega_properties() {
        let omega = get_omega();

        // omega^256 should equal 1
        let mut power = omega;
        for _ in 1..256 {
            power = power * omega;
        }
        assert_eq!(power, Scalar::one(), "omega^256 should equal 1");

        // omega^128 should not equal 1 (primitivity)
        let mut half_power = omega;
        for _ in 1..128 {
            half_power = half_power * omega;
        }
        assert_ne!(half_power, Scalar::one(), "omega^128 should not equal 1");
    }

    #[test]
    fn test_ifft_single() {
        let one = Scalar::one();
        let result = ifft(&[one]);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_ifft_basic() {
        let one = Scalar::one();
        let evaluations = vec![one, one, one, one];
        let coeffs = ifft(&evaluations);
        assert_eq!(coeffs.len(), 4);
    }
}
