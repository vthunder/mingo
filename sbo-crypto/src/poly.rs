//! Polynomial operations for KZG verification
//!
//! Provides iFFT for polynomial reconstruction and MSM for commitment computation.
//! Uses BLS12-381 curve (accelerated in RISC Zero zkVM).

#![cfg(feature = "kzg")]

extern crate alloc;
use alloc::vec::Vec;

use blst::{
    blst_fr, blst_scalar,
    blst_fr_from_uint64, blst_fr_mul, blst_fr_add, blst_fr_sub, blst_fr_inverse,
};

/// BLS12-381 scalar field modulus (for reference)
/// p = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
pub const SCALAR_MODULUS: [u64; 4] = [
    0xffffffff00000001,
    0x53bda402fffe5bfe,
    0x3339d80809a1d805,
    0x73eda753299d7d48,
];

/// Domain size for Avail (must be power of 2)
pub const DOMAIN_SIZE: usize = 256;

/// Primitive root of unity for domain size 256
/// omega^256 = 1 in the scalar field
/// This is: 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000
/// TODO: Compute correct root for BLS12-381 scalar field
pub fn get_omega() -> blst_fr {
    // For now, use a placeholder
    // Real implementation needs the 256th root of unity in BLS12-381 scalar field
    let mut omega = blst_fr::default();
    unsafe {
        blst_fr_from_uint64(&mut omega, [7, 0, 0, 0].as_ptr());
    }
    omega
}

/// Compute powers of omega: [1, omega, omega^2, ..., omega^(n-1)]
pub fn compute_domain(n: usize) -> Vec<blst_fr> {
    let omega = get_omega();
    let mut domain = Vec::with_capacity(n);

    let mut current = blst_fr::default();
    unsafe {
        blst_fr_from_uint64(&mut current, [1, 0, 0, 0].as_ptr());
    }

    for _ in 0..n {
        domain.push(current);
        unsafe {
            blst_fr_mul(&mut current, &current, &omega);
        }
    }

    domain
}

/// Convert 32-byte cell data to scalar field element
pub fn bytes_to_fr(bytes: &[u8; 32]) -> blst_fr {
    let mut fr = blst_fr::default();
    let mut scalar = blst_scalar::default();

    // Copy bytes (big-endian) to scalar
    scalar.b.copy_from_slice(bytes);

    unsafe {
        blst::blst_fr_from_scalar(&mut fr, &scalar);
    }

    fr
}

/// Inverse FFT to recover polynomial coefficients from evaluations
///
/// Given evaluations [p(1), p(omega), p(omega^2), ..., p(omega^(n-1))],
/// compute coefficients [a_0, a_1, ..., a_(n-1)] where p(x) = sum(a_i * x^i)
pub fn ifft(evaluations: &[blst_fr]) -> Vec<blst_fr> {
    let n = evaluations.len();
    assert!(n.is_power_of_two(), "Domain size must be power of 2");

    if n == 1 {
        return evaluations.to_vec();
    }

    // Standard Cooley-Tukey iFFT
    let mut coeffs: Vec<blst_fr> = evaluations.to_vec();

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
    let omega_inv = {
        let omega = get_omega();
        let mut inv = blst_fr::default();
        unsafe {
            blst_fr_inverse(&mut inv, &omega);
        }
        inv
    };

    let mut len = 2;
    while len <= n {
        // omega_inv^(n/len) for this stage
        let mut w_len = blst_fr::default();
        unsafe {
            blst_fr_from_uint64(&mut w_len, [1, 0, 0, 0].as_ptr());
        }

        let step = n / len;
        let mut omega_power = omega_inv;
        for _ in 1..step {
            unsafe {
                blst_fr_mul(&mut omega_power, &omega_power, &omega_inv);
            }
        }
        // omega_power = omega_inv^step

        for start in (0..n).step_by(len) {
            let mut w = blst_fr::default();
            unsafe {
                blst_fr_from_uint64(&mut w, [1, 0, 0, 0].as_ptr());
            }

            for k in 0..(len / 2) {
                let t = {
                    let mut t = blst_fr::default();
                    unsafe {
                        blst_fr_mul(&mut t, &w, &coeffs[start + k + len / 2]);
                    }
                    t
                };

                let u = coeffs[start + k];

                unsafe {
                    blst_fr_add(&mut coeffs[start + k], &u, &t);
                    blst_fr_sub(&mut coeffs[start + k + len / 2], &u, &t);
                }

                unsafe {
                    blst_fr_mul(&mut w, &w, &omega_power);
                }
            }
        }

        len *= 2;
    }

    // Divide by n
    let mut n_inv = blst_fr::default();
    unsafe {
        blst_fr_from_uint64(&mut n_inv, [n as u64, 0, 0, 0].as_ptr());
        blst_fr_inverse(&mut n_inv, &n_inv);
    }

    for coeff in &mut coeffs {
        unsafe {
            blst_fr_mul(coeff, coeff, &n_inv);
        }
    }

    coeffs
}

/// Compute KZG commitment using SRS: C = sum(a_i * SRS[i])
///
/// For row verification, we compute this from the polynomial coefficients
/// and compare against the row commitment from the header.
///
/// This uses the SRS (Structured Reference String) from Avail's trusted setup
/// via the srs module's multi-scalar multiplication function.
pub fn compute_commitment(coefficients: &[blst_fr]) -> [u8; 48] {
    crate::srs::msm(coefficients)
}

/// Verify a row's data against its commitment from the header
///
/// 1. Convert cell data to field elements
/// 2. iFFT to get polynomial coefficients
/// 3. Compute commitment via MSM
/// 4. Compare to expected commitment
pub fn verify_row(
    cells: &[[u8; 32]],
    expected_commitment: &[u8; 48],
) -> bool {
    // Convert cells to field elements (first 31 bytes, last byte is padding)
    let evaluations: Vec<blst_fr> = cells.iter()
        .map(|cell| {
            let mut data = [0u8; 32];
            data.copy_from_slice(cell);
            // Avail uses big-endian, first 31 bytes are data
            data[31] = 0; // Clear padding byte
            bytes_to_fr(&data)
        })
        .collect();

    // iFFT to get coefficients
    let coefficients = ifft(&evaluations);

    // Compute commitment
    let computed = compute_commitment(&coefficients);

    // Compare
    computed == *expected_commitment
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_to_fr() {
        let mut bytes = [0u8; 32];
        bytes[31] = 1; // Value 1 in big-endian
        let fr = bytes_to_fr(&bytes);
        // Verify that conversion happens (exact value depends on blst internals)
        // Just check that it's not all zeros
        let is_nonzero = fr.l.iter().any(|&x| x != 0);
        assert!(is_nonzero, "Field element should be non-zero for input with byte 1");
    }

    #[test]
    fn test_ifft_single() {
        let one = {
            let mut fr = blst_fr::default();
            unsafe {
                blst_fr_from_uint64(&mut fr, [1, 0, 0, 0].as_ptr());
            }
            fr
        };

        let result = ifft(&[one]);
        assert_eq!(result.len(), 1);
    }
}
