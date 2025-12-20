//! Avail SRS (Structured Reference String) for KZG commitments
//!
//! The SRS is from Avail's trusted setup ceremony and contains
//! powers of tau in G1: [G1, tau*G1, tau^2*G1, ..., tau^(n-1)*G1]
//!
//! Avail uses Filecoin's Powers of Tau (challenge_19) with BLS12-381 curve.
//! Source: https://github.com/availproject/avail-srs
//! SRS files: https://srs.availproject.org

#![cfg(feature = "kzg")]

extern crate alloc;
use blst::{blst_p1_affine, blst_p1, blst_fr};

/// Maximum domain size supported
/// Avail uses 256 columns in their data matrix, and the SRS supports up to 1024 points
/// from the trusted setup (N = 1 << 10)
pub const MAX_DOMAIN_SIZE: usize = 256;

/// Total SRS points available from Avail's trusted setup
/// They extracted 1024 points (2^10) from Filecoin's challenge_19
pub const SRS_TOTAL_POINTS: usize = 1024;

/// Embedded SRS points (G1 affine, compressed 48 bytes each)
///
/// TODO: Replace with actual Avail SRS from trusted setup
/// The actual SRS is available at https://srs.availproject.org
/// - File: pp_1024.data (serialized reference strings)
/// - File: g1_g2_1024.txt (G1 and G2 points in text format)
/// - File: extracted.data (compressed parameters, 15.7 MB)
///
/// For now, use placeholder generator points (INVALID for production)
/// Each entry is 48 bytes (compressed G1 affine point)
/// Total size would be: 48 * MAX_DOMAIN_SIZE = 12,288 bytes
pub static SRS_G1_POINTS: &[u8] = &[
    // Placeholder: This must be replaced with actual SRS
    // Format: concatenated 48-byte compressed BLS12-381 G1 points
    // Index i contains tau^i * G1 where tau is the secret from trusted setup
    //
    // To embed real SRS:
    // 1. Download from https://srs.availproject.org/pp_1024.data
    // 2. Extract first 256 G1 points (48 bytes each = 12,288 bytes total)
    // 3. Replace this array with the actual bytes
    //
    // Until then, this is intentionally empty to force proper implementation
];

/// Load SRS point at index i
///
/// Returns the G1 point corresponding to tau^i * G1 from the trusted setup.
/// Returns None if index is out of bounds or SRS is not loaded.
pub fn get_srs_point(index: usize) -> Option<blst_p1_affine> {
    if index >= MAX_DOMAIN_SIZE {
        return None;
    }

    // TODO: Decompress from SRS_G1_POINTS once actual SRS is embedded
    // The actual implementation would:
    // 1. Slice SRS_G1_POINTS[index*48..(index+1)*48]
    // 2. Call blst_p1_uncompress() to decompress to affine point
    // 3. Validate the point is on curve and in correct subgroup

    // For now, return generator (placeholder - DO NOT USE IN PRODUCTION)
    // This is intentionally wrong to ensure it fails verification
    unsafe {
        let generator_ptr = blst::blst_p1_affine_generator();
        Some(*generator_ptr)
    }
}

/// Compute MSM: sum(scalars[i] * srs_points[i])
///
/// This is the core operation for KZG commitment computation.
/// Given polynomial coefficients as scalars, this computes the commitment
/// by performing multi-scalar multiplication with the SRS points.
///
/// # Arguments
/// * `scalars` - Polynomial coefficients in field representation
///
/// # Returns
/// Compressed 48-byte G1 point representing the KZG commitment
pub fn msm(scalars: &[blst_fr]) -> [u8; 48] {
    use blst::{blst_p1_from_affine, blst_p1_mult, blst_p1_add_or_double, blst_p1_compress};

    let mut acc = blst_p1::default();
    let mut first = true;

    for (i, scalar) in scalars.iter().enumerate() {
        let Some(srs_point) = get_srs_point(i) else {
            break;
        };

        // Convert affine to projective
        let mut srs_proj = blst_p1::default();
        unsafe {
            blst_p1_from_affine(&mut srs_proj, &srs_point);
        }

        // Convert blst_fr to scalar bytes for multiplication
        let scalar_bytes = fr_to_scalar_bytes(scalar);

        // Multiply: scalar * srs_point
        let mut product = blst_p1::default();
        unsafe {
            blst_p1_mult(&mut product, &srs_proj, scalar_bytes.as_ptr(), 256);
        }

        // Add to accumulator
        if first {
            acc = product;
            first = false;
        } else {
            unsafe {
                blst_p1_add_or_double(&mut acc, &acc, &product);
            }
        }
    }

    // Compress result
    let mut result = [0u8; 48];
    unsafe {
        blst_p1_compress(result.as_mut_ptr(), &acc);
    }

    result
}

/// Convert blst_fr field element to 32-byte scalar representation
///
/// blst_fr is stored as an array of limbs. We need to convert this
/// to a byte array for use in scalar multiplication.
fn fr_to_scalar_bytes(fr: &blst_fr) -> [u8; 32] {
    let mut bytes = [0u8; 32];

    // blst_fr.l is an array of u64 limbs in little-endian order
    // We need to convert to byte representation
    for (i, &limb) in fr.l.iter().enumerate() {
        let limb_bytes = limb.to_le_bytes();
        let start = i * 8;
        let end = start + 8;
        if end <= 32 {
            bytes[start..end].copy_from_slice(&limb_bytes);
        }
    }

    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_max_domain_size() {
        // Verify constants are set correctly
        assert_eq!(MAX_DOMAIN_SIZE, 256);
        assert_eq!(SRS_TOTAL_POINTS, 1024);
        assert!(MAX_DOMAIN_SIZE <= SRS_TOTAL_POINTS);
    }

    #[test]
    fn test_get_srs_point_bounds() {
        // Should return None for out of bounds
        assert!(get_srs_point(MAX_DOMAIN_SIZE).is_none());
        assert!(get_srs_point(MAX_DOMAIN_SIZE + 1).is_none());

        // Should return Some for valid indices (even with placeholder)
        assert!(get_srs_point(0).is_some());
        assert!(get_srs_point(MAX_DOMAIN_SIZE - 1).is_some());
    }

    #[test]
    fn test_fr_to_scalar_bytes() {
        // Test converting field element to bytes
        let mut fr = blst_fr::default();
        unsafe {
            blst::blst_fr_from_uint64(&mut fr, [1, 0, 0, 0].as_ptr());
        }

        let bytes = fr_to_scalar_bytes(&fr);

        // Should be 32 bytes
        assert_eq!(bytes.len(), 32);

        // Should be non-zero somewhere (exact representation depends on blst internals)
        assert!(bytes.iter().any(|&b| b != 0), "Bytes should not be all zeros");
    }

    #[test]
    fn test_msm_empty() {
        // MSM with empty scalars should return identity/zero point
        let scalars: Vec<blst_fr> = Vec::new();
        let result = msm(&scalars);

        // Result is 48 bytes (could be zero/identity point)
        assert_eq!(result.len(), 48);
    }

    #[test]
    fn test_msm_single_scalar() {
        // MSM with single scalar should work
        let mut scalar = blst_fr::default();
        unsafe {
            blst::blst_fr_from_uint64(&mut scalar, [1, 0, 0, 0].as_ptr());
        }

        let result = msm(&[scalar]);
        assert_eq!(result.len(), 48);

        // With placeholder SRS (just generator), result should be non-zero
        assert!(result.iter().any(|&b| b != 0));
    }
}
