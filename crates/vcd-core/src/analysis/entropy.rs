//! Shannon entropy over a bounded sample.
//!
//! Entropy is a hint, not a verdict: compressed and encrypted data both look
//! like 8 bits per byte, and so do some legitimate resources.

/// Bits of entropy per byte, in `0.0..=8.0`.
pub fn shannon(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }

    let len = bytes.len() as f64;
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let probability = *count as f64 / len;
            -probability * probability.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_uniform_samples_sit_at_the_extremes() {
        assert_eq!(shannon(&[]), 0.0);
        assert_eq!(shannon(&[0u8; 4096]), 0.0);
    }

    #[test]
    fn a_full_byte_range_reaches_eight_bits() {
        let spread: Vec<u8> = (0..=255u8).cycle().take(65_536).collect();
        let value = shannon(&spread);
        assert!((value - 8.0).abs() < 0.001, "expected ~8.0, got {value}");
    }

    #[test]
    fn one_dominant_byte_lowers_entropy() {
        let mut sample = vec![0u8; 4096];
        sample[0] = 1;
        assert!(shannon(&sample) < 0.01);
    }
}
