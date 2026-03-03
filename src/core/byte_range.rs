//! ByteRange placeholder management, offset tracking, and backpatching.
//!
//! The ByteRange array `[offset1, length1, offset2, length2]` defines the
//! two byte ranges that are hashed for the signature. The gap between them
//! is the `/Contents` hex string. This module handles:
//!
//! - Allocating fixed-width placeholders so byte offsets are stable
//! - Computing the final ByteRange values after the incremental append is written
//! - Backpatching the placeholder values in the output bytes

use crate::error::CoreError;

/// Fixed width for each integer in the ByteRange placeholder.
/// Using 10 digits accommodates files up to ~10GB.
const BYTE_RANGE_INT_WIDTH: usize = 10;

/// Represents the ByteRange for a PDF signature.
#[derive(Debug, Clone)]
pub struct ByteRange {
    /// Byte offset where the ByteRange array literal starts in the output
    pub placeholder_offset: usize,
    /// Total length of the ByteRange placeholder string (for backpatching)
    pub placeholder_length: usize,
    /// Byte offset where the `/Contents` hex string starts (after the `<`)
    pub contents_offset: usize,
    /// Length of the `/Contents` hex string (between `<` and `>`)
    pub contents_length: usize,
}

impl ByteRange {
    /// Compute the final `[offset1, length1, offset2, length2]` values.
    ///
    /// - Range 1: from file start to just before the `<` of Contents
    /// - Range 2: from just after the `>` of Contents to end of file
    ///
    /// `contents_offset` is the position of the first hex byte (after `<`).
    /// So `<` is at `contents_offset - 1` and `>` is at `contents_offset + contents_length`.
    pub fn compute(&self, total_file_length: usize) -> [usize; 4] {
        let offset1 = 0;
        // Everything up to but not including `<`
        let length1 = self.contents_offset - 1;
        // `>` is at contents_offset + contents_length, so range 2 starts after it
        let offset2 = self.contents_offset + self.contents_length + 1;
        let length2 = total_file_length - offset2;
        [offset1, length1, offset2, length2]
    }

    /// Generate the ByteRange placeholder string with fixed-width integers.
    ///
    /// Returns a string like `[0000000000 0000000000 0000000000 0000000000]`.
    pub fn placeholder_string() -> String {
        let zero = "0".repeat(BYTE_RANGE_INT_WIDTH);
        format!("[{zero} {zero} {zero} {zero}]")
    }

    /// Format the final ByteRange values as a fixed-width string.
    ///
    /// Each integer is right-padded with spaces to maintain the same total
    /// length as the placeholder.
    pub fn format_values(values: &[usize; 4]) -> String {
        let parts: Vec<String> = values
            .iter()
            .map(|v| format!("{:<width$}", v, width = BYTE_RANGE_INT_WIDTH))
            .collect();
        format!("[{} {} {} {}]", parts[0], parts[1], parts[2], parts[3])
    }

    /// Backpatch the ByteRange placeholder in the output buffer with final values.
    pub fn backpatch(&self, buf: &mut [u8], total_file_length: usize) -> Result<(), CoreError> {
        let values = self.compute(total_file_length);
        let formatted = Self::format_values(&values);
        let formatted_bytes = formatted.as_bytes();

        if formatted_bytes.len() != self.placeholder_length {
            return Err(CoreError::ByteRangePlaceholderMissing);
        }

        buf[self.placeholder_offset..self.placeholder_offset + self.placeholder_length]
            .copy_from_slice(formatted_bytes);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_placeholder_string_length() {
        let s = ByteRange::placeholder_string();
        // [XXXX XXXX XXXX XXXX] = 1 + 10 + 1 + 10 + 1 + 10 + 1 + 10 + 1 = 45
        assert_eq!(s.len(), 45);
    }

    #[test]
    fn test_compute_byte_range() {
        let br = ByteRange {
            placeholder_offset: 100,
            placeholder_length: 45,
            contents_offset: 200, // first hex byte (after `<`)
            contents_length: 8192,
        };
        // Total file = 10000
        // `<` is at 199, hex bytes at [200..8392), `>` is at 8392
        let values = br.compute(10000);
        assert_eq!(values[0], 0); // offset1
        assert_eq!(values[1], 199); // length1 = contents_offset - 1 (up to `<`)
        assert_eq!(values[2], 8393); // offset2 = 200 + 8192 + 1 (after `>`)
        assert_eq!(values[3], 1607); // length2 = 10000 - 8393
    }

    #[test]
    fn test_format_values_same_length_as_placeholder() {
        let values = [0, 1234, 5678, 9012];
        let formatted = ByteRange::format_values(&values);
        let placeholder = ByteRange::placeholder_string();
        assert_eq!(formatted.len(), placeholder.len());
    }
}
