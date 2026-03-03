//! DocMDP and FieldMDP — certification and modification detection.
//!
//! Handles `/DocMDP` transform method for certification signatures and
//! `/FieldMDP` for field-level locking.

/// Permitted changes level for a certification signature (DocMDP).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocMdpPermissions {
    /// No changes allowed
    NoChanges = 1,
    /// Form filling and signing only
    FormFillingAndSigning = 2,
    /// Form filling, signing, and annotation
    FormFillingSigningAndAnnotation = 3,
}

impl Default for DocMdpPermissions {
    fn default() -> Self {
        Self::FormFillingAndSigning
    }
}
