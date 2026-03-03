//! Verification result types and signature status reporting.
//!
//! Provides structured types for representing the outcome of verifying
//! each signature in a PDF document. Follows the plan's specification
//! for rich validation results.

use crate::verify::chain_verify::CertValidity;
use crate::verify::extractor::SignatureType;

/// Overall status of a signature verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureStatus {
    /// Signature is cryptographically valid and trusted
    Valid,
    /// Signature is cryptographically valid but chain is not trusted
    ValidButUntrusted,
    /// Signature is cryptographically invalid
    Invalid,
    /// Signature could not be verified (missing data, unsupported algorithm, etc.)
    Indeterminate,
}

/// Cryptographic validity of the signature itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoValidity {
    /// Cryptographic signature is valid
    Valid,
    /// Cryptographic signature is invalid
    Invalid(String),
    /// Algorithm is unknown or unsupported
    UnknownAlgorithm(String),
}

/// Detected PAdES conformance level of a signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectedPadesLevel {
    /// PAdES B-B (basic)
    BB,
    /// PAdES B-T (with timestamp)
    BT,
    /// PAdES B-LT (with LTV data)
    BLT,
    /// PAdES B-LTA (with archive timestamp)
    BLTA,
    /// Not a PAdES signature
    NotPades,
    /// Cannot determine level
    Unknown,
}

/// Result of verifying a single signature in a PDF.
#[derive(Debug)]
pub struct SignatureVerificationResult {
    /// The signature field name
    pub field_name: String,
    /// Overall status
    pub status: SignatureStatus,
    /// Type of signature (PAdES, PKCS#7, DocTimestamp, etc.)
    pub signature_type: SignatureType,
    /// Signer's common name or subject, if extracted
    pub signer_name: Option<String>,
    /// Signing time from CMS signed attributes, if present
    pub signing_time: Option<String>,
    /// Timestamp time (from embedded RFC 3161 timestamp), if present
    pub timestamp_time: Option<String>,

    /// Integrity check: ByteRange is structurally valid
    pub integrity_ok: bool,
    /// Integrity check: ByteRange covers the entire file
    pub covers_whole_document: bool,
    /// ByteRange integrity issues (empty if none)
    pub integrity_issues: Vec<String>,

    /// CMS cryptographic verification result
    pub cryptographic_validity: CryptoValidity,
    /// Whether the messageDigest attribute matches the data hash
    pub digest_matches: bool,

    /// Certificate chain validation result
    pub certificate_validity: CertValidity,
    /// Whether the chain leads to a trusted root
    pub chain_trusted: bool,
    /// Trust anchor subject, if chain is trusted
    pub trust_anchor: Option<String>,

    /// Detected PAdES conformance level
    pub pades_level: DetectedPadesLevel,

    /// Whether the document was modified after this signature
    pub modifications_after_signing: bool,

    /// Human-readable summary
    pub summary: String,
}

/// Result of verifying all signatures in a PDF.
#[derive(Debug)]
pub struct VerificationReport {
    /// Results for each signature, in document order
    pub signatures: Vec<SignatureVerificationResult>,
    /// Whether the document has been modified after the last signature
    pub document_modified: bool,
    /// Number of valid signatures
    pub valid_count: usize,
    /// Number of invalid/indeterminate signatures
    pub invalid_count: usize,
    /// Overall document status summary
    pub summary: String,
}

impl VerificationReport {
    /// Whether all signatures are valid and trusted.
    pub fn all_valid(&self) -> bool {
        self.invalid_count == 0 && self.valid_count > 0
    }

    /// Whether any signature is valid (even if not all are).
    pub fn any_valid(&self) -> bool {
        self.valid_count > 0
    }
}
