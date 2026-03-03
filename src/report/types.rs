//! ETSI TS 119 102-2 data types and URI constants.
//!
//! Defines the enumerations and identifier URIs used in ETSI validation
//! reports: main/sub-indications, validation object types, and proof-of-existence types.

use std::fmt;

// ── XML Namespaces ──────────────────────────────────────────────────────

/// ETSI TS 119 102-2 validation report namespace.
pub const NS_VR: &str = "http://uri.etsi.org/19102/v1.2.1#";

/// XML Digital Signatures namespace.
pub const NS_DS: &str = "http://www.w3.org/2000/09/xmldsig#";

/// XAdES namespace (v1.3.2).
pub const NS_XADES: &str = "http://uri.etsi.org/01903/v1.3.2#";

// ── Main Indication (ETSI EN 319 102-1, clause 5.1.2) ──────────────────

/// Main indication of validation result.
///
/// See ETSI EN 319 102-1 clause 5.1.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MainIndication {
    /// Validation passed all checks.
    TotalPassed,
    /// Validation failed definitively.
    TotalFailed,
    /// Validation result is indeterminate.
    Indeterminate,
}

impl MainIndication {
    /// ETSI URI for this indication.
    pub fn uri(&self) -> &'static str {
        match self {
            Self::TotalPassed => "urn:etsi:019102:mainindication:total-passed",
            Self::TotalFailed => "urn:etsi:019102:mainindication:total-failed",
            Self::Indeterminate => "urn:etsi:019102:mainindication:indeterminate",
        }
    }
}

impl fmt::Display for MainIndication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.uri())
    }
}

// ── Sub Indication ──────────────────────────────────────────────────────

/// Sub-indication providing detail on why validation did not pass.
///
/// Defined in ETSI EN 319 102-1, clause 5.1.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubIndication {
    FormatFailure,
    HashFailure,
    SigCryptoFailure,
    Revoked,
    SigConstraintsFailure,
    ChainConstraintsFailure,
    CertificateChainGeneralFailure,
    CryptoConstraintsFailure,
    Expired,
    NotYetValid,
    PolicyProcessingError,
    SignatureProcessingError,
    FormatNotSupported,
    RevocationOutOfBounds,
    OutOfBoundsNoPoiFound,
    OutOfBoundsNotRevoked,
    TryLater,
    RevocationServerUnavailable,
    NoSigningCertificateFound,
    NoCertificateChainFound,
    RevokedNoPoiFound,
    RevokedCaNoPoiFound,
}

impl SubIndication {
    /// ETSI URI for this sub-indication.
    pub fn uri(&self) -> &'static str {
        match self {
            Self::FormatFailure => "urn:etsi:019102:subindication:FORMAT_FAILURE",
            Self::HashFailure => "urn:etsi:019102:subindication:HASH_FAILURE",
            Self::SigCryptoFailure => "urn:etsi:019102:subindication:SIG_CRYPTO_FAILURE",
            Self::Revoked => "urn:etsi:019102:subindication:REVOKED",
            Self::SigConstraintsFailure => "urn:etsi:019102:subindication:SIG_CONSTRAINTS_FAILURE",
            Self::ChainConstraintsFailure => {
                "urn:etsi:019102:subindication:CHAIN_CONSTRAINTS_FAILURE"
            }
            Self::CertificateChainGeneralFailure => {
                "urn:etsi:019102:subindication:CERTIFICATE_CHAIN_GENERAL_FAILURE"
            }
            Self::CryptoConstraintsFailure => {
                "urn:etsi:019102:subindication:CRYPTO_CONSTRAINTS_FAILURE"
            }
            Self::Expired => "urn:etsi:019102:subindication:EXPIRED",
            Self::NotYetValid => "urn:etsi:019102:subindication:NOT_YET_VALID",
            Self::PolicyProcessingError => "urn:etsi:019102:subindication:POLICY_PROCESSING_ERROR",
            Self::SignatureProcessingError => {
                "urn:etsi:019102:subindication:SIGNATURE_PROCESSING_ERROR"
            }
            Self::FormatNotSupported => "urn:etsi:019102:subindication:FORMAT_NOT_SUPPORTED",
            Self::RevocationOutOfBounds => {
                "urn:etsi:019102:subindication:REVOCATION_OUT_OF_BOUNDS_NO_POI"
            }
            Self::OutOfBoundsNoPoiFound => "urn:etsi:019102:subindication:OUT_OF_BOUNDS_NO_POI",
            Self::OutOfBoundsNotRevoked => {
                "urn:etsi:019102:subindication:OUT_OF_BOUNDS_NOT_REVOKED"
            }
            Self::TryLater => "urn:etsi:019102:subindication:TRY_LATER",
            Self::RevocationServerUnavailable => {
                "urn:etsi:019102:subindication:REVOCATION_SERVER_UNAVAILABLE"
            }
            Self::NoSigningCertificateFound => {
                "urn:etsi:019102:subindication:NO_SIGNING_CERTIFICATE_FOUND"
            }
            Self::NoCertificateChainFound => {
                "urn:etsi:019102:subindication:NO_CERTIFICATE_CHAIN_FOUND"
            }
            Self::RevokedNoPoiFound => "urn:etsi:019102:subindication:REVOKED_NO_POI",
            Self::RevokedCaNoPoiFound => "urn:etsi:019102:subindication:REVOKED_CA_NO_POI",
        }
    }
}

impl fmt::Display for SubIndication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.uri())
    }
}

// ── Validation Object Type ──────────────────────────────────────────────

/// Type of validation object included in the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationObjectType {
    Certificate,
    Crl,
    OcspResponse,
    Timestamp,
    EvidenceRecord,
    PublicKey,
    SignedData,
    Other,
}

impl ValidationObjectType {
    /// ETSI URI for this object type.
    pub fn uri(&self) -> &'static str {
        match self {
            Self::Certificate => "urn:etsi:019102:validationObject:certificate",
            Self::Crl => "urn:etsi:019102:validationObject:CRL",
            Self::OcspResponse => "urn:etsi:019102:validationObject:OCSPResponse",
            Self::Timestamp => "urn:etsi:019102:validationObject:timestamp",
            Self::EvidenceRecord => "urn:etsi:019102:validationObject:evidencerecord",
            Self::PublicKey => "urn:etsi:019102:validationObject:publicKey",
            Self::SignedData => "urn:etsi:019102:validationObject:signedData",
            Self::Other => "urn:etsi:019102:validationObject:other",
        }
    }

    /// Short prefix for generating object IDs (e.g., "C" for certificate).
    pub fn id_prefix(&self) -> &'static str {
        match self {
            Self::Certificate => "C",
            Self::Crl => "CRL",
            Self::OcspResponse => "OCSP",
            Self::Timestamp => "T",
            Self::EvidenceRecord => "ER",
            Self::PublicKey => "PK",
            Self::SignedData => "SD",
            Self::Other => "O",
        }
    }
}

impl fmt::Display for ValidationObjectType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.uri())
    }
}

// ── Proof-of-Existence Type ─────────────────────────────────────────────

/// Type of proof of existence (POE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum POEType {
    /// Proof from validation process.
    Validation,
    /// Proof provided externally.
    Provided,
    /// Proof from a policy.
    Policy,
}

impl POEType {
    /// ETSI URI for this proof type.
    pub fn uri(&self) -> &'static str {
        match self {
            Self::Validation => "urn:etsi:019102:poetype:validation",
            Self::Provided => "urn:etsi:019102:poetype:provided",
            Self::Policy => "urn:etsi:019102:poetype:policy",
        }
    }
}

impl fmt::Display for POEType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.uri())
    }
}

// ── Report Options ──────────────────────────────────────────────────────

/// Options controlling what is included in the validation report.
#[derive(Debug, Clone)]
pub struct ReportOptions {
    /// Include the full signer certificate chain in validation objects.
    pub include_chain: bool,

    /// Include timestamp-related certificates in validation objects.
    pub include_timestamp_certs: bool,

    /// Validation policy URI to include in the report.
    pub validation_policy: Option<String>,

    /// Validation process URI.
    pub validation_process: Option<String>,

    /// Human-readable name of the signature validator.
    pub validator_name: Option<String>,
}

impl Default for ReportOptions {
    fn default() -> Self {
        Self {
            include_chain: true,
            include_timestamp_certs: false,
            validation_policy: None,
            validation_process: None,
            validator_name: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_main_indication_uris() {
        assert_eq!(
            MainIndication::TotalPassed.uri(),
            "urn:etsi:019102:mainindication:total-passed"
        );
        assert_eq!(
            MainIndication::TotalFailed.uri(),
            "urn:etsi:019102:mainindication:total-failed"
        );
        assert_eq!(
            MainIndication::Indeterminate.uri(),
            "urn:etsi:019102:mainindication:indeterminate"
        );
    }

    #[test]
    fn test_sub_indication_uris() {
        assert_eq!(
            SubIndication::HashFailure.uri(),
            "urn:etsi:019102:subindication:HASH_FAILURE"
        );
        assert_eq!(
            SubIndication::SigCryptoFailure.uri(),
            "urn:etsi:019102:subindication:SIG_CRYPTO_FAILURE"
        );
        assert_eq!(
            SubIndication::Expired.uri(),
            "urn:etsi:019102:subindication:EXPIRED"
        );
    }

    #[test]
    fn test_validation_object_type_uris() {
        assert_eq!(
            ValidationObjectType::Certificate.uri(),
            "urn:etsi:019102:validationObject:certificate"
        );
        assert_eq!(
            ValidationObjectType::Crl.uri(),
            "urn:etsi:019102:validationObject:CRL"
        );
        assert_eq!(ValidationObjectType::Certificate.id_prefix(), "C");
        assert_eq!(ValidationObjectType::Timestamp.id_prefix(), "T");
    }

    #[test]
    fn test_poe_type_uris() {
        assert_eq!(
            POEType::Validation.uri(),
            "urn:etsi:019102:poetype:validation"
        );
        assert_eq!(POEType::Provided.uri(), "urn:etsi:019102:poetype:provided");
    }

    #[test]
    fn test_main_indication_display() {
        assert_eq!(
            format!("{}", MainIndication::TotalPassed),
            "urn:etsi:019102:mainindication:total-passed"
        );
    }

    #[test]
    fn test_report_options_default() {
        let opts = ReportOptions::default();
        assert!(opts.include_chain);
        assert!(!opts.include_timestamp_certs);
        assert!(opts.validation_policy.is_none());
        assert!(opts.validator_name.is_none());
    }
}
