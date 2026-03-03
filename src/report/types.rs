//! ETSI TS 119 102-2 data types and URI constants.
//!
//! Defines the enumerations and identifier URIs used in ETSI validation
//! reports: main/sub-indications, validation object types, proof-of-existence types,
//! validation objects, and signature quality levels.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
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

// ── Sweden Connect Identifier URIs ──────────────────────────────────────

/// Signature quality: Advanced Electronic Signature (baseline).
pub const QUALITY_ADES: &str = "http://id.swedenconnect.se/sigval-report/quality/ades";
/// Signature quality: ETSI baseline profile.
pub const QUALITY_ETSI: &str = "http://id.swedenconnect.se/sigval-report/quality/etsi";
/// Signature quality: EU Qualified Certificate.
pub const QUALITY_QC: &str = "http://id.swedenconnect.se/sigval-report/quality/qc";
/// Signature quality: EU Qualified Certificate on QSCD.
pub const QUALITY_QC_QSCD: &str = "http://id.swedenconnect.se/sigval-report/quality/qc-qscd";

/// Validation policy: basic trust-list validation (no revocation).
pub const POLICY_BASIC: &str = "http://id.swedenconnect.se/svt/sigval-policy/basic/01";
/// Validation policy: full PKIX path validation with revocation.
pub const POLICY_PKIX: &str = "http://id.swedenconnect.se/svt/sigval-policy/pkix/01";
/// Validation policy: PKIX with timestamp-based grace period.
pub const POLICY_TS_PKIX: &str = "http://id.swedenconnect.se/svt/sigval-policy/ts-pkix/01";
/// Validation policy: SVT-based (original was PKIX).
pub const POLICY_SVT_PKIX: &str = "http://id.swedenconnect.se/svt/sigval-policy/pkix/01/svt";
/// Validation policy: SVT-based (original was timestamped PKIX).
pub const POLICY_SVT_TS_PKIX: &str = "http://id.swedenconnect.se/svt/sigval-policy/ts-pkix/01/svt";

/// Status message data type in report.
pub const REPORT_STATUS_MESSAGE: &str = "http://id.swedenconnect.se/sigval-report/data/message";
/// Custom sub-indication for partially-signed documents.
pub const SUBINDICATION_PARTIALLY_SIGNED: &str =
    "http://id.swedenconnect.se/sigval-report/subindication/partially-signed";

// ── Signature Algorithm OID → XML-DSIG URI Mapping ─────────────────────

/// Map a CMS signature algorithm OID to the XML Digital Signature algorithm URI.
///
/// Returns `None` for unrecognized OIDs.
pub fn signature_algorithm_uri(oid: &str) -> Option<&'static str> {
    match oid {
        // RSA with SHA-256
        "1.2.840.113549.1.1.11" => Some("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"),
        // RSA with SHA-384
        "1.2.840.113549.1.1.12" => Some("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"),
        // RSA with SHA-512
        "1.2.840.113549.1.1.13" => Some("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"),
        // RSA with SHA-1 (legacy)
        "1.2.840.113549.1.1.5" => Some("http://www.w3.org/2000/09/xmldsig#rsa-sha1"),
        // RSA-PSS
        "1.2.840.113549.1.1.10" => Some("http://www.w3.org/2007/05/xmldsig-more#rsa-pss"),
        // ECDSA with SHA-256
        "1.2.840.10045.4.3.2" => Some("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"),
        // ECDSA with SHA-384
        "1.2.840.10045.4.3.3" => Some("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"),
        // ECDSA with SHA-512
        "1.2.840.10045.4.3.4" => Some("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"),
        // EdDSA (Ed25519)
        "1.3.101.112" => Some("http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519"),
        // EdDSA (Ed448)
        "1.3.101.113" => Some("http://www.w3.org/2021/04/xmldsig-more#eddsa-ed448"),
        _ => None,
    }
}

// ── Signature Quality ───────────────────────────────────────────────────

/// Quality level of an electronic signature.
///
/// Based on EU Regulation 910/2014 (eIDAS) and Sweden Connect extension identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureQuality {
    /// Advanced Electronic Signature (AdES baseline).
    Ades,
    /// ETSI baseline profile compliant.
    Etsi,
    /// Qualified Certificate used.
    Qc,
    /// Qualified Certificate on a Qualified Signature Creation Device.
    QcQscd,
}

impl SignatureQuality {
    /// URI for this quality level.
    pub fn uri(&self) -> &'static str {
        match self {
            Self::Ades => QUALITY_ADES,
            Self::Etsi => QUALITY_ETSI,
            Self::Qc => QUALITY_QC,
            Self::QcQscd => QUALITY_QC_QSCD,
        }
    }
}

impl fmt::Display for SignatureQuality {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.uri())
    }
}

// ── Validation Object ───────────────────────────────────────────────────

/// How a validation object is represented in the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepresentationType {
    /// Full object encoded in Base64.
    Base64,
    /// Hash-only representation (digest algorithm + digest value).
    Hash,
}

/// A validation object to be included in the `<SignatureValidationObjects>` section.
#[derive(Debug, Clone)]
pub struct ValidationObject {
    /// Unique ID (e.g. `C-{sha256hex40}`, `T-{sha256hex40}`).
    pub id: String,
    /// Type of this object.
    pub object_type: ValidationObjectType,
    /// How the object is represented.
    pub representation: RepresentationType,
    /// The raw object bytes (for Base64 representation).
    pub object_bytes: Option<Vec<u8>>,
    /// Hash algorithm URI (for Hash representation).
    pub hash_algorithm: Option<String>,
    /// Hash value (for Hash representation).
    pub hash_value: Option<Vec<u8>>,
    /// Proof-of-existence time, if applicable (ISO 8601 string).
    pub poe_time: Option<String>,
}

/// Generate a deterministic validation object ID from data bytes.
///
/// Format: `{prefix}-{sha256_hex_truncated_to_40}` matching the Java reference.
pub fn generate_vo_id(object_type: ValidationObjectType, data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    let hex = hex::encode(hash);
    let truncated = &hex[..hex.len().min(40)];
    format!("{}-{}", object_type.id_prefix(), truncated)
}

/// Collector for validation objects, with deduplication by ID.
///
/// The Java reference uses a `Map<String, ValidationObject>` shared across
/// all signatures. This collector mirrors that pattern.
#[derive(Debug, Default)]
pub struct ValidationObjectCollector {
    objects: HashMap<String, ValidationObject>,
    /// Insertion order for deterministic output.
    order: Vec<String>,
}

impl ValidationObjectCollector {
    /// Create a new empty collector.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a certificate as a Base64 validation object.
    ///
    /// Returns the generated VO ID. Deduplicates by ID.
    pub fn add_certificate(&mut self, cert_der: &[u8]) -> String {
        let id = generate_vo_id(ValidationObjectType::Certificate, cert_der);
        if !self.objects.contains_key(&id) {
            self.objects.insert(
                id.clone(),
                ValidationObject {
                    id: id.clone(),
                    object_type: ValidationObjectType::Certificate,
                    representation: RepresentationType::Base64,
                    object_bytes: Some(cert_der.to_vec()),
                    hash_algorithm: None,
                    hash_value: None,
                    poe_time: None,
                },
            );
            self.order.push(id.clone());
        }
        id
    }

    /// Add a timestamp token as a Hash validation object.
    ///
    /// Returns the generated VO ID. `poe_time` is the verified timestamp time (ISO 8601).
    pub fn add_timestamp(&mut self, token_der: &[u8], poe_time: Option<&str>) -> String {
        let hash = Sha256::digest(token_der);
        let hex_str = hex::encode(hash);
        let truncated = &hex_str[..hex_str.len().min(40)];
        let id = format!(
            "{}-{}",
            ValidationObjectType::Timestamp.id_prefix(),
            truncated
        );
        if !self.objects.contains_key(&id) {
            self.objects.insert(
                id.clone(),
                ValidationObject {
                    id: id.clone(),
                    object_type: ValidationObjectType::Timestamp,
                    representation: RepresentationType::Hash,
                    object_bytes: None,
                    hash_algorithm: Some("http://www.w3.org/2001/04/xmlenc#sha256".to_string()),
                    hash_value: Some(hash.to_vec()),
                    poe_time: poe_time.map(|s| s.to_string()),
                },
            );
            self.order.push(id.clone());
        }
        id
    }

    /// Add a signed data object as a Hash validation object.
    pub fn add_signed_data(&mut self, data: &[u8]) -> String {
        let hash = Sha256::digest(data);
        let hex_str = hex::encode(hash);
        let truncated = &hex_str[..hex_str.len().min(40)];
        let id = format!(
            "{}-{}",
            ValidationObjectType::SignedData.id_prefix(),
            truncated
        );
        if !self.objects.contains_key(&id) {
            self.objects.insert(
                id.clone(),
                ValidationObject {
                    id: id.clone(),
                    object_type: ValidationObjectType::SignedData,
                    representation: RepresentationType::Hash,
                    object_bytes: None,
                    hash_algorithm: Some("http://www.w3.org/2001/04/xmlenc#sha256".to_string()),
                    hash_value: Some(hash.to_vec()),
                    poe_time: None,
                },
            );
            self.order.push(id.clone());
        }
        id
    }

    /// Iterate over validation objects in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = &ValidationObject> {
        self.order.iter().filter_map(|id| self.objects.get(id))
    }

    /// Whether the collector has any objects.
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }

    /// Number of collected validation objects.
    pub fn len(&self) -> usize {
        self.objects.len()
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

    #[test]
    fn test_signature_quality_uris() {
        assert_eq!(SignatureQuality::Ades.uri(), QUALITY_ADES);
        assert_eq!(SignatureQuality::Etsi.uri(), QUALITY_ETSI);
        assert_eq!(SignatureQuality::Qc.uri(), QUALITY_QC);
        assert_eq!(SignatureQuality::QcQscd.uri(), QUALITY_QC_QSCD);
    }

    #[test]
    fn test_signature_quality_display() {
        assert!(format!("{}", SignatureQuality::QcQscd).contains("qc-qscd"));
    }

    #[test]
    fn test_signature_algorithm_uri_mapping() {
        assert_eq!(
            signature_algorithm_uri("1.2.840.113549.1.1.11"),
            Some("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
        );
        assert_eq!(
            signature_algorithm_uri("1.2.840.10045.4.3.2"),
            Some("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256")
        );
        assert_eq!(signature_algorithm_uri("9.9.9.9.9"), None);
    }

    #[test]
    fn test_generate_vo_id() {
        let id = generate_vo_id(ValidationObjectType::Certificate, b"test cert");
        assert!(id.starts_with("C-"));
        assert_eq!(id.len(), 2 + 40); // "C-" + 40 hex chars

        let id2 = generate_vo_id(ValidationObjectType::Timestamp, b"test ts");
        assert!(id2.starts_with("T-"));
    }

    #[test]
    fn test_vo_collector_deduplication() {
        let mut collector = ValidationObjectCollector::new();
        let cert = b"test certificate DER data";

        let id1 = collector.add_certificate(cert);
        let id2 = collector.add_certificate(cert);

        // Same data should produce the same ID
        assert_eq!(id1, id2);
        // Should only have one entry
        assert_eq!(collector.len(), 1);
    }

    #[test]
    fn test_vo_collector_multiple_types() {
        let mut collector = ValidationObjectCollector::new();

        let cert_id = collector.add_certificate(b"cert1");
        let ts_id = collector.add_timestamp(b"ts1", Some("2025-01-15T10:00:00Z"));
        let sd_id = collector.add_signed_data(b"signed data");

        assert_eq!(collector.len(), 3);
        assert!(cert_id.starts_with("C-"));
        assert!(ts_id.starts_with("T-"));
        assert!(sd_id.starts_with("SD-"));

        // Verify iteration order matches insertion order
        let ids: Vec<&str> = collector.iter().map(|vo| vo.id.as_str()).collect();
        assert_eq!(ids, vec![cert_id.as_str(), ts_id.as_str(), sd_id.as_str()]);
    }

    #[test]
    fn test_vo_collector_timestamp_with_poe() {
        let mut collector = ValidationObjectCollector::new();
        let id = collector.add_timestamp(b"timestamp token", Some("2025-06-01T12:00:00Z"));

        let vo = collector.iter().next().unwrap();
        assert_eq!(vo.id, id);
        assert_eq!(vo.object_type, ValidationObjectType::Timestamp);
        assert_eq!(vo.representation, RepresentationType::Hash);
        assert!(vo.hash_algorithm.is_some());
        assert!(vo.hash_value.is_some());
        assert_eq!(vo.poe_time.as_deref(), Some("2025-06-01T12:00:00Z"));
    }

    #[test]
    fn test_sweden_connect_constants() {
        assert!(POLICY_BASIC.contains("sigval-policy/basic"));
        assert!(POLICY_PKIX.contains("sigval-policy/pkix"));
        assert!(POLICY_SVT_PKIX.ends_with("/svt"));
        assert!(SUBINDICATION_PARTIALLY_SIGNED.contains("partially-signed"));
    }
}
