//! SVT JWT claim data types per RFC 9321.
//!
//! All types use `serde` for JSON serialization, matching the exact field
//! names from the RFC and the Sweden Connect Java reference implementation.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// SVT profile identifier — the type of signature being validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum SVTProfile {
    /// PDF signature (PAdES / PKCS#7)
    #[serde(rename = "PDF")]
    Pdf,
    /// XML signature (XAdES)
    #[serde(rename = "XML")]
    Xml,
    /// JSON Web Signature
    #[serde(rename = "JWS")]
    Jws,
}

impl fmt::Display for SVTProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SVTProfile::Pdf => write!(f, "PDF"),
            SVTProfile::Xml => write!(f, "XML"),
            SVTProfile::Jws => write!(f, "JWS"),
        }
    }
}

/// Validation conclusion for a policy check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ValidationConclusion {
    Passed,
    Failed,
    Indeterminate,
}

impl fmt::Display for ValidationConclusion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationConclusion::Passed => write!(f, "PASSED"),
            ValidationConclusion::Failed => write!(f, "FAILED"),
            ValidationConclusion::Indeterminate => write!(f, "INDETERMINATE"),
        }
    }
}

/// Certificate reference type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertRefType {
    /// Full certificate chain (base64-encoded DER certs)
    Chain,
    /// Certificate hash chain (base64 hashes of DER certs)
    ChainHash,
}

impl fmt::Display for CertRefType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CertRefType::Chain => write!(f, "chain"),
            CertRefType::ChainHash => write!(f, "chain_hash"),
        }
    }
}

/// Top-level SVT claims — the `sig_val_claims` JWT claim.
///
/// Corresponds to Java `SVTClaims`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SvtClaims {
    /// Version string, always "1.0".
    pub ver: String,

    /// SVT profile (PDF, XML, JWS).
    pub profile: SVTProfile,

    /// Hash algorithm URI used for all hash values in this SVT.
    pub hash_algo: String,

    /// Per-signature claims.
    pub sig: Vec<SignatureClaims>,

    /// Optional extensions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ext: Option<HashMap<String, String>>,
}

impl SvtClaims {
    /// Create new SVT claims with version "1.0" and no extensions.
    pub fn new(profile: SVTProfile, hash_algo: String, sig: Vec<SignatureClaims>) -> Self {
        Self {
            ver: "1.0".to_string(),
            profile,
            hash_algo,
            sig,
            ext: None,
        }
    }
}

/// Claims for a single signature within the SVT.
///
/// Corresponds to Java `SignatureClaims`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureClaims {
    /// Reference hashes identifying the signature.
    pub sig_ref: SigReferenceClaims,

    /// References to the signed data (document content).
    pub sig_data_ref: Vec<SignedDataClaims>,

    /// Reference to the signer's certificate chain.
    pub signer_cert_ref: CertReferenceClaims,

    /// Time validation results (timestamps, etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_val: Option<Vec<TimeValidationClaims>>,

    /// Signature validation policy results.
    pub sig_val: Vec<PolicyValidationClaims>,

    /// Optional extensions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ext: Option<HashMap<String, String>>,
}

/// Reference hashes that uniquely identify a signature.
///
/// Corresponds to Java `SigReferenceClaims`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigReferenceClaims {
    /// Optional signature identifier (e.g., field name for PDF).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Base64-encoded hash of the signature value bytes.
    pub sig_hash: String,

    /// Base64-encoded hash of the DER-encoded signed attributes (or
    /// SignedInfo for XML).
    pub sb_hash: String,
}

/// Reference to the signed data (document content).
///
/// Corresponds to Java `SignedDataClaims`.
/// Note: Java uses `ref` as field name; we use `data_ref` in Rust
/// (since `ref` is a keyword) and rename for JSON serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedDataClaims {
    /// Reference string identifying what was signed.
    /// For PDF: the ByteRange as "offset1 length1 offset2 length2".
    #[serde(rename = "ref")]
    pub data_ref: String,

    /// Base64-encoded hash of the signed content.
    pub hash: String,
}

/// Certificate reference in the SVT.
///
/// Corresponds to Java `CertReferenceClaims`.
/// Note: Java uses `type` and `ref` as field names.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertReferenceClaims {
    /// Type of certificate reference ("chain" or "chain_hash").
    #[serde(rename = "type")]
    pub ref_type: CertRefType,

    /// List of base64-encoded certificates (for "chain") or
    /// base64-encoded certificate hashes (for "chain_hash").
    #[serde(rename = "ref")]
    pub cert_ref: Vec<String>,
}

/// Time validation result.
///
/// Corresponds to Java `TimeValidationClaims`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeValidationClaims {
    /// Unix epoch time in seconds.
    pub time: i64,

    /// Type URI identifying the time source.
    #[serde(rename = "type")]
    pub time_type: String,

    /// Issuer identifier of the time evidence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,

    /// Identifier for the time evidence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Base64-encoded hash of the time evidence data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,

    /// Policy validation results for this time evidence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub val: Option<Vec<PolicyValidationClaims>>,

    /// Optional extensions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ext: Option<HashMap<String, String>>,
}

/// Policy validation result.
///
/// Corresponds to Java `PolicyValidationClaims`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyValidationClaims {
    /// Validation policy URI.
    pub pol: String,

    /// Validation conclusion.
    pub res: ValidationConclusion,

    /// Optional human-readable message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub msg: Option<String>,

    /// Optional extensions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ext: Option<HashMap<String, String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_svt_profile_serialize() {
        assert_eq!(serde_json::to_string(&SVTProfile::Pdf).unwrap(), "\"PDF\"");
        assert_eq!(serde_json::to_string(&SVTProfile::Xml).unwrap(), "\"XML\"");
        assert_eq!(serde_json::to_string(&SVTProfile::Jws).unwrap(), "\"JWS\"");
    }

    #[test]
    fn test_svt_profile_deserialize() {
        let p: SVTProfile = serde_json::from_str("\"PDF\"").unwrap();
        assert_eq!(p, SVTProfile::Pdf);
    }

    #[test]
    fn test_validation_conclusion_roundtrip() {
        for v in [
            ValidationConclusion::Passed,
            ValidationConclusion::Failed,
            ValidationConclusion::Indeterminate,
        ] {
            let json = serde_json::to_string(&v).unwrap();
            let back: ValidationConclusion = serde_json::from_str(&json).unwrap();
            assert_eq!(v, back);
        }
    }

    #[test]
    fn test_cert_ref_type_serialize() {
        assert_eq!(
            serde_json::to_string(&CertRefType::Chain).unwrap(),
            "\"chain\""
        );
        assert_eq!(
            serde_json::to_string(&CertRefType::ChainHash).unwrap(),
            "\"chain_hash\""
        );
    }

    #[test]
    fn test_svt_claims_json_roundtrip() {
        let claims = SvtClaims::new(
            SVTProfile::Pdf,
            "http://www.w3.org/2001/04/xmlenc#sha256".to_string(),
            vec![SignatureClaims {
                sig_ref: SigReferenceClaims {
                    id: Some("Signature1".to_string()),
                    sig_hash: "abc123".to_string(),
                    sb_hash: "def456".to_string(),
                },
                sig_data_ref: vec![SignedDataClaims {
                    data_ref: "0 100 200 300".to_string(),
                    hash: "ghi789".to_string(),
                }],
                signer_cert_ref: CertReferenceClaims {
                    ref_type: CertRefType::Chain,
                    cert_ref: vec!["MIIB...".to_string()],
                },
                time_val: None,
                sig_val: vec![PolicyValidationClaims {
                    pol: "http://example.com/policy".to_string(),
                    res: ValidationConclusion::Passed,
                    msg: Some("OK".to_string()),
                    ext: None,
                }],
                ext: None,
            }],
        );

        let json = serde_json::to_string_pretty(&claims).unwrap();
        let back: SvtClaims = serde_json::from_str(&json).unwrap();

        assert_eq!(back.ver, "1.0");
        assert_eq!(back.profile, SVTProfile::Pdf);
        assert_eq!(back.sig.len(), 1);
        assert_eq!(back.sig[0].sig_ref.sig_hash, "abc123");
        assert_eq!(back.sig[0].sig_val[0].res, ValidationConclusion::Passed);
    }

    #[test]
    fn test_signed_data_claims_ref_keyword() {
        // Verify that "ref" is used in JSON, not "data_ref"
        let sdc = SignedDataClaims {
            data_ref: "0 100 200 300".to_string(),
            hash: "abc".to_string(),
        };
        let json = serde_json::to_string(&sdc).unwrap();
        assert!(json.contains("\"ref\""));
        assert!(!json.contains("\"data_ref\""));
    }

    #[test]
    fn test_cert_ref_claims_type_keyword() {
        // Verify that "type" is used in JSON, not "ref_type"
        let crc = CertReferenceClaims {
            ref_type: CertRefType::ChainHash,
            cert_ref: vec!["hash1".to_string()],
        };
        let json = serde_json::to_string(&crc).unwrap();
        assert!(json.contains("\"type\""));
        assert!(json.contains("\"ref\""));
        assert!(!json.contains("\"ref_type\""));
        assert!(!json.contains("\"cert_ref\""));
    }

    #[test]
    fn test_time_validation_claims_type_keyword() {
        let tvc = TimeValidationClaims {
            time: 1700000000,
            time_type: "http://example.com/tsa".to_string(),
            iss: None,
            id: None,
            hash: None,
            val: None,
            ext: None,
        };
        let json = serde_json::to_string(&tvc).unwrap();
        assert!(json.contains("\"type\""));
        assert!(!json.contains("\"time_type\""));
    }
}
