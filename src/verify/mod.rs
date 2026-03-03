//! Signature verification and validation.
//!
//! Extracts signatures from PDFs, verifies CMS cryptographic integrity,
//! validates certificate chains, and checks ByteRange integrity.
//!
//! # Usage
//!
//! ```no_run
//! use underskrift::verify::{SignatureVerifier, VerificationReport};
//! use underskrift::trust::{TrustStore, TrustStoreSet};
//!
//! # fn example() -> Result<(), underskrift::PdfSignError> {
//! // Load the PDF and set up trust store
//! let pdf = std::fs::read("signed.pdf")?;
//! let trust = TrustStore::from_pem_file("ca-cert.pem")?;
//! let trust_set = TrustStoreSet::new().with_sig_store(trust);
//!
//! // Verify all signatures
//! let verifier = SignatureVerifier::new(&trust_set);
//! let report = verifier.verify_pdf(&pdf)?;
//!
//! for sig in &report.signatures {
//!     println!("{}: {:?}", sig.field_name, sig.status);
//! }
//! # Ok(())
//! # }
//! ```

pub mod chain_verify;
pub mod cms_verify;
pub mod extractor;
pub mod integrity;
pub mod report;

// Re-export key types for convenience
pub use chain_verify::CertValidity;
pub use extractor::{ExtractedSignature, SignatureType};
pub use report::{
    CryptoValidity, DetectedPadesLevel, SignatureStatus, SignatureVerificationResult,
    VerificationReport,
};

use crate::crypto::algorithm::DigestAlgorithm;
use crate::error::{PdfSignError, VerifyError};
use crate::trust::TrustStoreSet;

/// PDF signature verifier.
///
/// Orchestrates the full verification pipeline:
/// 1. Extract signatures from the PDF
/// 2. For each signature:
///    a. Verify ByteRange integrity
///    b. Verify CMS cryptographic signature
///    c. Validate the certificate chain
/// 3. Return a structured verification report
pub struct SignatureVerifier<'a> {
    /// Trust stores (signature, TSA, SVT)
    trust_stores: &'a TrustStoreSet,
    /// Whether to allow online validation (OCSP/CRL fetching).
    /// When false, only embedded validation data is used.
    /// Defaults to false (offline-only for now; online comes in Phase 4).
    allow_online: bool,
}

impl<'a> SignatureVerifier<'a> {
    /// Create a new verifier with the given trust store set.
    pub fn new(trust_stores: &'a TrustStoreSet) -> Self {
        Self {
            trust_stores,
            allow_online: false,
        }
    }

    /// Set whether online validation (OCSP/CRL) is allowed.
    pub fn allow_online(mut self, allow: bool) -> Self {
        self.allow_online = allow;
        self
    }

    /// Verify all signatures in a PDF document.
    ///
    /// Returns a `VerificationReport` with per-signature results and
    /// an overall document status.
    pub fn verify_pdf(&self, pdf_data: &[u8]) -> Result<VerificationReport, PdfSignError> {
        // Step 1: Extract all signatures
        let extracted = extractor::extract_signatures(pdf_data)?;

        if extracted.is_empty() {
            return Err(VerifyError::NoSignatures.into());
        }

        let mut results = Vec::with_capacity(extracted.len());
        let num_sigs = extracted.len();

        for (idx, sig) in extracted.iter().enumerate() {
            let is_last = idx == num_sigs - 1;
            let result = self.verify_single_signature(pdf_data, sig, is_last);
            results.push(result);
        }

        // Compute summary stats
        let valid_count = results
            .iter()
            .filter(|r| r.status == SignatureStatus::Valid)
            .count();
        let invalid_count = results.len() - valid_count;
        let document_modified = results
            .last()
            .map(|r| r.modifications_after_signing)
            .unwrap_or(false);

        let summary = if valid_count == results.len() {
            format!("all {} signatures valid and trusted", results.len())
        } else if valid_count > 0 {
            format!(
                "{} of {} signatures valid; {} invalid/indeterminate",
                valid_count,
                results.len(),
                invalid_count
            )
        } else {
            format!("no valid signatures found ({} checked)", results.len())
        };

        Ok(VerificationReport {
            signatures: results,
            document_modified,
            valid_count,
            invalid_count,
            summary,
        })
    }

    /// Verify a single extracted signature.
    fn verify_single_signature(
        &self,
        pdf_data: &[u8],
        sig: &ExtractedSignature,
        is_last: bool,
    ) -> SignatureVerificationResult {
        let mut all_issues = Vec::new();

        // --- Step A: ByteRange integrity ---
        // Determine digest algorithm: we'll try to get it from CMS first,
        // but we need to parse CMS for that. Use SHA-256 as default for
        // integrity check; we'll re-hash if CMS says otherwise.
        let default_digest = DigestAlgorithm::Sha256;

        let integrity_result =
            integrity::verify_byte_range(pdf_data, &sig.byte_range, default_digest);
        let integrity_ok = integrity_result.valid;
        let covers_whole_document = integrity_result.covers_whole_file;
        let integrity_issues = integrity_result.issues.clone();
        all_issues.extend(integrity_result.issues);

        // --- Step B: CMS cryptographic verification ---
        let (crypto_validity, digest_matches, signer_cert, embedded_certs, _cms_digest_alg) =
            match cms_verify::verify_cms(&sig.cms_bytes, &integrity_result.data_hash) {
                Ok(cms_result) => {
                    all_issues.extend(cms_result.issues.clone());

                    let crypto_validity = if cms_result.signature_valid {
                        CryptoValidity::Valid
                    } else {
                        let reason = cms_result
                            .issues
                            .iter()
                            .find(|i| i.contains("signature"))
                            .cloned()
                            .unwrap_or_else(|| "unknown".to_string());
                        CryptoValidity::Invalid(reason)
                    };

                    // If CMS says a different digest algorithm than our default,
                    // we should re-hash. For now, this only matters if they differ.
                    let actual_digest = cms_result.digest_algorithm.unwrap_or(default_digest);
                    let final_digest_matches = if actual_digest != default_digest {
                        // Re-compute hash with the correct algorithm
                        let rehash = integrity::compute_byte_range_hash(
                            pdf_data,
                            &sig.byte_range,
                            actual_digest,
                        );
                        // Re-verify CMS with correct hash
                        match cms_verify::verify_cms(&sig.cms_bytes, &rehash) {
                            Ok(r2) => r2.digest_matches,
                            Err(_) => false,
                        }
                    } else {
                        cms_result.digest_matches
                    };

                    (
                        crypto_validity,
                        final_digest_matches,
                        cms_result.signer_certificate,
                        cms_result.embedded_certificates,
                        Some(actual_digest),
                    )
                }
                Err(e) => {
                    all_issues.push(format!("CMS verification error: {e}"));
                    (
                        CryptoValidity::Invalid(e.to_string()),
                        false,
                        None,
                        Vec::new(),
                        None,
                    )
                }
            };

        // --- Step C: Certificate chain validation ---
        let (certificate_validity, chain_trusted, trust_anchor) =
            if let Some(ref signer_cert) = signer_cert {
                // Use the signature trust store
                if let Some(sig_store) = self.trust_stores.sig() {
                    let chain_result =
                        chain_verify::verify_chain(signer_cert, &embedded_certs, sig_store);
                    all_issues.extend(chain_result.issues);
                    (
                        chain_result.cert_validity,
                        chain_result.trusted,
                        chain_result.trust_anchor_subject,
                    )
                } else {
                    all_issues.push("no signature trust store configured".to_string());
                    (
                        CertValidity::ValidationError("no trust store".to_string()),
                        false,
                        None,
                    )
                }
            } else {
                all_issues.push("no signer certificate found — cannot validate chain".to_string());
                (CertValidity::ChainIncomplete, false, None)
            };

        // --- Step D: Extract signer name ---
        let signer_name = signer_cert
            .as_ref()
            .map(|cert| format!("{}", cert.tbs_certificate.subject));

        // --- Step E: Check post-signature modifications ---
        let modifications_after_signing = if is_last {
            integrity::check_post_signature_modifications(pdf_data, &sig.byte_range)
        } else {
            // Non-last signatures naturally don't cover the full file
            true
        };

        // --- Step F: Determine PAdES level ---
        let pades_level = match sig.signature_type {
            SignatureType::Pades => DetectedPadesLevel::BB, // TODO: detect B-T/B-LT/B-LTA
            SignatureType::DocTimestamp => DetectedPadesLevel::Unknown,
            _ => DetectedPadesLevel::NotPades,
        };

        // --- Step G: Compute overall status ---
        let status = compute_overall_status(
            integrity_ok,
            &crypto_validity,
            digest_matches,
            chain_trusted,
        );

        let summary = build_summary(&status, &all_issues);

        SignatureVerificationResult {
            field_name: sig.field_name.clone(),
            status,
            signature_type: sig.signature_type.clone(),
            signer_name,
            signing_time: sig.signing_time.clone(),
            timestamp_time: None, // TODO: extract from CMS unsigned attributes
            integrity_ok,
            covers_whole_document,
            integrity_issues,
            cryptographic_validity: crypto_validity,
            digest_matches,
            certificate_validity,
            chain_trusted,
            trust_anchor,
            pades_level,
            modifications_after_signing,
            summary,
        }
    }
}

/// Compute the overall signature status from sub-results.
fn compute_overall_status(
    integrity_ok: bool,
    crypto_validity: &CryptoValidity,
    digest_matches: bool,
    chain_trusted: bool,
) -> SignatureStatus {
    if !integrity_ok {
        return SignatureStatus::Invalid;
    }

    match crypto_validity {
        CryptoValidity::Valid => {
            if !digest_matches {
                SignatureStatus::Invalid
            } else if chain_trusted {
                SignatureStatus::Valid
            } else {
                SignatureStatus::ValidButUntrusted
            }
        }
        CryptoValidity::Invalid(_) => SignatureStatus::Invalid,
        CryptoValidity::UnknownAlgorithm(_) => SignatureStatus::Indeterminate,
    }
}

/// Build a human-readable summary string.
fn build_summary(status: &SignatureStatus, issues: &[String]) -> String {
    let status_str = match status {
        SignatureStatus::Valid => "VALID",
        SignatureStatus::ValidButUntrusted => "VALID (untrusted)",
        SignatureStatus::Invalid => "INVALID",
        SignatureStatus::Indeterminate => "INDETERMINATE",
    };

    if issues.is_empty() {
        status_str.to_string()
    } else {
        format!("{}: {}", status_str, issues.join("; "))
    }
}
