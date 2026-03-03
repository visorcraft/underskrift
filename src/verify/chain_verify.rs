//! Certificate chain and revocation validation.
//!
//! Validates the signer's certificate chain against a trust store.
//! Builds the chain from embedded CMS certificates and verifies it
//! leads to a trusted root.

use x509_cert::Certificate;

use crate::trust::TrustStore;

/// Result of certificate chain validation.
#[derive(Debug)]
pub struct ChainVerifyResult {
    /// Whether the chain is valid and leads to a trusted root
    pub trusted: bool,
    /// The certificate chain in order: [leaf, intermediate..., root]
    /// Only populated if chain building succeeds
    pub chain: Vec<Certificate>,
    /// Name of the trust anchor that validated the chain, if any
    pub trust_anchor_subject: Option<String>,
    /// Certificate validity status
    pub cert_validity: CertValidity,
    /// Human-readable issues
    pub issues: Vec<String>,
}

/// Certificate validity status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertValidity {
    /// Certificate and chain are valid
    Valid,
    /// Certificate has expired
    Expired,
    /// Certificate is not yet valid
    NotYetValid,
    /// Certificate is revoked (placeholder — full revocation checking in ltv module)
    Revoked(String),
    /// Certificate chain is incomplete (cannot build path to trust anchor)
    ChainIncomplete,
    /// Root certificate is not in the trust store
    UntrustedRoot,
    /// Validation error
    ValidationError(String),
}

/// Validate a signer certificate's chain against a trust store.
///
/// Attempts to build a certificate chain from the signer's certificate
/// through any intermediates to a trust anchor, then verifies the
/// cryptographic chain of signatures and time validity.
///
/// `signer_cert` is the end-entity certificate from the CMS signer info.
/// `embedded_certs` are all certificates from the CMS SignedData.
/// `trust_store` is the trust store containing root CA certificates.
pub fn verify_chain(
    signer_cert: &Certificate,
    embedded_certs: &[Certificate],
    trust_store: &TrustStore,
) -> ChainVerifyResult {
    let mut issues = Vec::new();

    // Build the certificate chain from signer cert to root
    let chain = match build_chain(signer_cert, embedded_certs) {
        Ok(chain) => chain,
        Err(e) => {
            issues.push(format!("chain building failed: {e}"));
            return ChainVerifyResult {
                trusted: false,
                chain: vec![signer_cert.clone()],
                trust_anchor_subject: None,
                cert_validity: CertValidity::ChainIncomplete,
                issues,
            };
        }
    };

    // Verify the chain against the trust store
    // Use the current system time for validation
    let now = {
        let utc = chrono::Utc::now();
        der::DateTime::new(
            utc.format("%Y").to_string().parse().unwrap_or(2026),
            utc.format("%m").to_string().parse().unwrap_or(1),
            utc.format("%d").to_string().parse().unwrap_or(1),
            utc.format("%H").to_string().parse().unwrap_or(0),
            utc.format("%M").to_string().parse().unwrap_or(0),
            utc.format("%S").to_string().parse().unwrap_or(0),
        )
        .ok()
    };
    match trust_store.verify_chain(&chain, now) {
        Ok(anchor) => {
            let anchor_subject = format!("{}", anchor.tbs_certificate.subject);
            ChainVerifyResult {
                trusted: true,
                chain,
                trust_anchor_subject: Some(anchor_subject),
                cert_validity: CertValidity::Valid,
                issues,
            }
        }
        Err(e) => {
            let cert_validity = match &e {
                crate::error::TrustError::Expired { .. } => CertValidity::Expired,
                crate::error::TrustError::NotYetValid { .. } => CertValidity::NotYetValid,
                crate::error::TrustError::UntrustedRoot { .. } => CertValidity::UntrustedRoot,
                crate::error::TrustError::ChainBroken { .. } => CertValidity::ChainIncomplete,
                other => CertValidity::ValidationError(format!("{other}")),
            };
            issues.push(format!("chain verification failed: {e}"));
            ChainVerifyResult {
                trusted: false,
                chain,
                trust_anchor_subject: None,
                cert_validity,
                issues,
            }
        }
    }
}

/// Build a certificate chain from a leaf certificate through intermediates.
///
/// Starting from the signer's certificate, finds each issuer in the
/// embedded certificates set, building a chain [leaf, intermediate_0, ..., intermediate_n].
/// The root CA is NOT included in the chain (it's found in the trust store).
///
/// Stops when:
/// - A self-signed certificate is found (root CA in the embedded set)
/// - No issuer is found in the embedded set (issuer should be in the trust store)
/// - Maximum chain depth is exceeded (prevents loops)
fn build_chain(
    signer_cert: &Certificate,
    embedded_certs: &[Certificate],
) -> Result<Vec<Certificate>, String> {
    const MAX_CHAIN_DEPTH: usize = 10;

    let mut chain = vec![signer_cert.clone()];
    let mut current = signer_cert.clone();

    for _ in 0..MAX_CHAIN_DEPTH {
        let issuer_name = &current.tbs_certificate.issuer;
        let subject_name = &current.tbs_certificate.subject;

        // Check if this is a self-signed cert (issuer == subject)
        if issuer_name == subject_name {
            // Self-signed — this is a root CA. Don't include it in the chain
            // if it's not the leaf (the trust store should have it).
            if chain.len() > 1 {
                // Remove the self-signed cert from the chain — trust store verifies against it
                // Actually, keep it — the trust store's verify_chain expects [leaf, ..., last_intermediate]
                // and the last intermediate's issuer should match a trust anchor.
                // A self-signed cert IS the root, so remove it from the chain.
                chain.pop();
            }
            break;
        }

        // Find the issuer in the embedded certificates
        let issuer_cert = embedded_certs.iter().find(|cert| {
            cert.tbs_certificate.subject == *issuer_name
                // Don't match ourselves
                && cert.tbs_certificate.serial_number != current.tbs_certificate.serial_number
        });

        match issuer_cert {
            Some(cert) => {
                chain.push(cert.clone());
                current = cert.clone();
            }
            None => {
                // Issuer not in embedded certs — should be in the trust store
                break;
            }
        }
    }

    if chain.is_empty() {
        Err("empty chain".to_string())
    } else {
        Ok(chain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cert_validity_enum() {
        assert_eq!(CertValidity::Valid, CertValidity::Valid);
        assert_ne!(CertValidity::Valid, CertValidity::Expired);
    }
}
