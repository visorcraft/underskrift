//! [`TrustStore`] — a collection of trusted CA certificates (trust anchors).

use crate::error::TrustError;
use der::{Decode, Encode};
use std::path::Path;
use x509_cert::Certificate;

/// A trust anchor: a parsed certificate paired with its DER encoding.
#[derive(Clone)]
struct TrustAnchor {
    cert: Certificate,
    der: Vec<u8>,
}

/// A collection of trusted CA certificates.
///
/// Used to validate that a certificate chain terminates at one of the
/// configured trust anchors.
#[derive(Clone)]
pub struct TrustStore {
    anchors: Vec<TrustAnchor>,
    /// Human-readable label for diagnostics (e.g., "sig", "tsa", "svt").
    label: Option<String>,
}

impl TrustStore {
    /// Create an empty trust store.
    pub fn new() -> Self {
        Self {
            anchors: Vec::new(),
            label: None,
        }
    }

    /// Set a diagnostic label for this store.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// The diagnostic label, if set.
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// Number of trust anchors in this store.
    pub fn len(&self) -> usize {
        self.anchors.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }

    // ── Loading methods ──────────────────────────────────────────────

    /// Load trust anchors from a PEM file (may contain multiple certificates).
    pub fn from_pem_file(path: impl AsRef<Path>) -> Result<Self, TrustError> {
        let data = std::fs::read(path.as_ref()).map_err(TrustError::Io)?;
        let mut store = Self::new();
        store.add_pem_data(&data)?;
        Ok(store)
    }

    /// Load trust anchors from all PEM files (*.pem, *.crt, *.cer) in a directory.
    ///
    /// Non-PEM files and files that fail to parse are silently skipped.
    pub fn from_pem_directory(dir: impl AsRef<Path>) -> Result<Self, TrustError> {
        let dir = dir.as_ref();
        if !dir.is_dir() {
            return Err(TrustError::NotADirectory(dir.display().to_string()));
        }

        let mut store = Self::new();
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .map_err(TrustError::Io)?
            .filter_map(|e| e.ok())
            .collect();
        entries.sort_by_key(|e| e.file_name());

        for entry in entries {
            let path = entry.path();
            if let Some(ext) = path.extension() {
                let ext = ext.to_string_lossy().to_lowercase();
                if ext == "pem" || ext == "crt" || ext == "cer" {
                    if let Ok(data) = std::fs::read(&path) {
                        // Best effort — skip files that aren't valid PEM
                        let _ = store.add_pem_data(&data);
                    }
                }
            }
        }

        Ok(store)
    }

    /// Add a single trust anchor from DER-encoded bytes.
    pub fn add_der_certificate(&mut self, der: &[u8]) -> Result<(), TrustError> {
        let cert = Certificate::from_der(der)
            .map_err(|e| TrustError::CertificateParse(format!("DER decode failed: {e}")))?;
        self.anchors.push(TrustAnchor {
            cert,
            der: der.to_vec(),
        });
        Ok(())
    }

    /// Add a trust anchor from an already-parsed `Certificate`.
    pub fn add_certificate(&mut self, cert: Certificate) -> Result<(), TrustError> {
        let der = cert
            .to_der()
            .map_err(|e| TrustError::CertificateParse(format!("DER encode failed: {e}")))?;
        self.anchors.push(TrustAnchor { cert, der });
        Ok(())
    }

    /// Add trust anchors from PEM-encoded data (may contain multiple certs).
    pub fn add_pem_data(&mut self, pem_data: &[u8]) -> Result<(), TrustError> {
        let pem_str = std::str::from_utf8(pem_data)
            .map_err(|e| TrustError::CertificateParse(format!("invalid UTF-8 in PEM: {e}")))?;

        let mut found_any = false;

        // Parse PEM by looking for BEGIN/END CERTIFICATE markers
        let mut remaining = pem_str;
        while let Some(begin_pos) = remaining.find("-----BEGIN CERTIFICATE-----") {
            let block_start = &remaining[begin_pos..];
            if let Some(end_pos) = block_start.find("-----END CERTIFICATE-----") {
                let end = end_pos + "-----END CERTIFICATE-----".len();
                let pem_block = &block_start[..end];

                // Decode the base64 between the markers
                let b64: String = pem_block
                    .lines()
                    .filter(|line| !line.starts_with("-----"))
                    .collect();

                use base64::Engine;
                let der_bytes = base64::engine::general_purpose::STANDARD
                    .decode(&b64)
                    .map_err(|e| {
                        TrustError::CertificateParse(format!("base64 decode error: {e}"))
                    })?;

                self.add_der_certificate(&der_bytes)?;
                found_any = true;

                remaining = &block_start[end..];
            } else {
                break;
            }
        }

        if !found_any {
            return Err(TrustError::CertificateParse(
                "no CERTIFICATE blocks found in PEM data".into(),
            ));
        }

        Ok(())
    }

    // ── Query methods ────────────────────────────────────────────────

    /// Check whether a given certificate (DER) is directly one of our anchors.
    ///
    /// Comparison is by raw DER bytes (exact match).
    pub fn contains_der(&self, cert_der: &[u8]) -> bool {
        self.anchors.iter().any(|a| a.der == cert_der)
    }

    /// Find the trust anchor that issued the given certificate, if any.
    ///
    /// Matching is done by comparing the certificate's issuer name with
    /// each anchor's subject name. This does NOT verify the signature —
    /// use [`verify_chain`](Self::verify_chain) for full validation.
    pub fn find_issuer(&self, cert: &Certificate) -> Option<&Certificate> {
        let issuer = &cert.tbs_certificate.issuer;
        self.anchors.iter().find_map(|anchor| {
            if &anchor.cert.tbs_certificate.subject == issuer {
                Some(&anchor.cert)
            } else {
                None
            }
        })
    }

    /// Find the trust anchor that issued the given DER-encoded certificate.
    pub fn find_issuer_for_der(&self, cert_der: &[u8]) -> Option<&Certificate> {
        let cert = Certificate::from_der(cert_der).ok()?;
        self.find_issuer(&cert)
    }

    /// Get an iterator over all trust anchor certificates.
    pub fn certificates(&self) -> impl Iterator<Item = &Certificate> {
        self.anchors.iter().map(|a| &a.cert)
    }

    /// Get an iterator over all trust anchor DER encodings.
    pub fn certificates_der(&self) -> impl Iterator<Item = &[u8]> {
        self.anchors.iter().map(|a| a.der.as_slice())
    }

    /// Verify a certificate chain from leaf to a trust anchor.
    ///
    /// The chain should be ordered: `[leaf, intermediate_0, ..., intermediate_n]`.
    /// This method checks:
    /// 1. Each certificate's issuer matches the next certificate's subject
    /// 2. The final certificate's issuer matches a trust anchor's subject
    /// 3. Each certificate's signature is verified against its issuer's public key
    /// 4. Time validity (not before / not after) if `validation_time` is provided
    ///
    /// Returns the matching trust anchor on success.
    pub fn verify_chain(
        &self,
        chain: &[Certificate],
        validation_time: Option<der::DateTime>,
    ) -> Result<&Certificate, TrustError> {
        if chain.is_empty() {
            return Err(TrustError::EmptyChain);
        }

        // Check time validity of all certificates in the chain
        if let Some(time) = validation_time {
            for (i, cert) in chain.iter().enumerate() {
                let validity = &cert.tbs_certificate.validity;
                if time < validity.not_before.to_date_time() {
                    return Err(TrustError::NotYetValid {
                        index: i,
                        not_before: validity.not_before.to_date_time(),
                    });
                }
                if time > validity.not_after.to_date_time() {
                    return Err(TrustError::Expired {
                        index: i,
                        not_after: validity.not_after.to_date_time(),
                    });
                }
            }
        }

        // Walk the chain: each cert's issuer must match next cert's subject
        for i in 0..chain.len().saturating_sub(1) {
            let cert = &chain[i];
            let issuer_cert = &chain[i + 1];

            // Issuer name must match the next certificate's subject name
            if cert.tbs_certificate.issuer != issuer_cert.tbs_certificate.subject {
                return Err(TrustError::ChainBroken {
                    index: i,
                    expected_issuer: format!("{}", cert.tbs_certificate.issuer),
                    found_subject: format!("{}", issuer_cert.tbs_certificate.subject),
                });
            }

            // Verify signature of cert against issuer's public key
            verify_signature(cert, issuer_cert)?;
        }

        // The last cert in the chain must be issued by a trust anchor
        let last = chain.last().unwrap();

        // Check if the last cert is self-signed and directly in the store
        // (i.e., the chain includes the root itself)
        if last.tbs_certificate.issuer == last.tbs_certificate.subject {
            if self.contains_der(&last.to_der().unwrap_or_default()) {
                // Self-signed cert is directly trusted — verify its self-signature
                verify_signature(last, last)?;
                let anchor = self.find_issuer(last).unwrap(); // must exist since contains_der passed
                return Ok(anchor);
            }
        }

        let anchor = self
            .find_issuer(last)
            .ok_or_else(|| TrustError::UntrustedRoot {
                issuer: format!("{}", last.tbs_certificate.issuer),
            })?;

        // Verify the last certificate's signature against the anchor
        verify_signature(last, anchor)?;

        // Check time validity of the anchor
        if let Some(time) = validation_time {
            let validity = &anchor.tbs_certificate.validity;
            if time < validity.not_before.to_date_time() {
                return Err(TrustError::NotYetValid {
                    index: chain.len(), // anchor
                    not_before: validity.not_before.to_date_time(),
                });
            }
            if time > validity.not_after.to_date_time() {
                return Err(TrustError::Expired {
                    index: chain.len(),
                    not_after: validity.not_after.to_date_time(),
                });
            }
        }

        Ok(anchor)
    }
}

impl Default for TrustStore {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for TrustStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustStore")
            .field("label", &self.label)
            .field("anchors", &self.anchors.len())
            .finish()
    }
}

// ── Signature verification helper ────────────────────────────────────────────

/// Verify the signature on `cert` using `issuer`'s public key.
///
/// Supports RSA PKCS#1 v1.5 (with SHA-256, SHA-384, SHA-512) and
/// ECDSA (P-256 with SHA-256, P-384 with SHA-384).
fn verify_signature(cert: &Certificate, issuer: &Certificate) -> Result<(), TrustError> {
    use const_oid::db;

    // Get the issuer's public key info
    let issuer_spki = &issuer.tbs_certificate.subject_public_key_info;

    // Get the TBS (to-be-signed) bytes and signature from the certificate
    let tbs_bytes = cert
        .tbs_certificate
        .to_der()
        .map_err(|e| TrustError::SignatureVerification(format!("TBS encoding failed: {e}")))?;
    let signature_bytes = cert.signature.raw_bytes();
    let sig_alg_oid = &cert.signature_algorithm.oid;

    // Decode the issuer's SPKI to DER bytes for signature verification
    let spki_der = issuer_spki
        .to_der()
        .map_err(|e| TrustError::SignatureVerification(format!("SPKI encoding failed: {e}")))?;

    // Determine algorithm from OID and verify
    // We re-decode spki_ref for each branch since the key types take ownership.
    if *sig_alg_oid == db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION {
        verify_rsa_signature::<sha2::Sha256>(&tbs_bytes, signature_bytes, &spki_der)
    } else if *sig_alg_oid == db::rfc5912::SHA_384_WITH_RSA_ENCRYPTION {
        verify_rsa_signature::<sha2::Sha384>(&tbs_bytes, signature_bytes, &spki_der)
    } else if *sig_alg_oid == db::rfc5912::SHA_512_WITH_RSA_ENCRYPTION {
        verify_rsa_signature::<sha2::Sha512>(&tbs_bytes, signature_bytes, &spki_der)
    } else if *sig_alg_oid == db::rfc5912::ECDSA_WITH_SHA_256 {
        verify_ecdsa_p256_signature(&tbs_bytes, signature_bytes, &spki_der)
    } else if *sig_alg_oid == db::rfc5912::ECDSA_WITH_SHA_384 {
        verify_ecdsa_p384_signature(&tbs_bytes, signature_bytes, &spki_der)
    } else {
        Err(TrustError::UnsupportedAlgorithm(format!(
            "signature algorithm OID: {sig_alg_oid}"
        )))
    }
}

fn verify_rsa_signature<D: digest::Digest + const_oid::AssociatedOid>(
    tbs: &[u8],
    sig: &[u8],
    spki_der: &[u8],
) -> Result<(), TrustError> {
    use rsa::pkcs1v15::Pkcs1v15Sign;
    use rsa::RsaPublicKey;
    use spki::SubjectPublicKeyInfoRef;

    let spki = SubjectPublicKeyInfoRef::from_der(spki_der)
        .map_err(|e| TrustError::SignatureVerification(format!("SPKI decode failed: {e}")))?;
    let pub_key = RsaPublicKey::try_from(spki)
        .map_err(|e| TrustError::SignatureVerification(format!("RSA key decode failed: {e}")))?;

    let hash = D::digest(tbs);
    let scheme = Pkcs1v15Sign::new::<D>();
    pub_key
        .verify(scheme, &hash, sig)
        .map_err(|e| TrustError::SignatureVerification(format!("RSA signature invalid: {e}")))
}

fn verify_ecdsa_p256_signature(tbs: &[u8], sig: &[u8], spki_der: &[u8]) -> Result<(), TrustError> {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use spki::SubjectPublicKeyInfoRef;

    let spki = SubjectPublicKeyInfoRef::from_der(spki_der)
        .map_err(|e| TrustError::SignatureVerification(format!("SPKI decode failed: {e}")))?;
    let vk = VerifyingKey::try_from(spki)
        .map_err(|e| TrustError::SignatureVerification(format!("P-256 key decode failed: {e}")))?;
    let signature = Signature::from_der(sig)
        .map_err(|e| TrustError::SignatureVerification(format!("P-256 sig decode failed: {e}")))?;

    vk.verify(tbs, &signature)
        .map_err(|e| TrustError::SignatureVerification(format!("ECDSA P-256 invalid: {e}")))
}

fn verify_ecdsa_p384_signature(tbs: &[u8], sig: &[u8], spki_der: &[u8]) -> Result<(), TrustError> {
    use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use spki::SubjectPublicKeyInfoRef;

    let spki = SubjectPublicKeyInfoRef::from_der(spki_der)
        .map_err(|e| TrustError::SignatureVerification(format!("SPKI decode failed: {e}")))?;
    let vk = VerifyingKey::try_from(spki)
        .map_err(|e| TrustError::SignatureVerification(format!("P-384 key decode failed: {e}")))?;
    let signature = Signature::from_der(sig)
        .map_err(|e| TrustError::SignatureVerification(format!("P-384 sig decode failed: {e}")))?;

    vk.verify(tbs, &signature)
        .map_err(|e| TrustError::SignatureVerification(format!("ECDSA P-384 invalid: {e}")))
}
