//! CMS SignedData cryptographic verification.
//!
//! Parses a CMS `SignedData` structure (RFC 5652) from a PDF signature's
//! `/Contents` value, verifies the cryptographic signature over the signed
//! attributes, and checks that the `messageDigest` attribute matches the
//! hash of the PDF byte ranges.

use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier, SignerInfo};
use const_oid::db::rfc5911;
use const_oid::db::rfc5912;
use der::asn1::OctetString;
use der::{Decode, Encode};
use x509_cert::Certificate;

use crate::crypto::algorithm::DigestAlgorithm;
use crate::error::VerifyError;

/// Result of CMS cryptographic verification.
#[derive(Debug)]
pub struct CmsVerifyResult {
    /// Whether the CMS signature is cryptographically valid
    pub signature_valid: bool,
    /// Whether the messageDigest attribute matches the provided data hash
    pub digest_matches: bool,
    /// The signer's certificate extracted from the CMS certificates set
    pub signer_certificate: Option<Certificate>,
    /// All certificates embedded in the CMS structure (for chain building)
    pub embedded_certificates: Vec<Certificate>,
    /// The digest algorithm used
    pub digest_algorithm: Option<DigestAlgorithm>,
    /// Human-readable issues
    pub issues: Vec<String>,
}

/// Verify a CMS SignedData structure against the provided data hash.
///
/// This performs the core cryptographic verification per RFC 5652 §5.6:
/// 1. Parse the DER-encoded ContentInfo/SignedData
/// 2. Extract the signer info (first signer — PDF signatures have exactly one)
/// 3. Extract the messageDigest signed attribute and compare to `data_hash`
/// 4. Re-encode the signed attributes as a SET OF for signature verification
/// 5. Verify the signature over the signed attributes using the signer's public key
///
/// `cms_bytes` is the raw DER from the PDF /Contents field.
/// `data_hash` is the hash of the byte-range-selected PDF data.
pub fn verify_cms(cms_bytes: &[u8], data_hash: &[u8]) -> Result<CmsVerifyResult, VerifyError> {
    let mut issues = Vec::new();

    // Step 1: Parse ContentInfo
    let content_info = ContentInfo::from_der(cms_bytes).map_err(|e| {
        VerifyError::CmsVerification(format!("failed to parse CMS ContentInfo: {e}"))
    })?;

    if content_info.content_type != rfc5911::ID_SIGNED_DATA {
        return Err(VerifyError::CmsVerification(format!(
            "unexpected content type: {} (expected signedData)",
            content_info.content_type
        )));
    }

    // Step 2: Parse SignedData
    let sd_bytes = content_info.content.to_der().map_err(|e| {
        VerifyError::CmsVerification(format!("failed to re-encode SignedData content: {e}"))
    })?;
    let signed_data = SignedData::from_der(&sd_bytes)
        .map_err(|e| VerifyError::CmsVerification(format!("failed to parse SignedData: {e}")))?;

    // Step 3: Extract all embedded certificates
    let embedded_certificates = extract_certificates(&signed_data);

    // Step 4: Get the first (and typically only) SignerInfo
    let signer_infos: Vec<&SignerInfo> = signed_data.signer_infos.0.iter().collect();
    if signer_infos.is_empty() {
        return Err(VerifyError::CmsVerification(
            "no signer infos in SignedData".to_string(),
        ));
    }
    if signer_infos.len() > 1 {
        issues.push(format!(
            "multiple signer infos found ({}); using first",
            signer_infos.len()
        ));
    }
    let signer_info = signer_infos[0];

    // Step 5: Determine digest algorithm from SignerInfo
    let digest_algorithm = oid_to_digest_algorithm(&signer_info.digest_alg.oid);

    // Step 6: Find the signer's certificate
    let signer_certificate = find_signer_certificate(signer_info, &embedded_certificates);
    if signer_certificate.is_none() {
        issues.push("signer certificate not found in embedded certificates".to_string());
    }

    // Step 7: Check messageDigest attribute
    let digest_matches = match extract_message_digest(signer_info) {
        Some(cms_digest) => {
            if cms_digest == data_hash {
                true
            } else {
                issues.push("messageDigest does not match data hash".to_string());
                false
            }
        }
        None => {
            issues.push("messageDigest attribute not found in signed attributes".to_string());
            false
        }
    };

    // Step 8: Verify the cryptographic signature
    let signature_valid = if let Some(ref cert) = signer_certificate {
        match verify_signer_info_signature(signer_info, cert) {
            Ok(()) => true,
            Err(e) => {
                issues.push(format!("signature verification failed: {e}"));
                false
            }
        }
    } else {
        issues.push("cannot verify signature: signer certificate not found".to_string());
        false
    };

    Ok(CmsVerifyResult {
        signature_valid,
        digest_matches,
        signer_certificate,
        embedded_certificates,
        digest_algorithm,
        issues,
    })
}

/// Extract all certificates from a SignedData's certificate set.
fn extract_certificates(signed_data: &SignedData) -> Vec<Certificate> {
    let mut certs = Vec::new();
    if let Some(ref cert_set) = signed_data.certificates {
        for choice in cert_set.0.iter() {
            if let cms::cert::CertificateChoices::Certificate(cert) = choice {
                certs.push(cert.clone());
            }
        }
    }
    certs
}

/// Find the signer's certificate by matching the SignerIdentifier.
fn find_signer_certificate(
    signer_info: &SignerInfo,
    certificates: &[Certificate],
) -> Option<Certificate> {
    match &signer_info.sid {
        SignerIdentifier::IssuerAndSerialNumber(ias) => certificates
            .iter()
            .find(|cert| {
                cert.tbs_certificate.issuer == ias.issuer
                    && cert.tbs_certificate.serial_number == ias.serial_number
            })
            .cloned(),
        SignerIdentifier::SubjectKeyIdentifier(ski) => {
            // Find by Subject Key Identifier extension
            certificates
                .iter()
                .find(|cert| {
                    if let Some(ref extensions) = cert.tbs_certificate.extensions {
                        for ext in extensions.iter() {
                            if ext.extn_id == const_oid::db::rfc5912::ID_CE_SUBJECT_KEY_IDENTIFIER {
                                if let Ok(ski_val) =
                                    OctetString::from_der(ext.extn_value.as_bytes())
                                {
                                    return ski_val.as_bytes() == ski.0.as_bytes();
                                }
                            }
                        }
                    }
                    false
                })
                .cloned()
        }
    }
}

/// Extract the messageDigest value from signed attributes.
fn extract_message_digest(signer_info: &SignerInfo) -> Option<Vec<u8>> {
    let signed_attrs = signer_info.signed_attrs.as_ref()?;
    for attr in signed_attrs.iter() {
        if attr.oid == rfc5911::ID_MESSAGE_DIGEST {
            // The attribute value is an OCTET STRING
            if let Some(value) = attr.values.iter().next() {
                let value_der = value.to_der().ok()?;
                let octet_string = OctetString::from_der(&value_der).ok()?;
                return Some(octet_string.as_bytes().to_vec());
            }
        }
    }
    None
}

/// Verify the cryptographic signature in a SignerInfo against the signer's certificate.
///
/// Per RFC 5652 §5.4: The signature is computed over the DER-encoded
/// signed attributes, re-encoded as a SET OF (tag 0x31).
fn verify_signer_info_signature(
    signer_info: &SignerInfo,
    signer_cert: &Certificate,
) -> Result<(), VerifyError> {
    // Get the signed attributes DER
    let signed_attrs = signer_info.signed_attrs.as_ref().ok_or_else(|| {
        VerifyError::CmsVerification("no signed attributes in signer info".to_string())
    })?;

    // Encode the signed attributes as SET OF for signature verification.
    // The cms crate stores them internally as IMPLICIT [0], but to_der()
    // on SetOfVec<Attribute> produces a SET OF (tag 0x31) encoding.
    let attrs_der = signed_attrs.to_der().map_err(|e| {
        VerifyError::CmsVerification(format!("failed to DER-encode signed attributes: {e}"))
    })?;

    // The signed_attrs from the cms crate's SignerInfo are stored with
    // IMPLICIT [0] tag (0xA0). We need to re-encode them as SET OF (0x31)
    // for signature verification per RFC 5652 §5.4.
    let attrs_bytes = if !attrs_der.is_empty() && attrs_der[0] == 0xA0 {
        // Replace the tag byte
        let mut fixed = attrs_der.clone();
        fixed[0] = 0x31;
        fixed
    } else {
        // Already has SET OF tag or some other encoding
        attrs_der
    };

    // Get signature algorithm OID
    let sig_alg_oid = &signer_info.signature_algorithm.oid;

    // Get the signer's public key
    let spki = &signer_cert.tbs_certificate.subject_public_key_info;
    let spki_der = spki
        .to_der()
        .map_err(|e| VerifyError::CmsVerification(format!("failed to encode signer SPKI: {e}")))?;

    // Get the raw signature bytes
    let signature_bytes = signer_info.signature.as_bytes();

    // Verify using the appropriate algorithm
    verify_cms_signature(sig_alg_oid, &attrs_bytes, signature_bytes, &spki_der)
}

/// Verify a CMS signature given the algorithm OID, data, signature, and public key.
fn verify_cms_signature(
    sig_alg_oid: &const_oid::ObjectIdentifier,
    data: &[u8],
    signature: &[u8],
    spki_der: &[u8],
) -> Result<(), VerifyError> {
    use const_oid::db;

    if *sig_alg_oid == db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION {
        verify_rsa_cms::<sha2::Sha256>(data, signature, spki_der)
    } else if *sig_alg_oid == db::rfc5912::SHA_384_WITH_RSA_ENCRYPTION {
        verify_rsa_cms::<sha2::Sha384>(data, signature, spki_der)
    } else if *sig_alg_oid == db::rfc5912::SHA_512_WITH_RSA_ENCRYPTION {
        verify_rsa_cms::<sha2::Sha512>(data, signature, spki_der)
    } else if *sig_alg_oid == db::rfc5912::ECDSA_WITH_SHA_256 {
        verify_ecdsa_p256_cms(data, signature, spki_der)
    } else if *sig_alg_oid == db::rfc5912::ECDSA_WITH_SHA_384 {
        verify_ecdsa_p384_cms(data, signature, spki_der)
    } else {
        Err(VerifyError::CmsVerification(format!(
            "unsupported signature algorithm: {sig_alg_oid}"
        )))
    }
}

fn verify_rsa_cms<D: digest::Digest + const_oid::AssociatedOid>(
    data: &[u8],
    signature: &[u8],
    spki_der: &[u8],
) -> Result<(), VerifyError> {
    use rsa::pkcs1v15::Pkcs1v15Sign;
    use rsa::RsaPublicKey;
    use spki::SubjectPublicKeyInfoRef;

    let spki = SubjectPublicKeyInfoRef::from_der(spki_der)
        .map_err(|e| VerifyError::CmsVerification(format!("SPKI decode failed: {e}")))?;
    let pub_key = RsaPublicKey::try_from(spki)
        .map_err(|e| VerifyError::CmsVerification(format!("RSA key decode failed: {e}")))?;

    let hash = D::digest(data);
    let scheme = Pkcs1v15Sign::new::<D>();
    pub_key
        .verify(scheme, &hash, signature)
        .map_err(|e| VerifyError::CmsVerification(format!("RSA signature invalid: {e}")))
}

fn verify_ecdsa_p256_cms(
    data: &[u8],
    signature: &[u8],
    spki_der: &[u8],
) -> Result<(), VerifyError> {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use spki::SubjectPublicKeyInfoRef;

    let spki = SubjectPublicKeyInfoRef::from_der(spki_der)
        .map_err(|e| VerifyError::CmsVerification(format!("SPKI decode failed: {e}")))?;
    let vk = VerifyingKey::try_from(spki)
        .map_err(|e| VerifyError::CmsVerification(format!("P-256 key decode failed: {e}")))?;
    let sig = Signature::from_der(signature)
        .map_err(|e| VerifyError::CmsVerification(format!("P-256 signature decode failed: {e}")))?;

    vk.verify(data, &sig)
        .map_err(|e| VerifyError::CmsVerification(format!("ECDSA P-256 invalid: {e}")))
}

fn verify_ecdsa_p384_cms(
    data: &[u8],
    signature: &[u8],
    spki_der: &[u8],
) -> Result<(), VerifyError> {
    use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use spki::SubjectPublicKeyInfoRef;

    let spki = SubjectPublicKeyInfoRef::from_der(spki_der)
        .map_err(|e| VerifyError::CmsVerification(format!("SPKI decode failed: {e}")))?;
    let vk = VerifyingKey::try_from(spki)
        .map_err(|e| VerifyError::CmsVerification(format!("P-384 key decode failed: {e}")))?;
    let sig = Signature::from_der(signature)
        .map_err(|e| VerifyError::CmsVerification(format!("P-384 signature decode failed: {e}")))?;

    vk.verify(data, &sig)
        .map_err(|e| VerifyError::CmsVerification(format!("ECDSA P-384 invalid: {e}")))
}

/// Map an OID to our DigestAlgorithm enum.
fn oid_to_digest_algorithm(oid: &const_oid::ObjectIdentifier) -> Option<DigestAlgorithm> {
    if *oid == rfc5912::ID_SHA_256 {
        Some(DigestAlgorithm::Sha256)
    } else if *oid == rfc5912::ID_SHA_384 {
        Some(DigestAlgorithm::Sha384)
    } else if *oid == rfc5912::ID_SHA_512 {
        Some(DigestAlgorithm::Sha512)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oid_to_digest_algorithm() {
        assert_eq!(
            oid_to_digest_algorithm(&rfc5912::ID_SHA_256),
            Some(DigestAlgorithm::Sha256)
        );
        assert_eq!(
            oid_to_digest_algorithm(&rfc5912::ID_SHA_384),
            Some(DigestAlgorithm::Sha384)
        );
        assert_eq!(
            oid_to_digest_algorithm(&rfc5912::ID_SHA_512),
            Some(DigestAlgorithm::Sha512)
        );
        // Unknown OID
        assert_eq!(
            oid_to_digest_algorithm(&const_oid::ObjectIdentifier::new_unwrap("1.2.3.4.5")),
            None
        );
    }
}
