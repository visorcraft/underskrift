//! Detached CAdES (ETSI EN 319 122-1) construction and qualifying properties.
//!
//! This builds standalone detached CAdES signatures — independent of PDF — and
//! the unsigned-attribute layer that upgrades a baseline signature to higher
//! conformance levels:
//!
//! - **CAdES-B-B**: [`sign_detached`] — a detached `SignedData` over external
//!   content, with content-type, message-digest, signing-certificate-v2 and
//!   signing-time signed attributes.
//! - **CAdES-B-T**: attach a [`signature_timestamp_attr`] (RFC 3161 token over
//!   the signature value) via [`add_unsigned_attributes`].
//! - **CAdES-B-LT**: attach [`certificate_values_attr`] and
//!   [`revocation_values_attr`] (the certs/OCSP/CRLs needed to validate the
//!   signature long-term) via [`add_unsigned_attributes`].
//!
//! CAdES-B-LTA (archive-timestamp-v3 with `ats-hash-index-v3`) is intentionally
//! not implemented here yet; it is the most intricate part of the format and is
//! tracked as follow-on work.
//!
//! The [`signature_value`] helper returns the bytes a caller must timestamp to
//! produce the B-T signature timestamp.

use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerInfo, SignerInfos};
use const_oid::db::rfc5911;
use const_oid::ObjectIdentifier;
use der::asn1::SetOfVec;
use der::{Any, Decode, Encode};
use x509_cert::attr::{Attribute, AttributeValue};

use crate::crypto::traits::CryptoSigner;
use crate::error::CmsError;

use super::builder::{CmsProfile, PdfCmsBuilder};

/// `id-aa-signatureTimeStampToken`: `1.2.840.113549.1.9.16.2.14`.
const OID_AA_SIGNATURE_TIME_STAMP_TOKEN: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");
/// `id-aa-ets-certValues`: `1.2.840.113549.1.9.16.2.23`.
const OID_AA_ETS_CERT_VALUES: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.23");
/// `id-aa-ets-revocationValues`: `1.2.840.113549.1.9.16.2.24`.
const OID_AA_ETS_REVOCATION_VALUES: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.24");

// --- minimal DER helpers (constructed types only) --------------------------

fn der_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else {
        let mut bytes = len.to_be_bytes().to_vec();
        while bytes.first() == Some(&0) {
            bytes.remove(0);
        }
        let mut out = vec![0x80 | bytes.len() as u8];
        out.extend_from_slice(&bytes);
        out
    }
}

/// Tag-length-value with an explicit tag byte over already-encoded `content`.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + content.len() + 4);
    out.push(tag);
    out.extend_from_slice(&der_length(content.len()));
    out.extend_from_slice(content);
    out
}

/// SEQUENCE (tag 0x30) over the concatenation of `items`.
fn sequence(items: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &items.concat())
}

/// IMPLICIT `[n]` constructed context tag (0xA0 | n) over `content`.
fn implicit_context(n: u8, content: &[u8]) -> Vec<u8> {
    tlv(0xA0 | n, content)
}

// --- CAdES-B-B -------------------------------------------------------------

/// Produce a detached CAdES-B-B signature over `content`.
///
/// The content is hashed with the signer's configured digest algorithm and
/// placed in the `messageDigest` signed attribute; the `SignedData` is detached
/// (no encapsulated content). `signing_time`, when provided, is included as the
/// `signingTime` signed attribute (recommended for CAdES baseline).
///
/// Returns the DER-encoded `ContentInfo` wrapping the `SignedData`.
pub fn sign_detached(
    content: &[u8],
    signer: &dyn CryptoSigner,
    signing_time: Option<chrono::NaiveDateTime>,
) -> Result<Vec<u8>, CmsError> {
    let data_hash = signer.digest_algorithm().digest(content);
    let mut builder = PdfCmsBuilder::new(signer).profile(CmsProfile::Cades);
    if let Some(t) = signing_time {
        builder = builder.signing_time(t);
    }
    builder.build(&data_hash)
}

// --- unsigned-attribute builders -------------------------------------------

fn single_value_attr(oid: ObjectIdentifier, value_der: &[u8]) -> Result<Attribute, CmsError> {
    let value = AttributeValue::from_der(value_der)
        .map_err(|e| CmsError::Der(format!("attribute value parse: {e}")))?;
    let mut values = SetOfVec::new();
    values
        .insert(value)
        .map_err(|e| CmsError::Builder(format!("insert attribute value: {e}")))?;
    Ok(Attribute { oid, values })
}

/// Build the `signature-time-stamp-token` unsigned attribute (CAdES-B-T).
///
/// `tst_der` is the DER of the RFC 3161 timestamp token (a CMS `ContentInfo`),
/// computed by a TSA over the signature value (see [`signature_value`]).
pub fn signature_timestamp_attr(tst_der: &[u8]) -> Result<Attribute, CmsError> {
    // The attribute value is the timestamp token (a ContentInfo) verbatim.
    single_value_attr(OID_AA_SIGNATURE_TIME_STAMP_TOKEN, tst_der)
}

/// Build the `certificate-values` unsigned attribute (CAdES-B-LT).
///
/// `certs_der` are the DER-encoded X.509 certificates needed to validate the
/// signature (the chain beyond what is already embedded in `SignedData.certificates`).
///
/// ```text
/// CertificateValues ::= SEQUENCE OF Certificate
/// ```
pub fn certificate_values_attr(certs_der: &[&[u8]]) -> Result<Attribute, CmsError> {
    // Validate each entry is a parseable certificate before embedding.
    for der in certs_der {
        x509_cert::Certificate::from_der(der)
            .map_err(|e| CmsError::Der(format!("certificate-values entry parse: {e}")))?;
    }
    let items: Vec<Vec<u8>> = certs_der.iter().map(|c| c.to_vec()).collect();
    let seq = sequence(&items);
    single_value_attr(OID_AA_ETS_CERT_VALUES, &seq)
}

/// Build the `revocation-values` unsigned attribute (CAdES-B-LT).
///
/// `crls_der` are DER-encoded `CertificateList`s; `ocsp_basic_der` are
/// DER-encoded `BasicOCSPResponse`s (the inner response, not the OCSP response
/// wrapper). Either list may be empty.
///
/// ```text
/// RevocationValues ::= SEQUENCE {
///   crlVals  [0] SEQUENCE OF CertificateList    OPTIONAL,
///   ocspVals [1] SEQUENCE OF BasicOCSPResponse  OPTIONAL,
///   otherRevVals [2] OtherRevVals               OPTIONAL }
/// ```
pub fn revocation_values_attr(
    crls_der: &[&[u8]],
    ocsp_basic_der: &[&[u8]],
) -> Result<Attribute, CmsError> {
    let mut fields: Vec<Vec<u8>> = Vec::new();
    if !crls_der.is_empty() {
        let items: Vec<Vec<u8>> = crls_der.iter().map(|c| c.to_vec()).collect();
        // [0] IMPLICIT SEQUENCE OF CertificateList
        fields.push(implicit_context(0, &items.concat()));
    }
    if !ocsp_basic_der.is_empty() {
        let items: Vec<Vec<u8>> = ocsp_basic_der.iter().map(|c| c.to_vec()).collect();
        // [1] IMPLICIT SEQUENCE OF BasicOCSPResponse
        fields.push(implicit_context(1, &items.concat()));
    }
    let seq = sequence(&fields);
    single_value_attr(OID_AA_ETS_REVOCATION_VALUES, &seq)
}

// --- composition over an existing CMS --------------------------------------

/// Return the signature value (the `SignerInfo.signature` octets) from a
/// detached CMS. This is the data a TSA must timestamp to produce the B-T
/// signature timestamp (the caller hashes these bytes and sends the digest).
pub fn signature_value(cms_der: &[u8]) -> Result<Vec<u8>, CmsError> {
    let signed_data = parse_signed_data(cms_der)?;
    let infos: Vec<&SignerInfo> = signed_data.signer_infos.0.iter().collect();
    let si = exactly_one(&infos)?;
    Ok(si.signature.as_bytes().to_vec())
}

/// Add unsigned attributes to the single `SignerInfo` of a detached CMS,
/// preserving any already present, and re-encode the `ContentInfo`.
///
/// This is the composition primitive used to upgrade B-B → B-T (add a
/// signature timestamp) and B-T → B-LT (add certificate/revocation values).
pub fn add_unsigned_attributes(
    cms_der: &[u8],
    new_attrs: Vec<Attribute>,
) -> Result<Vec<u8>, CmsError> {
    let mut signed_data = parse_signed_data(cms_der)?;

    let mut infos: Vec<SignerInfo> = signed_data.signer_infos.0.iter().cloned().collect();
    if infos.len() != 1 {
        return Err(CmsError::Builder(format!(
            "expected exactly one SignerInfo, found {}",
            infos.len()
        )));
    }

    let mut merged: Vec<Attribute> = infos[0]
        .unsigned_attrs
        .as_ref()
        .map(|s| s.iter().cloned().collect())
        .unwrap_or_default();
    merged.extend(new_attrs);
    infos[0].unsigned_attrs = Some(
        SetOfVec::try_from(merged)
            .map_err(|e| CmsError::Builder(format!("rebuild unsigned attrs: {e}")))?,
    );

    signed_data.signer_infos = SignerInfos(
        SetOfVec::try_from(infos)
            .map_err(|e| CmsError::Builder(format!("rebuild signer infos: {e}")))?,
    );

    let sd_der = signed_data
        .to_der()
        .map_err(|e| CmsError::Der(format!("re-encode SignedData: {e}")))?;
    let content =
        Any::from_der(&sd_der).map_err(|e| CmsError::Der(format!("re-wrap SignedData: {e}")))?;
    let content_info = ContentInfo {
        content_type: rfc5911::ID_SIGNED_DATA,
        content,
    };
    content_info
        .to_der()
        .map_err(|e| CmsError::Der(format!("re-encode ContentInfo: {e}")))
}

fn parse_signed_data(cms_der: &[u8]) -> Result<SignedData, CmsError> {
    let ci = ContentInfo::from_der(cms_der)
        .map_err(|e| CmsError::Der(format!("parse ContentInfo: {e}")))?;
    if ci.content_type != rfc5911::ID_SIGNED_DATA {
        return Err(CmsError::Builder("not a SignedData ContentInfo".into()));
    }
    let sd_der = ci
        .content
        .to_der()
        .map_err(|e| CmsError::Der(format!("extract SignedData: {e}")))?;
    SignedData::from_der(&sd_der).map_err(|e| CmsError::Der(format!("parse SignedData: {e}")))
}

fn exactly_one<'a>(infos: &'a [&'a SignerInfo]) -> Result<&'a SignerInfo, CmsError> {
    match infos {
        [one] => Ok(one),
        _ => Err(CmsError::Builder(format!(
            "expected exactly one SignerInfo, found {}",
            infos.len()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::software::SoftwareSigner;

    fn signer() -> SoftwareSigner {
        let p12 = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/signer.p12");
        SoftwareSigner::from_pkcs12_file(p12, "test123").expect("load signer")
    }

    #[test]
    fn detached_cades_bb_is_wellformed_and_has_unsigned_attr_slot() {
        let content = b"hello cades world";
        let cms = sign_detached(content, &signer(), None).expect("sign detached");

        // It parses as a SignedData ContentInfo with exactly one SignerInfo.
        let sd = parse_signed_data(&cms).expect("parse");
        assert_eq!(sd.signer_infos.0.len(), 1);
        // Detached: no encapsulated content.
        assert!(sd.encap_content_info.econtent.is_none());
        // The signature value is retrievable for timestamping.
        let sigval = signature_value(&cms).expect("sig value");
        assert!(!sigval.is_empty());
    }

    #[test]
    fn add_certificate_and_revocation_values_roundtrips() {
        let cms = sign_detached(b"data", &signer(), None).expect("sign");

        let signer_cert = signer().certificate_der().to_vec();
        let cert_attr = certificate_values_attr(&[&signer_cert]).expect("cert values");
        let rev_attr = revocation_values_attr(&[], &[b"fake-basic-ocsp"]).expect("rev values");

        let upgraded =
            add_unsigned_attributes(&cms, vec![cert_attr, rev_attr]).expect("add unsigned");

        // Re-parse and confirm the unsigned attributes are present with the
        // right OIDs, and the signature value is unchanged (B-LT does not
        // re-sign).
        let sd = parse_signed_data(&upgraded).expect("parse upgraded");
        let si = sd.signer_infos.0.iter().next().unwrap();
        let unsigned = si.unsigned_attrs.as_ref().expect("unsigned attrs present");
        let oids: Vec<_> = unsigned.iter().map(|a| a.oid).collect();
        assert!(oids.contains(&OID_AA_ETS_CERT_VALUES));
        assert!(oids.contains(&OID_AA_ETS_REVOCATION_VALUES));

        assert_eq!(
            signature_value(&cms).unwrap(),
            signature_value(&upgraded).unwrap(),
            "adding validation data must not change the signature"
        );
    }

    #[cfg(feature = "verify")]
    #[test]
    fn detached_cades_bb_verifies_cryptographically() {
        let content = b"the quick brown fox";
        let s = signer();
        let cms = sign_detached(content, &s, None).expect("sign");

        let data_hash = s.digest_algorithm().digest(content);
        let result = crate::verify::cms_verify::verify_cms(&cms, &data_hash).expect("verify");
        assert!(result.signature_valid, "issues: {:?}", result.issues);
        assert!(
            result.digest_matches,
            "messageDigest must match content hash"
        );
        // CAdES baseline carries signingCertificateV2.
        assert_eq!(result.ess_cert_id_match, Some(true));
    }

    #[cfg(feature = "verify")]
    #[test]
    fn b_t_signature_timestamp_is_surfaced_by_verifier() {
        let s = signer();
        let cms = sign_detached(b"content", &s, None).expect("sign");
        // Embed a placeholder signature-timestamp token (verifier exposes it raw).
        let fake_tst = der::asn1::OctetString::new(vec![9, 9, 9])
            .unwrap()
            .to_der()
            .unwrap();
        let bt = add_unsigned_attributes(&cms, vec![signature_timestamp_attr(&fake_tst).unwrap()])
            .expect("add ts");

        let data_hash = s.digest_algorithm().digest(b"content");
        let result = crate::verify::cms_verify::verify_cms(&bt, &data_hash).expect("verify");
        assert!(result.signature_valid, "issues: {:?}", result.issues);
        assert_eq!(
            result.signature_timestamp_token.as_deref(),
            Some(fake_tst.as_slice()),
            "verifier must surface the embedded signature timestamp token"
        );
    }

    #[test]
    fn signature_timestamp_attr_wraps_token() {
        // A syntactically-valid placeholder token (any DER) is embedded verbatim.
        let fake_tst = der::asn1::OctetString::new(vec![1, 2, 3, 4])
            .unwrap()
            .to_der()
            .unwrap();
        let attr = signature_timestamp_attr(&fake_tst).expect("ts attr");
        assert_eq!(attr.oid, OID_AA_SIGNATURE_TIME_STAMP_TOKEN);

        let cms = sign_detached(b"x", &signer(), None).expect("sign");
        let bt = add_unsigned_attributes(&cms, vec![attr]).expect("add ts");
        let sd = parse_signed_data(&bt).expect("parse");
        let si = sd.signer_infos.0.iter().next().unwrap();
        assert!(si
            .unsigned_attrs
            .as_ref()
            .unwrap()
            .iter()
            .any(|a| a.oid == OID_AA_SIGNATURE_TIME_STAMP_TOKEN));
    }
}
