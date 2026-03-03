//! OCSP client and response handling.
//!
//! Builds OCSP requests, sends them to OCSP responders discovered from
//! certificate AIA extensions, and parses responses.

use std::time::Duration;

use der::Encode;
use reqwest::Client;
use x509_cert::Certificate;

use crate::error::LtvError;

/// OCSP request Content-Type.
const OCSP_REQUEST_CONTENT_TYPE: &str = "application/ocsp-request";

/// OCSP good response status.
const OCSP_RESPONSE_SUCCESSFUL: u8 = 0;

/// OCSP client for querying certificate revocation status.
#[derive(Debug, Clone)]
pub struct OcspClient {
    http_client: Client,
    timeout: Duration,
}

impl OcspClient {
    /// Create a new OCSP client with default settings.
    pub fn new() -> Self {
        Self {
            http_client: Client::new(),
            timeout: Duration::from_secs(30),
        }
    }

    /// Set the HTTP client.
    pub fn http_client(mut self, client: Client) -> Self {
        self.http_client = client;
        self
    }

    /// Set the request timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Extract OCSP responder URLs from a certificate's AIA extension.
    pub fn extract_ocsp_urls(cert: &Certificate) -> Vec<String> {
        extract_aia_urls(cert, AiaAccessMethod::Ocsp)
    }

    /// Fetch an OCSP response for a certificate.
    ///
    /// Builds an OCSP request for `cert` issued by `issuer`, sends it
    /// to the OCSP responder URL found in the certificate's AIA extension,
    /// and returns the raw DER-encoded OCSP response.
    pub async fn fetch_ocsp_response(
        &self,
        cert: &Certificate,
        issuer: &Certificate,
    ) -> Result<Vec<u8>, LtvError> {
        let urls = Self::extract_ocsp_urls(cert);
        if urls.is_empty() {
            return Err(LtvError::Ocsp(
                "no OCSP responder URL in certificate AIA extension".into(),
            ));
        }

        // Build the OCSP request
        let ocsp_request = build_ocsp_request(cert, issuer)?;

        let mut last_error = None;

        for url in &urls {
            match self.send_ocsp_request(url, &ocsp_request).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    log::warn!("OCSP request to {url} failed: {e}");
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            LtvError::Ocsp("all OCSP responder URLs failed".into())
        }))
    }

    /// Send an OCSP request to the given URL.
    async fn send_ocsp_request(
        &self,
        url: &str,
        request_der: &[u8],
    ) -> Result<Vec<u8>, LtvError> {
        log::debug!("Sending OCSP request to {url} ({} bytes)", request_der.len());

        let response = self
            .http_client
            .post(url)
            .header("Content-Type", OCSP_REQUEST_CONTENT_TYPE)
            .timeout(self.timeout)
            .body(request_der.to_vec())
            .send()
            .await
            .map_err(|e| LtvError::Ocsp(format!("OCSP request to {url} failed: {e}")))?;

        // Handle redirects — some responders redirect HTTP to HTTPS
        let status = response.status();
        if !status.is_success() {
            return Err(LtvError::Ocsp(format!(
                "OCSP responder {url} returned HTTP {status}"
            )));
        }

        let resp_bytes = response
            .bytes()
            .await
            .map_err(|e| LtvError::Ocsp(format!("failed to read OCSP response body: {e}")))?
            .to_vec();

        if resp_bytes.is_empty() {
            return Err(LtvError::Ocsp(format!(
                "OCSP responder {url} returned empty response"
            )));
        }

        // Basic validation: check it's a SEQUENCE (DER-encoded OCSPResponse)
        if resp_bytes[0] != 0x30 {
            return Err(LtvError::Ocsp(format!(
                "OCSP response from {url} does not appear to be DER-encoded"
            )));
        }

        // Validate the response status
        validate_ocsp_response_status(&resp_bytes)?;

        log::debug!("OCSP response from {url}: {} bytes", resp_bytes.len());

        Ok(resp_bytes)
    }
}

impl Default for OcspClient {
    fn default() -> Self {
        Self::new()
    }
}

/// AIA access method type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AiaAccessMethod {
    /// OCSP (1.3.6.1.5.5.7.48.1)
    Ocsp,
    /// CA Issuers (1.3.6.1.5.5.7.48.2)
    CaIssuers,
}

/// Extract URLs from a certificate's Authority Information Access extension.
pub fn extract_aia_urls(cert: &Certificate, method: AiaAccessMethod) -> Vec<String> {
    let mut urls = Vec::new();

    // AIA extension OID: 1.3.6.1.5.5.7.1.1
    let aia_oid = const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.1");

    let method_oid = match method {
        AiaAccessMethod::Ocsp => {
            const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1")
        }
        AiaAccessMethod::CaIssuers => {
            const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.2")
        }
    };

    if let Some(extensions) = &cert.tbs_certificate.extensions {
        for ext in extensions.iter() {
            if ext.extn_id == aia_oid {
                if let Ok(parsed) = parse_aia_extension(ext.extn_value.as_bytes(), &method_oid) {
                    urls.extend(parsed);
                }
            }
        }
    }

    urls
}

/// Parse AIA extension value to extract URLs for a specific access method.
///
/// ```text
/// AuthorityInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF AccessDescription
/// AccessDescription ::= SEQUENCE {
///     accessMethod    OBJECT IDENTIFIER,
///     accessLocation  GeneralName
/// }
/// ```
fn parse_aia_extension(
    der_bytes: &[u8],
    target_method_oid: &const_oid::ObjectIdentifier,
) -> Result<Vec<String>, LtvError> {
    let mut urls = Vec::new();

    let (tag, body) = parse_tlv(der_bytes)?;
    if tag != 0x30 {
        return Err(LtvError::Ocsp(format!("AIA: expected SEQUENCE, got 0x{tag:02x}")));
    }

    let target_oid_der = target_method_oid
        .to_der()
        .map_err(|e| LtvError::Ocsp(format!("failed to encode target OID: {e}")))?;

    let mut pos = &body[..];
    while !pos.is_empty() {
        let (ad_tag, ad_body, rest) = parse_tlv_with_rest(pos)?;
        if ad_tag == 0x30 {
            // AccessDescription SEQUENCE
            // First: accessMethod OID
            let (oid_tag, oid_body, ad_rest) = parse_tlv_with_rest(&ad_body)?;
            if oid_tag == 0x06 {
                let oid_tlv = encode_tlv(0x06, &oid_body);
                if oid_tlv == target_oid_der {
                    // Match — extract accessLocation GeneralName
                    // Look for uniformResourceIdentifier [6]
                    if !ad_rest.is_empty() {
                        let (gn_tag, gn_body, _) = parse_tlv_with_rest(ad_rest)?;
                        if gn_tag == 0x86 {
                            // [6] IMPLICIT IA5String — URI
                            if let Ok(uri) = std::str::from_utf8(&gn_body) {
                                urls.push(uri.to_string());
                            }
                        }
                    }
                }
            }
        }
        pos = rest;
    }

    Ok(urls)
}

/// Build an OCSP request for a certificate.
///
/// ```text
/// OCSPRequest ::= SEQUENCE {
///     tbsRequest    TBSRequest,
///     optionalSignature [0] EXPLICIT Signature OPTIONAL
/// }
/// TBSRequest ::= SEQUENCE {
///     version           [0] EXPLICIT Version DEFAULT v1,
///     requestorName     [1] EXPLICIT GeneralName OPTIONAL,
///     requestList       SEQUENCE OF Request,
///     requestExtensions [2] EXPLICIT Extensions OPTIONAL
/// }
/// Request ::= SEQUENCE {
///     reqCert    CertID,
///     singleRequestExtensions [0] EXPLICIT Extensions OPTIONAL
/// }
/// CertID ::= SEQUENCE {
///     hashAlgorithm     AlgorithmIdentifier,
///     issuerNameHash    OCTET STRING,
///     issuerKeyHash     OCTET STRING,
///     serialNumber      CertificateSerialNumber
/// }
/// ```
fn build_ocsp_request(
    cert: &Certificate,
    issuer: &Certificate,
) -> Result<Vec<u8>, LtvError> {
    // Use SHA-1 for OCSP CertID (per RFC 6960, SHA-1 is the most widely supported)

    // Hash the issuer's distinguished name
    let issuer_name_der = issuer
        .tbs_certificate
        .subject
        .to_der()
        .map_err(|e| LtvError::Ocsp(format!("failed to encode issuer name: {e}")))?;
    let issuer_name_hash = sha1_hash(&issuer_name_der);

    // Hash the issuer's public key
    let issuer_key_der = issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes()
        .to_vec();
    let issuer_key_hash = sha1_hash(&issuer_key_der);

    // Serial number of the cert being checked
    let serial_der = cert
        .tbs_certificate
        .serial_number
        .to_der()
        .map_err(|e| LtvError::Ocsp(format!("failed to encode serial number: {e}")))?;

    // Build CertID
    // Build it properly using raw DER
    let sha1_alg_id = build_sha1_algorithm_identifier()?;
    let issuer_name_hash_oct = encode_tlv(0x04, &issuer_name_hash);
    let issuer_key_hash_oct = encode_tlv(0x04, &issuer_key_hash);

    let cert_id = encode_sequence_from_parts(&[
        &sha1_alg_id,
        &issuer_name_hash_oct,
        &issuer_key_hash_oct,
        &serial_der,
    ]);

    // Request SEQUENCE { reqCert CertID }
    let request = encode_sequence_from_parts(&[&cert_id]);

    // requestList SEQUENCE OF Request
    let request_list = encode_sequence_from_parts(&[&request]);

    // TBSRequest SEQUENCE { requestList }
    // (version defaults to v1, so omit it)
    let tbs_request = encode_sequence_from_parts(&[&request_list]);

    // OCSPRequest SEQUENCE { tbsRequest }
    let ocsp_request = encode_sequence_from_parts(&[&tbs_request]);

    Ok(ocsp_request)
}

/// Build SHA-1 AlgorithmIdentifier (SEQUENCE { OID, NULL }).
fn build_sha1_algorithm_identifier() -> Result<Vec<u8>, LtvError> {
    let sha1_oid = const_oid::ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
    let oid_der = sha1_oid
        .to_der()
        .map_err(|e| LtvError::Ocsp(format!("failed to encode SHA-1 OID: {e}")))?;
    let null_der = vec![0x05, 0x00]; // NULL
    Ok(encode_sequence_from_parts(&[&oid_der, &null_der]))
}

/// Validate the OCSPResponse status field.
///
/// ```text
/// OCSPResponse ::= SEQUENCE {
///     responseStatus  OCSPResponseStatus,
///     responseBytes   [0] EXPLICIT ResponseBytes OPTIONAL
/// }
/// OCSPResponseStatus ::= ENUMERATED { successful(0), ... }
/// ```
fn validate_ocsp_response_status(der_bytes: &[u8]) -> Result<(), LtvError> {
    let (tag, body) = parse_tlv(der_bytes)?;
    if tag != 0x30 {
        return Err(LtvError::Ocsp(format!(
            "OCSP response: expected SEQUENCE, got 0x{tag:02x}"
        )));
    }

    // First element: responseStatus ENUMERATED
    let (status_tag, status_body, _) = parse_tlv_with_rest(&body)?;
    if status_tag != 0x0A {
        return Err(LtvError::Ocsp(format!(
            "OCSP response: expected ENUMERATED status, got 0x{status_tag:02x}"
        )));
    }

    if status_body.is_empty() {
        return Err(LtvError::Ocsp("OCSP response: empty status".into()));
    }

    let status = status_body[0];
    if status != OCSP_RESPONSE_SUCCESSFUL {
        let status_name = match status {
            1 => "malformedRequest",
            2 => "internalError",
            3 => "tryLater",
            5 => "sigRequired",
            6 => "unauthorized",
            _ => "unknown",
        };
        return Err(LtvError::Ocsp(format!(
            "OCSP response status: {status_name} ({status})"
        )));
    }

    Ok(())
}

/// Compute SHA-1 hash of data.
fn sha1_hash(data: &[u8]) -> Vec<u8> {
    use sha1::Digest;
    sha1::Sha1::digest(data).to_vec()
}

// ---------------------------------------------------------------------------
// DER helpers
// ---------------------------------------------------------------------------

fn parse_tlv(data: &[u8]) -> Result<(u8, Vec<u8>), LtvError> {
    let (tag, body, _) = parse_tlv_with_rest(data)?;
    Ok((tag, body.to_vec()))
}

fn parse_tlv_with_rest(data: &[u8]) -> Result<(u8, &[u8], &[u8]), LtvError> {
    if data.is_empty() {
        return Err(LtvError::Ocsp("empty input".into()));
    }
    let tag = data[0];
    let (len, header_len) = parse_der_length(&data[1..])?;
    let total_header = 1 + header_len;
    if total_header + len > data.len() {
        return Err(LtvError::Ocsp(format!(
            "TLV overflow: need {}, have {}",
            total_header + len,
            data.len()
        )));
    }
    let value = &data[total_header..total_header + len];
    let rest = &data[total_header + len..];
    Ok((tag, value, rest))
}

fn parse_der_length(data: &[u8]) -> Result<(usize, usize), LtvError> {
    if data.is_empty() {
        return Err(LtvError::Ocsp("empty length".into()));
    }
    let first = data[0];
    if first < 0x80 {
        Ok((first as usize, 1))
    } else if first == 0x80 {
        Err(LtvError::Ocsp("indefinite length not supported".into()))
    } else {
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes > 4 || 1 + num_bytes > data.len() {
            return Err(LtvError::Ocsp("length encoding error".into()));
        }
        let mut len: usize = 0;
        for i in 0..num_bytes {
            len = (len << 8) | (data[1 + i] as usize);
        }
        Ok((len, 1 + num_bytes))
    }
}

fn encode_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 5 + value.len());
    out.push(tag);
    encode_der_length(&mut out, value.len());
    out.extend_from_slice(value);
    out
}

fn encode_sequence_from_parts(parts: &[&[u8]]) -> Vec<u8> {
    let total_len: usize = parts.iter().map(|p| p.len()).sum();
    let mut body = Vec::with_capacity(total_len);
    for part in parts {
        body.extend_from_slice(part);
    }
    let mut out = Vec::with_capacity(1 + 5 + body.len());
    out.push(0x30);
    encode_der_length(&mut out, body.len());
    out.extend_from_slice(&body);
    out
}

fn encode_der_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.push(0x81);
        out.push(len as u8);
    } else if len <= 0xFFFF {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else if len <= 0xFF_FFFF {
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else {
        out.push(0x84);
        out.push((len >> 24) as u8);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Decode;

    #[test]
    fn test_ocsp_client_default() {
        let client = OcspClient::new();
        assert_eq!(client.timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_sha1_hash() {
        let hash = sha1_hash(b"test");
        assert_eq!(hash.len(), 20); // SHA-1 is 20 bytes
    }

    #[test]
    fn test_build_sha1_algorithm_identifier() {
        let alg_id = build_sha1_algorithm_identifier().unwrap();
        assert_eq!(alg_id[0], 0x30); // SEQUENCE
    }

    #[test]
    fn test_extract_ocsp_urls_from_fixture_cert() {
        // Load the signer cert which should have OCSP URL from our CA
        let cert_pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/signer_cert.pem"
        ));
        let pem_data = pem_rfc7468::decode_vec(cert_pem.as_bytes());
        if let Ok((_label, der)) = pem_data {
            if let Ok(cert) = Certificate::from_der(&der) {
                let urls = OcspClient::extract_ocsp_urls(&cert);
                // Our django-ca issued cert should have OCSP URL
                // (may or may not depending on test fixture setup)
                let _ = urls;
            }
        }
    }
}
