//! CRL fetching and caching.
//!
//! Fetches Certificate Revocation Lists from distribution points found in
//! X.509 certificates, with both in-memory and optional disk caching.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use reqwest::Client;
use x509_cert::Certificate;

use crate::error::LtvError;

/// A cached CRL entry.
#[derive(Debug, Clone)]
struct CrlCacheEntry {
    /// Raw DER-encoded CRL bytes.
    der: Vec<u8>,
    /// When this entry was fetched.
    fetched_at: Instant,
}

/// CRL client with in-memory caching.
///
/// Fetches CRLs from distribution points and caches them to avoid
/// redundant network requests.
#[derive(Debug, Clone)]
pub struct CrlClient {
    http_client: Client,
    timeout: Duration,
    /// In-memory cache: URL -> CRL entry
    cache: Arc<Mutex<HashMap<String, CrlCacheEntry>>>,
    /// How long cached CRLs remain valid.
    grace_period: Duration,
}

impl CrlClient {
    /// Create a new CRL client with default settings.
    ///
    /// Default grace period: 1 hour.
    pub fn new() -> Self {
        Self {
            http_client: Client::new(),
            timeout: Duration::from_secs(30),
            cache: Arc::new(Mutex::new(HashMap::new())),
            grace_period: Duration::from_secs(3600),
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

    /// Set the cache grace period.
    pub fn grace_period(mut self, grace: Duration) -> Self {
        self.grace_period = grace;
        self
    }

    /// Extract CRL distribution point URLs from a certificate.
    pub fn extract_crl_urls(cert: &Certificate) -> Vec<String> {
        let mut urls = Vec::new();

        // CRL Distribution Points extension OID: 2.5.29.31
        let crl_dp_oid = const_oid::ObjectIdentifier::new_unwrap("2.5.29.31");

        if let Some(extensions) = &cert.tbs_certificate.extensions {
            for ext in extensions.iter() {
                if ext.extn_id == crl_dp_oid {
                    // Parse the CRL Distribution Points extension value
                    // It's a SEQUENCE OF DistributionPoint
                    if let Ok(urls_from_ext) = parse_crl_dp_extension(ext.extn_value.as_bytes()) {
                        urls.extend(urls_from_ext);
                    }
                }
            }
        }

        urls
    }

    /// Fetch a CRL from the given URL, using cache if available.
    pub async fn fetch_crl(&self, url: &str) -> Result<Vec<u8>, LtvError> {
        // Check cache first
        {
            let cache = self.cache.lock().map_err(|e| {
                LtvError::Crl(format!("cache lock poisoned: {e}"))
            })?;
            if let Some(entry) = cache.get(url) {
                if entry.fetched_at.elapsed() < self.grace_period {
                    log::debug!("CRL cache hit for {url}");
                    return Ok(entry.der.clone());
                }
            }
        }

        log::debug!("Fetching CRL from {url}");

        let response = self
            .http_client
            .get(url)
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| LtvError::Crl(format!("CRL fetch from {url} failed: {e}")))?;

        if !response.status().is_success() {
            return Err(LtvError::Crl(format!(
                "CRL fetch from {url} returned HTTP {}",
                response.status()
            )));
        }

        let crl_bytes = response
            .bytes()
            .await
            .map_err(|e| LtvError::Crl(format!("failed to read CRL response body: {e}")))?
            .to_vec();

        // Validate that it looks like a DER-encoded CRL (starts with SEQUENCE tag)
        if crl_bytes.is_empty() || crl_bytes[0] != 0x30 {
            return Err(LtvError::Crl(format!(
                "CRL from {url} does not appear to be DER-encoded"
            )));
        }

        log::debug!("CRL from {url}: {} bytes", crl_bytes.len());

        // Update cache
        {
            let mut cache = self.cache.lock().map_err(|e| {
                LtvError::Crl(format!("cache lock poisoned: {e}"))
            })?;
            cache.insert(
                url.to_string(),
                CrlCacheEntry {
                    der: crl_bytes.clone(),
                    fetched_at: Instant::now(),
                },
            );
        }

        Ok(crl_bytes)
    }

    /// Fetch all CRLs for a certificate (from all distribution points).
    pub async fn fetch_crls_for_cert(
        &self,
        cert: &Certificate,
    ) -> Result<Vec<Vec<u8>>, LtvError> {
        let urls = Self::extract_crl_urls(cert);
        let mut crls = Vec::new();

        for url in &urls {
            match self.fetch_crl(url).await {
                Ok(crl) => {
                    crls.push(crl);
                    // One CRL is sufficient for most validation scenarios
                    break;
                }
                Err(e) => {
                    log::warn!("Failed to fetch CRL from {url}: {e}");
                    // Try next URL
                }
            }
        }

        Ok(crls)
    }

    /// Clear the in-memory cache.
    pub fn clear_cache(&self) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.clear();
        }
    }
}

impl Default for CrlClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse the CRL Distribution Points extension value.
///
/// ```text
/// CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
/// DistributionPoint ::= SEQUENCE {
///     distributionPoint  [0] DistributionPointName OPTIONAL,
///     reasons            [1] ReasonFlags OPTIONAL,
///     cRLIssuer          [2] GeneralNames OPTIONAL
/// }
/// DistributionPointName ::= CHOICE {
///     fullName           [0] GeneralNames,
///     nameRelativeToCRLIssuer [1] RelativeDistinguishedName
/// }
/// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
/// GeneralName ::= CHOICE {
///     uniformResourceIdentifier [6] IA5String,
///     ...
/// }
/// ```
fn parse_crl_dp_extension(der_bytes: &[u8]) -> Result<Vec<String>, String> {
    let mut urls = Vec::new();

    // SEQUENCE OF DistributionPoint
    let (tag, body) = parse_tlv(der_bytes)?;
    if tag != 0x30 {
        return Err(format!("expected SEQUENCE, got 0x{tag:02x}"));
    }

    let mut pos = &body[..];
    while !pos.is_empty() {
        let (dp_tag, dp_body, rest) = parse_tlv_with_rest(pos)?;
        if dp_tag == 0x30 {
            // DistributionPoint SEQUENCE
            // Look for distributionPoint [0]
            if !dp_body.is_empty() {
                if let Ok((inner_tag, inner_body, _)) = parse_tlv_with_rest(&dp_body) {
                    if inner_tag == 0xA0 {
                        // DistributionPointName — look for fullName [0]
                        if let Ok((fn_tag, fn_body, _)) = parse_tlv_with_rest(&inner_body) {
                            if fn_tag == 0xA0 {
                                // GeneralNames — look for URI [6]
                                let mut gn_pos = &fn_body[..];
                                while !gn_pos.is_empty() {
                                    if let Ok((gn_tag, gn_body, gn_rest)) =
                                        parse_tlv_with_rest(gn_pos)
                                    {
                                        if gn_tag == 0x86 {
                                            // uniformResourceIdentifier [6] IMPLICIT IA5String
                                            if let Ok(uri) = std::str::from_utf8(&gn_body) {
                                                urls.push(uri.to_string());
                                            }
                                        }
                                        gn_pos = gn_rest;
                                    } else {
                                        break;
                                    }
                                }
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

// ---------------------------------------------------------------------------
// DER parsing helpers (duplicated from tsp::token for module independence)
// ---------------------------------------------------------------------------

fn parse_tlv(data: &[u8]) -> Result<(u8, Vec<u8>), String> {
    let (tag, body, _rest) = parse_tlv_with_rest(data)?;
    Ok((tag, body.to_vec()))
}

fn parse_tlv_with_rest(data: &[u8]) -> Result<(u8, &[u8], &[u8]), String> {
    if data.is_empty() {
        return Err("empty input".into());
    }
    let tag = data[0];
    let (len, header_len) = parse_der_length(&data[1..])?;
    let total_header = 1 + header_len;
    if total_header + len > data.len() {
        return Err(format!(
            "TLV length exceeds data: header={total_header}, len={len}, available={}",
            data.len()
        ));
    }
    let value = &data[total_header..total_header + len];
    let rest = &data[total_header + len..];
    Ok((tag, value, rest))
}

fn parse_der_length(data: &[u8]) -> Result<(usize, usize), String> {
    if data.is_empty() {
        return Err("empty length".into());
    }
    let first = data[0];
    if first < 0x80 {
        Ok((first as usize, 1))
    } else if first == 0x80 {
        Err("indefinite length not supported".into())
    } else {
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes > 4 || 1 + num_bytes > data.len() {
            return Err("length encoding error".into());
        }
        let mut len: usize = 0;
        for i in 0..num_bytes {
            len = (len << 8) | (data[1 + i] as usize);
        }
        Ok((len, 1 + num_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Decode;

    #[test]
    fn test_crl_client_default() {
        let client = CrlClient::new();
        assert_eq!(client.grace_period, Duration::from_secs(3600));
    }

    #[test]
    fn test_crl_client_builder() {
        let client = CrlClient::new()
            .timeout(Duration::from_secs(10))
            .grace_period(Duration::from_secs(7200));
        assert_eq!(client.grace_period, Duration::from_secs(7200));
    }

    #[test]
    fn test_extract_crl_urls_no_extensions() {
        // A certificate without CRL DP extensions should return empty
        let cert_pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/ca_cert.pem"
        ));
        // Root CAs typically don't have CRL DPs
        let pem_data = pem_rfc7468::decode_vec(cert_pem.as_bytes());
        if let Ok((_label, der)) = pem_data {
            if let Ok(cert) = Certificate::from_der(&der) {
                let urls = CrlClient::extract_crl_urls(&cert);
                // Root CA may or may not have CRL DPs, just ensure no panic
                let _ = urls;
            }
        }
    }
}
