//! Tests for the trust module — TrustStore and TrustStoreSet.

use der::Decode;
use std::path::PathBuf;
use underskrift::error::TrustError;
use underskrift::trust::{StoreKind, TrustStore, TrustStoreSet};
use x509_cert::Certificate;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

fn load_ca_cert_der() -> Vec<u8> {
    let pem = std::fs::read(fixtures_dir().join("ca_cert.pem")).unwrap();
    pem_to_der(&pem)
}

fn load_intermediate_ca_cert_der() -> Vec<u8> {
    let pem = std::fs::read(fixtures_dir().join("intermediate_ca_cert.pem")).unwrap();
    pem_to_der(&pem)
}

fn load_signer_cert_der() -> Vec<u8> {
    let pem = std::fs::read(fixtures_dir().join("signer_cert.pem")).unwrap();
    pem_to_der(&pem)
}

/// Extract DER bytes from PEM data (first CERTIFICATE block).
fn pem_to_der(pem_data: &[u8]) -> Vec<u8> {
    let pem_str = std::str::from_utf8(pem_data).unwrap();
    let begin = pem_str.find("-----BEGIN CERTIFICATE-----").unwrap();
    let block = &pem_str[begin..];
    let end = block.find("-----END CERTIFICATE-----").unwrap() + "-----END CERTIFICATE-----".len();
    let pem_block = &block[..end];

    let b64: String = pem_block
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();

    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .unwrap()
}

// ── TrustStore basic operations ──────────────────────────────────────────────

#[test]
fn test_trust_store_new_is_empty() {
    let store = TrustStore::new();
    assert!(store.is_empty());
    assert_eq!(store.len(), 0);
}

#[test]
fn test_trust_store_with_label() {
    let store = TrustStore::new().with_label("sig");
    assert_eq!(store.label(), Some("sig"));
}

#[test]
fn test_trust_store_default_has_no_label() {
    let store = TrustStore::default();
    assert_eq!(store.label(), None);
}

// ── Loading certificates ─────────────────────────────────────────────────────

#[test]
fn test_load_from_pem_file() {
    let store = TrustStore::from_pem_file(fixtures_dir().join("ca_cert.pem")).unwrap();
    assert_eq!(store.len(), 1);
    assert!(!store.is_empty());
}

#[test]
fn test_load_from_pem_file_nonexistent() {
    let result = TrustStore::from_pem_file("/nonexistent/path.pem");
    assert!(result.is_err());
    match result.unwrap_err() {
        TrustError::Io(_) => {} // expected
        other => panic!("expected Io error, got: {other}"),
    }
}

#[test]
fn test_add_der_certificate() {
    let mut store = TrustStore::new();
    let ca_der = load_ca_cert_der();
    store.add_der_certificate(&ca_der).unwrap();
    assert_eq!(store.len(), 1);
}

#[test]
fn test_add_invalid_der_fails() {
    let mut store = TrustStore::new();
    let result = store.add_der_certificate(b"not a certificate");
    assert!(result.is_err());
    match result.unwrap_err() {
        TrustError::CertificateParse(_) => {}
        other => panic!("expected CertificateParse, got: {other}"),
    }
}

#[test]
fn test_add_pem_data() {
    let mut store = TrustStore::new();
    let pem = std::fs::read(fixtures_dir().join("ca_cert.pem")).unwrap();
    store.add_pem_data(&pem).unwrap();
    assert_eq!(store.len(), 1);
}

#[test]
fn test_add_multiple_pem_certs() {
    // Concatenate ca_cert and signer_cert into one PEM blob
    let ca_pem = std::fs::read(fixtures_dir().join("ca_cert.pem")).unwrap();
    let signer_pem = std::fs::read(fixtures_dir().join("signer_cert.pem")).unwrap();
    let mut combined = ca_pem.clone();
    combined.push(b'\n');
    combined.extend_from_slice(&signer_pem);

    let mut store = TrustStore::new();
    store.add_pem_data(&combined).unwrap();
    assert_eq!(store.len(), 2);
}

#[test]
fn test_add_pem_no_cert_blocks_fails() {
    let mut store = TrustStore::new();
    let result = store.add_pem_data(b"just some random text");
    assert!(result.is_err());
    match result.unwrap_err() {
        TrustError::CertificateParse(msg) => {
            assert!(msg.contains("no CERTIFICATE blocks"), "got: {msg}");
        }
        other => panic!("expected CertificateParse, got: {other}"),
    }
}

// ── Query methods ────────────────────────────────────────────────────────────

#[test]
fn test_contains_der() {
    let ca_der = load_ca_cert_der();
    let signer_der = load_signer_cert_der();

    let mut store = TrustStore::new();
    store.add_der_certificate(&ca_der).unwrap();

    assert!(store.contains_der(&ca_der));
    assert!(!store.contains_der(&signer_der));
}

#[test]
fn test_find_issuer() {
    let intermediate_der = load_intermediate_ca_cert_der();
    let signer_der = load_signer_cert_der();

    let mut store = TrustStore::new();
    store.add_der_certificate(&intermediate_der).unwrap();

    let signer_cert = Certificate::from_der(&signer_der).unwrap();
    let issuer = store.find_issuer(&signer_cert);
    assert!(
        issuer.is_some(),
        "should find intermediate CA as issuer of signer cert"
    );
}

#[test]
fn test_find_issuer_not_in_store() {
    let signer_der = load_signer_cert_der();

    let store = TrustStore::new(); // empty store
    let signer_cert = Certificate::from_der(&signer_der).unwrap();
    let issuer = store.find_issuer(&signer_cert);
    assert!(issuer.is_none());
}

#[test]
fn test_find_issuer_for_der() {
    let intermediate_der = load_intermediate_ca_cert_der();
    let signer_der = load_signer_cert_der();

    let mut store = TrustStore::new();
    store.add_der_certificate(&intermediate_der).unwrap();

    assert!(store.find_issuer_for_der(&signer_der).is_some());
    assert!(store.find_issuer_for_der(b"garbage").is_none());
}

#[test]
fn test_certificates_iterator() {
    let ca_der = load_ca_cert_der();
    let signer_der = load_signer_cert_der();

    let mut store = TrustStore::new();
    store.add_der_certificate(&ca_der).unwrap();
    store.add_der_certificate(&signer_der).unwrap();

    let certs: Vec<_> = store.certificates().collect();
    assert_eq!(certs.len(), 2);
}

#[test]
fn test_certificates_der_iterator() {
    let ca_der = load_ca_cert_der();

    let mut store = TrustStore::new();
    store.add_der_certificate(&ca_der).unwrap();

    let ders: Vec<_> = store.certificates_der().collect();
    assert_eq!(ders.len(), 1);
    assert_eq!(ders[0], ca_der.as_slice());
}

// ── Chain verification ───────────────────────────────────────────────────────

#[test]
fn test_verify_chain_single_cert_issued_by_anchor() {
    let ca_der = load_ca_cert_der();
    let intermediate_der = load_intermediate_ca_cert_der();
    let signer_der = load_signer_cert_der();

    let mut store = TrustStore::new();
    store.add_der_certificate(&ca_der).unwrap();

    let signer_cert = Certificate::from_der(&signer_der).unwrap();
    let intermediate_cert = Certificate::from_der(&intermediate_der).unwrap();
    let result = store.verify_chain(&[signer_cert, intermediate_cert], None);
    assert!(
        result.is_ok(),
        "chain verification failed: {:?}",
        result.err()
    );
}

#[test]
fn test_verify_chain_empty_chain_fails() {
    let ca_der = load_ca_cert_der();
    let mut store = TrustStore::new();
    store.add_der_certificate(&ca_der).unwrap();

    let result = store.verify_chain(&[], None);
    assert!(result.is_err());
    match result.unwrap_err() {
        TrustError::EmptyChain => {}
        other => panic!("expected EmptyChain, got: {other}"),
    }
}

#[test]
fn test_verify_chain_untrusted_root() {
    let signer_der = load_signer_cert_der();
    let store = TrustStore::new(); // empty store — no trust anchors

    let signer_cert = Certificate::from_der(&signer_der).unwrap();
    let result = store.verify_chain(&[signer_cert], None);
    assert!(result.is_err());
    match result.unwrap_err() {
        TrustError::UntrustedRoot { .. } => {}
        other => panic!("expected UntrustedRoot, got: {other}"),
    }
}

#[test]
fn test_verify_chain_self_signed_in_store() {
    // The CA cert is self-signed. If we put it in the store and verify a chain
    // containing just the CA cert, it should succeed.
    let ca_der = load_ca_cert_der();

    let mut store = TrustStore::new();
    store.add_der_certificate(&ca_der).unwrap();

    let ca_cert = Certificate::from_der(&ca_der).unwrap();
    let result = store.verify_chain(&[ca_cert], None);
    assert!(
        result.is_ok(),
        "self-signed CA in store should verify: {:?}",
        result.err()
    );
}

// ── TrustStoreSet ────────────────────────────────────────────────────────────

#[test]
fn test_store_set_new_has_no_stores() {
    let set = TrustStoreSet::new();
    assert!(!set.has_any());
    assert!(set.sig().is_none());
    assert!(set.tsa().is_none());
    assert!(set.svt().is_none());
}

#[test]
fn test_store_set_with_sig_store() {
    let store = TrustStore::from_pem_file(fixtures_dir().join("ca_cert.pem")).unwrap();
    let set = TrustStoreSet::new().with_sig_store(store);
    assert!(set.has_any());
    assert!(set.sig().is_some());
    assert!(set.tsa().is_none());
    assert!(set.svt().is_none());
    assert_eq!(set.sig().unwrap().len(), 1);
}

#[test]
fn test_store_set_get_by_kind() {
    let store = TrustStore::from_pem_file(fixtures_dir().join("ca_cert.pem")).unwrap();
    let set = TrustStoreSet::new().with_tsa_store(store);

    assert!(set.get(StoreKind::Timestamp).is_some());
    assert!(set.get(StoreKind::Signature).is_none());
    assert!(set.get(StoreKind::Svt).is_none());
}

#[test]
fn test_store_set_set_by_kind() {
    let store = TrustStore::from_pem_file(fixtures_dir().join("ca_cert.pem")).unwrap();
    let mut set = TrustStoreSet::new();
    set.set(StoreKind::Svt, store);
    assert!(set.svt().is_some());
}

#[test]
fn test_store_set_all_three_stores() {
    let sig_store = TrustStore::new().with_label("sig");
    let tsa_store = TrustStore::new().with_label("tsa");
    let svt_store = TrustStore::new().with_label("svt");

    let set = TrustStoreSet::new()
        .with_sig_store(sig_store)
        .with_tsa_store(tsa_store)
        .with_svt_store(svt_store);

    assert!(set.has_any());
    assert_eq!(set.sig().unwrap().label(), Some("sig"));
    assert_eq!(set.tsa().unwrap().label(), Some("tsa"));
    assert_eq!(set.svt().unwrap().label(), Some("svt"));
}

#[test]
fn test_store_kind_display() {
    assert_eq!(format!("{}", StoreKind::Signature), "sig");
    assert_eq!(format!("{}", StoreKind::Timestamp), "tsa");
    assert_eq!(format!("{}", StoreKind::Svt), "svt");
}

// ── Debug output ─────────────────────────────────────────────────────────────

#[test]
fn test_trust_store_debug() {
    let store = TrustStore::from_pem_file(fixtures_dir().join("ca_cert.pem"))
        .unwrap()
        .with_label("test");
    let debug = format!("{:?}", store);
    assert!(debug.contains("TrustStore"));
    assert!(debug.contains("test"));
    assert!(debug.contains("1")); // 1 anchor
}
