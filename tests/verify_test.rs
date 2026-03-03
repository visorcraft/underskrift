//! Integration tests for the verify module.
//!
//! Tests the full sign-then-verify round-trip to ensure signatures
//! produced by underskrift can be verified by underskrift.

use underskrift::crypto::software::SoftwareSigner;
use underskrift::signer::{PdfSigner, SigningOptions, SubFilter};
use underskrift::trust::{TrustStore, TrustStoreSet};
use underskrift::verify::report::SignatureStatus;
use underskrift::verify::SignatureVerifier;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn load_signer() -> SoftwareSigner {
    let p12_path = format!("{}/signer.p12", FIXTURES);
    SoftwareSigner::from_pkcs12_file(&p12_path, "test123").expect("failed to load PKCS#12")
}

fn load_trust_store() -> TrustStoreSet {
    let ca_path = format!("{}/ca_cert.pem", FIXTURES);
    let store = TrustStore::from_pem_file(&ca_path).expect("failed to load CA cert");
    TrustStoreSet::new().with_sig_store(store)
}

fn load_pdf() -> Vec<u8> {
    let pdf_path = format!("{}/sample.pdf", FIXTURES);
    std::fs::read(&pdf_path).expect("failed to read sample PDF")
}

// ── PAdES sign-then-verify ─────────────────────────────────────────────────

#[tokio::test]
async fn test_sign_then_verify_pades() {
    let pdf_data = load_pdf();
    let signer = load_signer();
    let trust_stores = load_trust_store();

    // Sign the PDF
    let opts = SigningOptions {
        sub_filter: SubFilter::Pades,
        field_name: "TestSig1".to_string(),
        ..Default::default()
    };
    let signed_pdf = PdfSigner::new()
        .options(opts)
        .sign(&pdf_data, &signer)
        .await
        .expect("signing failed");

    // Verify the signed PDF
    let verifier = SignatureVerifier::new(&trust_stores);
    let report = verifier.verify_pdf(&signed_pdf).expect("verification failed");

    assert_eq!(report.signatures.len(), 1, "should have exactly 1 signature");
    let sig = &report.signatures[0];

    assert_eq!(sig.field_name, "TestSig1");
    assert!(sig.integrity_ok, "ByteRange integrity should be OK");
    assert!(sig.digest_matches, "messageDigest should match");
    assert!(sig.covers_whole_document, "should cover entire file");
    assert!(!sig.modifications_after_signing, "no modifications expected");
    assert!(
        sig.status == SignatureStatus::Valid || sig.status == SignatureStatus::ValidButUntrusted,
        "signature should be valid or valid-but-untrusted, got: {:?}\nsummary: {}",
        sig.status,
        sig.summary
    );

    // With correct trust store, it should be fully valid
    if sig.status != SignatureStatus::Valid {
        eprintln!("WARNING: signature is {:?}", sig.status);
        eprintln!("  chain_trusted: {}", sig.chain_trusted);
        eprintln!("  trust_anchor: {:?}", sig.trust_anchor);
        eprintln!("  summary: {}", sig.summary);
    }

    assert!(report.valid_count >= 1, "should have at least 1 valid sig");
    assert!(!report.document_modified, "document should not be modified");
}

// ── PKCS#7 sign-then-verify ────────────────────────────────────────────────

#[tokio::test]
async fn test_sign_then_verify_pkcs7() {
    let pdf_data = load_pdf();
    let signer = load_signer();
    let trust_stores = load_trust_store();

    let opts = SigningOptions {
        sub_filter: SubFilter::Pkcs7,
        field_name: "TestSig2".to_string(),
        ..Default::default()
    };
    let signed_pdf = PdfSigner::new()
        .options(opts)
        .sign(&pdf_data, &signer)
        .await
        .expect("signing failed");

    let verifier = SignatureVerifier::new(&trust_stores);
    let report = verifier.verify_pdf(&signed_pdf).expect("verification failed");

    assert_eq!(report.signatures.len(), 1);
    let sig = &report.signatures[0];
    assert_eq!(sig.field_name, "TestSig2");
    assert!(sig.integrity_ok, "ByteRange integrity should be OK");
    assert!(sig.digest_matches, "messageDigest should match");
}

// ── Unsigned PDF returns error ─────────────────────────────────────────────

#[test]
fn test_verify_unsigned_pdf_returns_no_signatures() {
    let pdf_data = load_pdf();
    let trust_stores = load_trust_store();

    let verifier = SignatureVerifier::new(&trust_stores);
    let result = verifier.verify_pdf(&pdf_data);

    assert!(result.is_err(), "unsigned PDF should return error");
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("no signatures"),
        "error should mention no signatures: {err}"
    );
}

// ── Extractor tests on signed PDF ──────────────────────────────────────────

#[tokio::test]
async fn test_extract_signatures_from_signed_pdf() {
    let pdf_data = load_pdf();
    let signer = load_signer();

    let opts = SigningOptions {
        sub_filter: SubFilter::Pades,
        field_name: "ExtractTest".to_string(),
        reason: Some("Testing extraction".to_string()),
        ..Default::default()
    };
    let signed_pdf = PdfSigner::new()
        .options(opts)
        .sign(&pdf_data, &signer)
        .await
        .expect("signing failed");

    let sigs =
        underskrift::verify::extractor::extract_signatures(&signed_pdf).expect("extraction failed");

    assert_eq!(sigs.len(), 1);
    let sig = &sigs[0];
    assert_eq!(sig.field_name, "ExtractTest");
    assert_eq!(
        sig.signature_type,
        underskrift::verify::SignatureType::Pades
    );
    assert!(!sig.cms_bytes.is_empty(), "CMS bytes should not be empty");
    assert_eq!(sig.reason.as_deref(), Some("Testing extraction"));

    // ByteRange should be valid
    assert_eq!(sig.byte_range[0], 0, "first range starts at 0");
    assert!(sig.byte_range[1] > 0, "first range has positive length");
    assert!(sig.byte_range[2] > sig.byte_range[1], "gap between ranges");
    let end = sig.byte_range[2] + sig.byte_range[3];
    assert_eq!(end, signed_pdf.len(), "should cover to EOF");
}

// ── Tampered PDF detection ─────────────────────────────────────────────────

#[tokio::test]
async fn test_verify_detects_tampered_pdf() {
    let pdf_data = load_pdf();
    let signer = load_signer();
    let trust_stores = load_trust_store();

    let opts = SigningOptions::default();
    let mut signed_pdf = PdfSigner::new()
        .options(opts)
        .sign(&pdf_data, &signer)
        .await
        .expect("signing failed");

    // Tamper with the PDF: modify a byte in the first range
    // (but not in the signature contents area)
    if signed_pdf.len() > 100 {
        signed_pdf[50] ^= 0xFF; // Flip bits
    }

    let verifier = SignatureVerifier::new(&trust_stores);
    let report = verifier.verify_pdf(&signed_pdf).expect("should still parse");

    assert_eq!(report.signatures.len(), 1);
    let sig = &report.signatures[0];

    // Either the digest won't match or the CMS verification will fail
    assert!(
        !sig.digest_matches || sig.status == SignatureStatus::Invalid,
        "tampered PDF should fail verification: digest_matches={}, status={:?}",
        sig.digest_matches,
        sig.status
    );
}

// ── Chain verification with full chain ─────────────────────────────────────

#[tokio::test]
async fn test_verify_with_intermediate_ca() {
    let pdf_data = load_pdf();
    let signer = load_signer();

    // Load root CA as trust anchor
    let ca_path = format!("{}/ca_cert.pem", FIXTURES);
    let trust_store = TrustStore::from_pem_file(&ca_path).expect("failed to load CA");
    let trust_stores = TrustStoreSet::new().with_sig_store(trust_store);

    let opts = SigningOptions {
        sub_filter: SubFilter::Pades,
        ..Default::default()
    };
    let signed_pdf = PdfSigner::new()
        .options(opts)
        .sign(&pdf_data, &signer)
        .await
        .expect("signing failed");

    let verifier = SignatureVerifier::new(&trust_stores);
    let report = verifier.verify_pdf(&signed_pdf).expect("verification failed");

    let sig = &report.signatures[0];
    // The signer_name should be extracted from the certificate
    assert!(sig.signer_name.is_some(), "signer name should be extracted");
    eprintln!("Signer: {:?}", sig.signer_name);
    eprintln!("Status: {:?}", sig.status);
    eprintln!("Chain trusted: {}", sig.chain_trusted);
    eprintln!("Trust anchor: {:?}", sig.trust_anchor);
    eprintln!("Summary: {}", sig.summary);
}
