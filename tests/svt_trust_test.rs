//! Regression tests for U-3: SVT `x5c` certificate trust enforcement.
//!
//! Before the fix, `SvtValidator::verify_jwt` accepted any certificate found in
//! the JWT `x5c` header even when it was not in (and did not chain to) the
//! trusted set ("accepting for now"). These tests lock in that an `x5c` signing
//! certificate is only honoured when it is itself a trust anchor or chains to
//! one, and that an unconfigured trust set fails closed.

use underskrift::svt::claims::{
    CertRefType, CertReferenceClaims, PolicyValidationClaims, SigReferenceClaims, SignatureClaims,
    SignedDataClaims, ValidationConclusion,
};
use underskrift::svt::issuer::{SvtIssuer, SvtModel};
use underskrift::svt::validator::SvtValidator;

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name);
    std::fs::read(path).expect("read fixture")
}

/// Decode a single-block PEM file to its DER bytes.
fn pem_to_der(name: &str) -> Vec<u8> {
    let pem = fixture(name);
    let (_label, der) = pem_rfc7468::decode_vec(&pem).expect("decode PEM");
    der
}

/// Build a minimal but structurally valid SVT JWT signed by the test signer,
/// carrying the given certificate chain in the `x5c` header.
fn issue_svt(chain_der: Vec<Vec<u8>>) -> String {
    let key_der = pem_to_der("signer_key.pem");
    let issuer = SvtIssuer::new("RS256", key_der, chain_der).expect("issuer");

    let sig_claims = SignatureClaims {
        sig_ref: SigReferenceClaims {
            id: Some("Sig1".to_string()),
            sig_hash: "AAAA".to_string(),
            sb_hash: "BBBB".to_string(),
        },
        sig_data_ref: vec![SignedDataClaims {
            data_ref: "0 100 200 50".to_string(),
            hash: "CCCC".to_string(),
        }],
        signer_cert_ref: CertReferenceClaims {
            ref_type: CertRefType::Chain,
            cert_ref: vec!["DDDD".to_string()],
        },
        time_val: None,
        sig_val: vec![PolicyValidationClaims {
            pol: "http://id.swedenconnect.se/svt/sigval-policy/chain/01".to_string(),
            res: ValidationConclusion::Passed,
            msg: None,
            ext: None,
        }],
        ext: None,
    };
    let model = SvtModel::builder()
        .issuer_id("https://svt.example.com")
        .validity_period(3600)
        .build();
    issuer.issue(vec![sig_claims], &model).expect("issue SVT")
}

#[test]
fn x5c_empty_trust_set_fails_closed() {
    let signer = pem_to_der("signer_cert.pem");
    let intermediate = pem_to_der("intermediate_ca_cert.pem");
    let jwt = issue_svt(vec![signer, intermediate]);

    // No trust anchors configured: trust cannot be established, so we must
    // reject rather than silently accept the attacker-supplied certificate.
    let result = SvtValidator::verify_jwt(&jwt, &[]);
    assert!(
        result.is_err(),
        "empty trust set must fail closed, got: {result:?}"
    );
}

#[test]
fn x5c_untrusted_chain_is_rejected() {
    // x5c contains only the leaf; trusting just the root leaves the chain
    // incomplete (missing intermediate) so it must not validate.
    let signer = pem_to_der("signer_cert.pem");
    let root = pem_to_der("ca_cert.pem");
    let jwt = issue_svt(vec![signer]);

    let result = SvtValidator::verify_jwt(&jwt, &[root]);
    assert!(
        result.is_err(),
        "leaf that does not chain to an anchor must be rejected, got: {result:?}"
    );
}

#[test]
fn x5c_leaf_as_explicit_anchor_is_accepted() {
    // The signing certificate is itself supplied as a trust anchor.
    let signer = pem_to_der("signer_cert.pem");
    let intermediate = pem_to_der("intermediate_ca_cert.pem");
    let jwt = issue_svt(vec![signer.clone(), intermediate]);

    let result = SvtValidator::verify_jwt(&jwt, &[signer]);
    assert!(
        result.is_ok(),
        "signing cert present as an anchor must be accepted, got: {result:?}"
    );
}

#[test]
fn x5c_chain_to_trusted_root_is_accepted() {
    // Full chain in x5c (leaf + intermediate) anchored at the trusted root.
    let signer = pem_to_der("signer_cert.pem");
    let intermediate = pem_to_der("intermediate_ca_cert.pem");
    let root = pem_to_der("ca_cert.pem");
    let jwt = issue_svt(vec![signer, intermediate]);

    let result = SvtValidator::verify_jwt(&jwt, &[root]);
    assert!(
        result.is_ok(),
        "leaf chaining to a trusted root must be accepted, got: {result:?}"
    );
}
