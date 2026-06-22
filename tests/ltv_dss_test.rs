//! Regression test for U-6 (audit B10): object-ID allocation when the DSS /
//! LTV builder adds validation-data objects to a signed document must not
//! collide with existing objects.
//!
//! The DSS builder and the incremental signing writer allocate object IDs
//! independently; this test locks in that DSS-added objects receive fresh,
//! unique IDs distinct from everything already in the parsed document.

#![cfg(feature = "ltv")]

use std::collections::HashSet;

use lopdf::{Document, Object};
use underskrift::ltv::{DssBuilder, VriEntry};
use underskrift::{PdfSigner, SigningOptions, SoftwareSigner, SubFilter};

fn test_signer() -> SoftwareSigner {
    let p12 = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/signer.p12");
    SoftwareSigner::from_pkcs12_file(p12, "test123").expect("load signer")
}

async fn signed_sample() -> Vec<u8> {
    let pdf = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/sample.pdf"
    ))
    .expect("read sample");
    PdfSigner::new()
        .options(SigningOptions {
            sub_filter: SubFilter::Pades,
            field_name: "Sig".into(),
            ..Default::default()
        })
        .sign(&pdf, &test_signer())
        .await
        .expect("sign")
}

#[tokio::test]
async fn dss_objects_get_fresh_unique_ids() {
    let signed = signed_sample().await;
    let mut doc = Document::load_mem(&signed).expect("parse signed PDF");

    // Snapshot the object IDs that exist before DSS embedding.
    let pre_existing: HashSet<(u32, u16)> = doc.objects.keys().copied().collect();
    let pre_max_id = doc.max_id;

    // Build a DSS with several certs, an OCSP, a CRL, and a VRI entry — every
    // one of these becomes a new stream object.
    let mut dss = DssBuilder::new();
    dss.add_certificate(b"fake-signer-cert".to_vec());
    dss.add_certificate(b"fake-intermediate-cert".to_vec());
    dss.add_ocsp_response(b"fake-ocsp-response".to_vec());
    dss.add_crl(b"fake-crl".to_vec());
    dss.add_vri_entry(
        "ABCDEF".to_string(),
        VriEntry {
            certs: vec![b"vri-cert".to_vec()],
            ocsps: vec![b"vri-ocsp".to_vec()],
            crls: vec![],
        },
    );

    let dss_obj = dss.build_dss_dict(&mut doc).expect("build DSS dict");
    assert!(matches!(dss_obj, Object::Dictionary(_)));

    // Every object now in the document must have a unique ID (lopdf's map keys
    // are unique by construction; this asserts the builder never reused one),
    // and all newly-added objects must sit above the original max object number
    // and must not overlap any pre-existing object ID.
    let new_ids: Vec<(u32, u16)> = doc
        .objects
        .keys()
        .copied()
        .filter(|id| !pre_existing.contains(id))
        .collect();

    assert!(
        new_ids.len() >= 6,
        "expected at least 6 new DSS stream objects, got {}",
        new_ids.len()
    );

    let unique: HashSet<_> = new_ids.iter().copied().collect();
    assert_eq!(unique.len(), new_ids.len(), "DSS object IDs must be unique");

    for id in &new_ids {
        assert!(
            !pre_existing.contains(id),
            "DSS object {id:?} collides with a pre-existing object"
        );
        assert!(
            id.0 > pre_max_id,
            "DSS object number {} must exceed original max_id {pre_max_id}",
            id.0
        );
    }
}
