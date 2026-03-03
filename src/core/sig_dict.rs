//! Signature and DocTimeStamp dictionary creation.
//!
//! Creates `/Type /Sig` and `/Type /DocTimeStamp` dictionaries with proper
//! `/Filter`, `/SubFilter`, `/ByteRange`, and `/Contents` entries.

use lopdf::{Dictionary, Object};

/// SubFilter values we support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigSubFilter {
    /// PAdES: `/ETSI.CAdES.detached`
    EtsiCadesDetached,
    /// Traditional: `/adbe.pkcs7.detached`
    AdbePkcs7Detached,
}

impl SigSubFilter {
    /// Returns the PDF name string for this sub-filter.
    pub fn as_pdf_name(&self) -> &'static str {
        match self {
            SigSubFilter::EtsiCadesDetached => "ETSI.CAdES.detached",
            SigSubFilter::AdbePkcs7Detached => "adbe.pkcs7.detached",
        }
    }
}

/// Build a signature dictionary with placeholder ByteRange and Contents.
///
/// `contents_size` is the number of bytes to reserve for the hex-encoded
/// signature in `/Contents`. This must be large enough to hold the final
/// CMS signature.
pub fn build_sig_dict(sub_filter: SigSubFilter, contents_size: usize) -> Dictionary {
    let mut dict = Dictionary::new();
    dict.set("Type", Object::Name(b"Sig".to_vec()));
    dict.set("Filter", Object::Name(b"Adobe.PPKLite".to_vec()));
    dict.set(
        "SubFilter",
        Object::Name(sub_filter.as_pdf_name().as_bytes().to_vec()),
    );

    // ByteRange placeholder — will be backpatched after serialization
    // Using [0 0 0 0] as placeholder; real values computed during incremental write
    dict.set(
        "ByteRange",
        Object::Array(vec![
            Object::Integer(0),
            Object::Integer(0),
            Object::Integer(0),
            Object::Integer(0),
        ]),
    );

    // Contents placeholder — hex-encoded zeroes, sized to `contents_size`
    // The actual signature bytes will replace these zeroes after signing
    let placeholder = vec![0u8; contents_size];
    dict.set(
        "Contents",
        Object::String(placeholder, lopdf::StringFormat::Hexadecimal),
    );

    dict
}
