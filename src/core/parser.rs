//! PDF metadata extraction and existing signature parsing.
//!
//! Extracts structural metadata needed for incremental updates (xref offset,
//! trailer /Size, root catalog ID) and parses existing signature dictionaries
//! for verification and multi-signature support.

use lopdf::xref::XrefType;
use lopdf::{Document, Object, ObjectId};

use crate::error::CoreError;

/// Structural metadata extracted from a parsed PDF, needed to initialize
/// the [`IncrementalWriter`](super::incremental::IncrementalWriter).
#[derive(Debug, Clone)]
pub struct PdfMetadata {
    /// The byte offset of the cross-reference table (startxref value).
    pub xref_offset: usize,
    /// The /Size value from the trailer (next available object number).
    pub trailer_size: u32,
    /// The /Root catalog object ID.
    pub root_id: ObjectId,
    /// The maximum object ID used in the document.
    pub max_id: u32,
    /// The trailer `/ID` array, if present. Must be carried forward into the
    /// incremental update's trailer (required for encrypted PDFs and PDF/A,
    /// and expected by many validators).
    pub id: Option<Object>,
    /// The trailer `/Encrypt` entry, if present. Carried forward so the
    /// incremental update remains structurally consistent with an encrypted
    /// document.
    pub encrypt: Option<Object>,
    /// Whether the document's most recent cross-reference section is a
    /// cross-reference **stream** (PDF 1.5+) rather than a classic `xref`
    /// table. When true, the incremental update must also be written as an
    /// XRef stream so the chain remains consistent for strict readers.
    pub uses_xref_stream: bool,
}

/// Information about an existing signature in a PDF.
#[derive(Debug)]
pub struct ExistingSignature {
    /// The signature field name
    pub field_name: String,
    /// The raw ByteRange values [offset1, length1, offset2, length2]
    pub byte_range: [usize; 4],
    /// The raw CMS/PKCS#7 signature bytes from /Contents
    pub contents: Vec<u8>,
    /// The SubFilter value
    pub sub_filter: String,
}

/// Extract structural metadata from a parsed PDF document.
///
/// This information is needed to construct the incremental update:
/// - `xref_offset` — becomes the /Prev in the new trailer
/// - `trailer_size` — becomes the basis for new object numbering
/// - `root_id` — referenced in the new trailer's /Root
/// - `max_id` — used to allocate new object IDs
pub fn extract_metadata(doc: &Document) -> Result<PdfMetadata, CoreError> {
    // xref_start is populated by lopdf during parsing
    let xref_offset = doc.xref_start;
    if xref_offset == 0 {
        // xref_start == 0 could be a legitimate offset for very small PDFs,
        // but it's much more likely the document wasn't parsed from bytes.
        // We'll accept it but log a warning.
        log::warn!("xref_start is 0 — this may indicate the document wasn't parsed from bytes");
    }

    // Get /Size from trailer
    let trailer_size = doc
        .trailer
        .get(b"Size")
        .and_then(Object::as_i64)
        .map(|s| s as u32)
        .map_err(|_| CoreError::InvalidXref)?;

    // Get /Root from trailer
    let root_id = doc
        .trailer
        .get(b"Root")
        .and_then(Object::as_reference)
        .map_err(|_| CoreError::InvalidStructure("trailer missing /Root".into()))?;

    // Preserve /ID and /Encrypt from the trailer so the incremental update's
    // trailer stays structurally faithful (dropping /ID breaks PDF/A and many
    // validators; dropping /Encrypt corrupts encrypted documents).
    let id = doc.trailer.get(b"ID").ok().cloned();
    let encrypt = doc.trailer.get(b"Encrypt").ok().cloned();

    let uses_xref_stream = matches!(
        doc.reference_table.cross_reference_type,
        XrefType::CrossReferenceStream
    );

    Ok(PdfMetadata {
        xref_offset,
        trailer_size,
        root_id,
        max_id: doc.max_id,
        id,
        encrypt,
        uses_xref_stream,
    })
}

/// Extract all existing signatures from a PDF document.
///
/// Walks the AcroForm /Fields looking for signature fields (/FT /Sig),
/// extracts their ByteRange and Contents values.
pub fn extract_signatures(doc: &Document) -> Result<Vec<ExistingSignature>, CoreError> {
    let mut signatures = Vec::new();

    // Get the catalog
    let catalog = doc
        .catalog()
        .map_err(|e| CoreError::InvalidStructure(format!("failed to get catalog: {e}")))?;

    // Check for AcroForm
    let acroform = match catalog.get(b"AcroForm") {
        Ok(Object::Reference(id)) => doc.get_object(*id).and_then(Object::as_dict).ok(),
        Ok(Object::Dictionary(d)) => Some(d),
        _ => None,
    };

    let acroform = match acroform {
        Some(af) => af,
        None => return Ok(signatures), // No AcroForm, no signatures
    };

    // Get the Fields array
    let fields = match acroform.get(b"Fields") {
        Ok(Object::Array(arr)) => arr.clone(),
        _ => return Ok(signatures),
    };

    // Walk each field looking for signature fields
    for field_ref in &fields {
        let field_id = match field_ref.as_reference() {
            Ok(id) => id,
            Err(_) => continue,
        };

        let field = match doc.get_object(field_id).and_then(Object::as_dict) {
            Ok(d) => d,
            Err(_) => continue,
        };

        // Check if this is a signature field
        let ft = match field.get(b"FT").and_then(Object::as_name) {
            Ok(name) => name,
            Err(_) => continue,
        };
        if ft != b"Sig" {
            continue;
        }

        // Get the field name
        let field_name = field
            .get(b"T")
            .and_then(Object::as_str)
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .unwrap_or_default();

        // Get the signature dictionary (may be inline or referenced via /V)
        let sig_dict = match field.get(b"V") {
            Ok(Object::Reference(sig_id)) => {
                match doc.get_object(*sig_id).and_then(Object::as_dict) {
                    Ok(d) => d,
                    Err(_) => continue,
                }
            }
            Ok(Object::Dictionary(d)) => d,
            _ => continue,
        };

        // Extract ByteRange
        let byte_range = match extract_byte_range(sig_dict) {
            Some(br) => br,
            None => continue,
        };

        // Extract Contents (hex-decoded CMS/PKCS#7 bytes)
        // The Contents value is zero-padded to fill the reserved space,
        // so we trim trailing zero bytes to get the actual DER-encoded CMS.
        let contents = match sig_dict.get(b"Contents").and_then(Object::as_str) {
            Ok(bytes) => {
                let mut data = bytes.to_vec();
                // Trim trailing zeros (padding)
                while data.last() == Some(&0) {
                    data.pop();
                }
                data
            }
            Err(_) => continue,
        };

        // Extract SubFilter
        let sub_filter = sig_dict
            .get(b"SubFilter")
            .and_then(Object::as_name)
            .map(|n| String::from_utf8_lossy(n).into_owned())
            .unwrap_or_default();

        signatures.push(ExistingSignature {
            field_name,
            byte_range,
            contents,
            sub_filter,
        });
    }

    Ok(signatures)
}

/// Extract ByteRange array values from a signature dictionary.
fn extract_byte_range(sig_dict: &lopdf::Dictionary) -> Option<[usize; 4]> {
    let arr = sig_dict.get(b"ByteRange").ok()?.as_array().ok()?;
    if arr.len() != 4 {
        return None;
    }
    let values: Vec<usize> = arr
        .iter()
        .filter_map(|obj| obj.as_i64().ok().map(|v| v as usize))
        .collect();
    if values.len() == 4 {
        Some([values[0], values[1], values[2], values[3]])
    } else {
        None
    }
}
