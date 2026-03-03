//! Signature field creation and annotation widgets.
//!
//! Creates `/FT /Sig` form fields and their associated annotation widgets.
//! For invisible signatures, a zero-size annotation is used.

use lopdf::{Dictionary, Object, ObjectId};

/// Configuration for a signature field.
#[derive(Debug, Clone)]
pub struct SignatureFieldOptions {
    /// Field name (e.g., "Signature1")
    pub name: String,
    /// Page number (0-indexed) to place the annotation on
    pub page: u32,
    /// Annotation rectangle [x1, y1, x2, y2] in PDF user space.
    /// Use [0, 0, 0, 0] for invisible signatures.
    pub rect: [f32; 4],
}

impl Default for SignatureFieldOptions {
    fn default() -> Self {
        Self {
            name: "Signature1".to_string(),
            page: 0,
            rect: [0.0, 0.0, 0.0, 0.0], // Invisible
        }
    }
}

/// Build a signature field dictionary (combined field + widget annotation).
///
/// The `sig_dict_ref` is the object ID of the signature dictionary that
/// this field will reference via `/V`.
pub fn build_sig_field(options: &SignatureFieldOptions, sig_dict_ref: ObjectId) -> Dictionary {
    let mut dict = Dictionary::new();

    // Form field entries
    dict.set("FT", Object::Name(b"Sig".to_vec()));
    dict.set(
        "T",
        Object::String(
            options.name.as_bytes().to_vec(),
            lopdf::StringFormat::Literal,
        ),
    );
    dict.set("V", Object::Reference(sig_dict_ref));

    // Widget annotation entries
    dict.set("Type", Object::Name(b"Annot".to_vec()));
    dict.set("Subtype", Object::Name(b"Widget".to_vec()));
    dict.set(
        "Rect",
        Object::Array(options.rect.iter().map(|&v| Object::Real(v)).collect()),
    );

    // Annotation flags: Print (bit 3) | Locked (bit 8)
    dict.set("F", Object::Integer(132));

    dict
}
