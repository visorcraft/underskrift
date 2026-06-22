//! DocMDP and FieldMDP — certification and modification detection.
//!
//! Handles `/DocMDP` transform method for certification signatures and
//! `/FieldMDP` for field-level locking.

use lopdf::{Dictionary, Object};

/// Permitted changes level for a certification signature (DocMDP).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DocMdpPermissions {
    /// No changes allowed
    NoChanges = 1,
    /// Form filling and signing only
    #[default]
    FormFillingAndSigning = 2,
    /// Form filling, signing, and annotation
    FormFillingSigningAndAnnotation = 3,
}

impl DocMdpPermissions {
    /// The `/P` value used in the DocMDP `TransformParams` dictionary.
    pub fn as_p(self) -> i64 {
        self as i64
    }
}

/// Build the `/Reference` array for a certification (DocMDP) signature.
///
/// This goes in the signature dictionary. Per PDF 32000-1 §12.8.2.2 it carries
/// a single signature-reference dictionary using the `DocMDP` transform method
/// with a `TransformParams` `/P` permission level and `/V 1.2`:
///
/// ```text
/// /Reference [ << /Type /SigRef
///                 /TransformMethod /DocMDP
///                 /TransformParams << /Type /TransformParams /P n /V /1.2 >> >> ]
/// ```
///
/// The catalog must additionally carry `/Perms << /DocMDP <sig dict ref> >>`
/// pointing back at the signature dictionary (see [`build_docmdp_perms`]).
pub fn build_docmdp_reference(perms: DocMdpPermissions) -> Object {
    let mut transform_params = Dictionary::new();
    transform_params.set("Type", Object::Name(b"TransformParams".to_vec()));
    transform_params.set("P", Object::Integer(perms.as_p()));
    transform_params.set("V", Object::Name(b"1.2".to_vec()));

    let mut sig_ref = Dictionary::new();
    sig_ref.set("Type", Object::Name(b"SigRef".to_vec()));
    sig_ref.set("TransformMethod", Object::Name(b"DocMDP".to_vec()));
    sig_ref.set("TransformParams", Object::Dictionary(transform_params));

    Object::Array(vec![Object::Dictionary(sig_ref)])
}

/// Build the catalog `/Perms` dictionary for a certification signature,
/// referencing the certifying signature dictionary by object id.
pub fn build_docmdp_perms(sig_dict_id: lopdf::ObjectId) -> Dictionary {
    let mut perms = Dictionary::new();
    perms.set("DocMDP", Object::Reference(sig_dict_id));
    perms
}
