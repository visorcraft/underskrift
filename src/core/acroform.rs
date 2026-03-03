//! AcroForm dictionary management.
//!
//! Handles creating or updating the document's `/AcroForm` dictionary,
//! including `/SigFlags` and the `/Fields` array. Also handles adding
//! signature field references to the AcroForm and page annotations.

use lopdf::{Dictionary, Document, Object, ObjectId};

use crate::error::CoreError;

/// SigFlags bits for the AcroForm dictionary.
///
/// Bit 1 (value 1): SignaturesExist — the document contains signatures.
/// Bit 2 (value 2): AppendOnly — the document was signed with append-only mode.
const SIG_FLAGS: i64 = 3; // bits 1 + 2

/// Ensures the document has an AcroForm dictionary with the correct SigFlags,
/// adds the signature field to the Fields array, and adds the annotation
/// reference to the target page's /Annots array.
///
/// This function modifies the document's catalog in-place.
///
/// # Arguments
///
/// * `doc` — the parsed PDF document (lopdf)
/// * `sig_field_id` — the object ID of the signature field (combined field+widget)
/// * `page_index` — the 0-indexed page number to place the annotation on
pub fn ensure_acroform(
    doc: &mut Document,
    sig_field_id: ObjectId,
    page_index: u32,
) -> Result<(), CoreError> {
    // 1. Get the root catalog object ID
    let catalog_id = doc
        .trailer
        .get(b"Root")
        .and_then(Object::as_reference)
        .map_err(|_| CoreError::InvalidStructure("trailer missing /Root reference".into()))?;

    // 2. Add signature field reference to AcroForm/Fields
    add_field_to_acroform(doc, catalog_id, sig_field_id)?;

    // 3. Add annotation reference to page /Annots
    add_annot_to_page(doc, sig_field_id, page_index)?;

    Ok(())
}

/// Adds the signature field to the AcroForm's /Fields array and sets SigFlags.
///
/// If the catalog doesn't have an /AcroForm yet, creates one as a new indirect
/// object and adds it to the catalog.
fn add_field_to_acroform(
    doc: &mut Document,
    catalog_id: ObjectId,
    sig_field_id: ObjectId,
) -> Result<(), CoreError> {
    let catalog = doc
        .get_object(catalog_id)
        .map_err(|e| CoreError::AcroForm(format!("failed to get catalog: {e}")))?
        .as_dict()
        .map_err(|e| CoreError::AcroForm(format!("catalog is not a dictionary: {e}")))?
        .clone();

    if let Ok(acroform_ref) = catalog.get(b"AcroForm") {
        // AcroForm exists — may be an indirect reference or inline dictionary
        match acroform_ref {
            Object::Reference(af_id) => {
                let af_id = *af_id;
                // Modify the existing AcroForm object
                let acroform = doc
                    .get_object_mut(af_id)
                    .map_err(|e| {
                        CoreError::AcroForm(format!("failed to get AcroForm object: {e}"))
                    })?
                    .as_dict_mut()
                    .map_err(|e| {
                        CoreError::AcroForm(format!("AcroForm is not a dictionary: {e}"))
                    })?;
                update_acroform_dict(acroform, sig_field_id)?;
            }
            Object::Dictionary(_) => {
                // Inline dictionary in the catalog — clone it out, modify, create as indirect
                let mut acroform_dict = acroform_ref
                    .as_dict()
                    .map_err(|e| CoreError::AcroForm(format!("AcroForm is not a dictionary: {e}")))?
                    .clone();
                update_acroform_dict(&mut acroform_dict, sig_field_id)?;
                let af_id = doc.add_object(Object::Dictionary(acroform_dict));
                // Update catalog to reference the new indirect AcroForm
                let catalog_mut = doc
                    .get_object_mut(catalog_id)
                    .map_err(|e| CoreError::AcroForm(format!("failed to get catalog: {e}")))?
                    .as_dict_mut()
                    .map_err(|e| {
                        CoreError::AcroForm(format!("catalog is not a dictionary: {e}"))
                    })?;
                catalog_mut.set("AcroForm", Object::Reference(af_id));
            }
            _ => {
                return Err(CoreError::AcroForm(
                    "AcroForm entry is neither a reference nor a dictionary".into(),
                ));
            }
        }
    } else {
        // No AcroForm — create a new one
        let mut acroform_dict = Dictionary::new();
        acroform_dict.set(
            "Fields",
            Object::Array(vec![Object::Reference(sig_field_id)]),
        );
        acroform_dict.set("SigFlags", Object::Integer(SIG_FLAGS));

        let af_id = doc.add_object(Object::Dictionary(acroform_dict));
        let catalog_mut = doc
            .get_object_mut(catalog_id)
            .map_err(|e| CoreError::AcroForm(format!("failed to get catalog: {e}")))?
            .as_dict_mut()
            .map_err(|e| CoreError::AcroForm(format!("catalog is not a dictionary: {e}")))?;
        catalog_mut.set("AcroForm", Object::Reference(af_id));
    }

    Ok(())
}

/// Updates an existing AcroForm dictionary: appends the sig field to /Fields
/// and ensures /SigFlags is set.
fn update_acroform_dict(
    acroform: &mut Dictionary,
    sig_field_id: ObjectId,
) -> Result<(), CoreError> {
    // Update SigFlags
    acroform.set("SigFlags", Object::Integer(SIG_FLAGS));

    // Add to Fields array
    if let Ok(fields) = acroform.get_mut(b"Fields") {
        match fields {
            Object::Array(arr) => {
                arr.push(Object::Reference(sig_field_id));
            }
            _ => {
                // Fields exists but isn't an array — replace it
                acroform.set(
                    "Fields",
                    Object::Array(vec![Object::Reference(sig_field_id)]),
                );
            }
        }
    } else {
        // No Fields array yet
        acroform.set(
            "Fields",
            Object::Array(vec![Object::Reference(sig_field_id)]),
        );
    }

    Ok(())
}

/// Adds the signature annotation reference to the target page's /Annots array.
fn add_annot_to_page(
    doc: &mut Document,
    annot_id: ObjectId,
    page_index: u32,
) -> Result<(), CoreError> {
    // Get the page object ID (pages are 1-indexed in lopdf's get_pages())
    let pages = doc.get_pages();
    let page_num = page_index + 1; // convert 0-indexed to 1-indexed
    let page_id = pages.get(&page_num).copied().ok_or_else(|| {
        CoreError::AcroForm(format!(
            "page {page_index} (1-indexed: {page_num}) not found"
        ))
    })?;

    // Get the page dictionary and update /Annots
    let page = doc
        .get_object_mut(page_id)
        .map_err(|e| CoreError::AcroForm(format!("failed to get page object: {e}")))?
        .as_dict_mut()
        .map_err(|e| CoreError::AcroForm(format!("page is not a dictionary: {e}")))?;

    if let Ok(annots) = page.get_mut(b"Annots") {
        match annots {
            Object::Array(arr) => {
                arr.push(Object::Reference(annot_id));
            }
            Object::Reference(_annots_ref) => {
                // /Annots is an indirect reference to an array.
                // We need to dereference, clone, modify, and create a new indirect array.
                // For simplicity, replace with inline array containing the old ref + new ref.
                let old_ref = annots.clone();
                *annots = Object::Array(vec![old_ref, Object::Reference(annot_id)]);
            }
            _ => {
                page.set("Annots", Object::Array(vec![Object::Reference(annot_id)]));
            }
        }
    } else {
        page.set("Annots", Object::Array(vec![Object::Reference(annot_id)]));
    }

    Ok(())
}
