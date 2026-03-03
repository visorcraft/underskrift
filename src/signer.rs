//! High-level PDF signer builder and orchestrator.
//!
//! `PdfSigner` is the main entry point for signing PDFs. It uses a builder
//! pattern to configure signing options, then orchestrates the full flow:
//! parse PDF -> prepare signature structures -> compute hash -> sign -> embed.

use lopdf::{Document, Object};

use crate::cms::builder::{CmsProfile, PdfCmsBuilder};
use crate::core::acroform;
use crate::core::incremental::IncrementalWriter;
use crate::core::parser;
use crate::core::sig_dict::{self, SigSubFilter};
use crate::core::sig_field::{self, SignatureFieldOptions};
use crate::crypto::algorithm::DigestAlgorithm;
use crate::crypto::traits::CryptoSigner;
use crate::error::{CoreError, PdfSignError};

/// PAdES conformance level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PadesLevel {
    /// PAdES Baseline B-B (basic signature)
    BB,
    /// PAdES Baseline B-T (with timestamp)
    BT,
    /// PAdES Baseline B-LT (with LTV data)
    BLT,
    /// PAdES Baseline B-LTA (with archive timestamp)
    BLTA,
}

impl Default for PadesLevel {
    fn default() -> Self {
        Self::BB
    }
}

/// SubFilter selection for the public API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubFilter {
    /// PAdES: ETSI.CAdES.detached
    Pades,
    /// Traditional: adbe.pkcs7.detached
    Pkcs7,
}

impl Default for SubFilter {
    fn default() -> Self {
        Self::Pades
    }
}

impl From<SubFilter> for SigSubFilter {
    fn from(sf: SubFilter) -> Self {
        match sf {
            SubFilter::Pades => SigSubFilter::EtsiCadesDetached,
            SubFilter::Pkcs7 => SigSubFilter::AdbePkcs7Detached,
        }
    }
}

/// Configuration options for PDF signing.
#[derive(Debug, Clone)]
pub struct SigningOptions {
    /// The signature sub-filter to use
    pub sub_filter: SubFilter,
    /// PAdES conformance level (only relevant when sub_filter is Pades)
    pub pades_level: PadesLevel,
    /// Digest algorithm
    pub digest_algorithm: DigestAlgorithm,
    /// Signature field name
    pub field_name: String,
    /// Page to place the signature annotation (0-indexed)
    pub page: u32,
    /// Reason for signing
    pub reason: Option<String>,
    /// Signer location
    pub location: Option<String>,
    /// Signer contact info
    pub contact_info: Option<String>,
    /// Size to reserve for the /Contents hex string (in bytes, not hex chars).
    /// Default is 8192 bytes (16384 hex chars). Increase for large cert chains
    /// or if timestamps are included.
    pub content_size: usize,
    /// TSA URL for timestamping (required for B-T and above)
    #[cfg(feature = "tsp")]
    pub tsa_url: Option<String>,
    /// Whether this is a certification signature (first signature with DocMDP)
    pub certify: bool,
}

impl Default for SigningOptions {
    fn default() -> Self {
        Self {
            sub_filter: SubFilter::default(),
            pades_level: PadesLevel::default(),
            digest_algorithm: DigestAlgorithm::default(),
            field_name: "Signature1".to_string(),
            page: 0,
            reason: None,
            location: None,
            contact_info: None,
            content_size: 8192,
            #[cfg(feature = "tsp")]
            tsa_url: None,
            certify: false,
        }
    }
}

/// High-level PDF signer.
///
/// # Example
///
/// ```no_run
/// use underskrift::{PdfSigner, SigningOptions, SoftwareSigner};
///
/// # async fn example() -> Result<(), underskrift::PdfSignError> {
/// let pdf = std::fs::read("document.pdf")?;
/// let signer = SoftwareSigner::from_pkcs12_file("key.p12", "pass")?;
///
/// let signed = PdfSigner::new()
///     .options(SigningOptions::default())
///     .sign(&pdf, &signer)
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct PdfSigner {
    options: SigningOptions,
}

impl PdfSigner {
    /// Create a new PdfSigner with default options.
    pub fn new() -> Self {
        Self {
            options: SigningOptions::default(),
        }
    }

    /// Set signing options.
    pub fn options(mut self, options: SigningOptions) -> Self {
        self.options = options;
        self
    }

    /// Sign a PDF document.
    ///
    /// Takes the original PDF bytes and a signer implementation.
    /// Returns the signed PDF bytes (original + incremental update).
    ///
    /// # Flow
    ///
    /// 1. Parse the PDF with lopdf
    /// 2. Create signature dictionary with ByteRange/Contents placeholders
    /// 3. Create signature field (combined form field + widget annotation)
    /// 4. Update AcroForm + page annotations
    /// 5. Write incremental update with custom byte-level writer
    /// 6. Compute hash of ByteRange-selected bytes
    /// 7. Build CMS SignedData with the hash
    /// 8. Inject signature into /Contents and backpatch ByteRange
    pub async fn sign(
        &self,
        pdf_data: &[u8],
        signer: &dyn CryptoSigner,
    ) -> Result<Vec<u8>, PdfSignError> {
        // Step 1: Parse the PDF
        let mut doc = Document::load_mem(pdf_data)
            .map_err(|e| CoreError::Lopdf(e))?;

        // Step 2: Extract metadata needed for incremental writer
        let meta = parser::extract_metadata(&doc)?;
        log::debug!(
            "PDF metadata: xref_offset={}, trailer_size={}, root={:?}, max_id={}",
            meta.xref_offset,
            meta.trailer_size,
            meta.root_id,
            meta.max_id,
        );

        // Step 3: Build the signature dictionary
        let sub_filter: SigSubFilter = self.options.sub_filter.into();
        // contents_size is in bytes; hex encoding doubles it
        let contents_hex_size = self.options.content_size * 2;
        let mut sig_dict = sig_dict::build_sig_dict(sub_filter, self.options.content_size);

        // Add optional entries to the sig dict
        if let Some(reason) = &self.options.reason {
            sig_dict.set(
                "Reason",
                Object::String(reason.as_bytes().to_vec(), lopdf::StringFormat::Literal),
            );
        }
        if let Some(location) = &self.options.location {
            sig_dict.set(
                "Location",
                Object::String(location.as_bytes().to_vec(), lopdf::StringFormat::Literal),
            );
        }
        if let Some(contact) = &self.options.contact_info {
            sig_dict.set(
                "ContactInfo",
                Object::String(contact.as_bytes().to_vec(), lopdf::StringFormat::Literal),
            );
        }

        // Step 4: Add sig dict as a new object
        let sig_dict_id = doc.add_object(Object::Dictionary(sig_dict));

        // Step 5: Build the signature field
        let field_opts = SignatureFieldOptions {
            name: self.options.field_name.clone(),
            page: self.options.page,
            rect: [0.0, 0.0, 0.0, 0.0], // invisible signature
        };
        let sig_field_dict = sig_field::build_sig_field(&field_opts, sig_dict_id);
        let sig_field_id = doc.add_object(Object::Dictionary(sig_field_dict));

        // Step 6: Update AcroForm and page annotations
        acroform::ensure_acroform(&mut doc, sig_field_id, self.options.page)?;

        // Step 7: Build the incremental update
        // We need to collect all new/modified objects to write.
        // The IncrementalWriter takes the original PDF bytes and appends new objects.
        let mut writer = IncrementalWriter::new(
            pdf_data.to_vec(),
            meta.trailer_size,
            meta.xref_offset,
            meta.root_id,
            contents_hex_size,
        );

        // Add all objects that are new or modified.
        // New objects: sig_dict, sig_field
        // Modified objects: catalog (AcroForm reference), page (Annots), and possibly the AcroForm itself
        writer.set_sig_dict_id(sig_dict_id);

        // Add all objects from the document that have IDs > the original max
        // (these are the new objects we created), plus any modified objects.
        // For simplicity, we add the sig dict, sig field, and re-serialize
        // any objects that were modified (catalog, acroform, page).
        let catalog_id = meta.root_id;

        // Add sig dict
        if let Ok(obj) = doc.get_object(sig_dict_id) {
            writer.add_object(sig_dict_id, obj.clone());
        }

        // Add sig field
        if let Ok(obj) = doc.get_object(sig_field_id) {
            writer.add_object(sig_field_id, obj.clone());
        }

        // Add modified catalog (has new/updated AcroForm reference)
        if let Ok(obj) = doc.get_object(catalog_id) {
            writer.add_object(catalog_id, obj.clone());
        }

        // Add the AcroForm object if it's an indirect reference
        if let Ok(catalog_dict) = doc.get_object(catalog_id).and_then(|o| o.as_dict()) {
            if let Ok(Object::Reference(af_id)) = catalog_dict.get(b"AcroForm") {
                if let Ok(obj) = doc.get_object(*af_id) {
                    writer.add_object(*af_id, obj.clone());
                }
            }
        }

        // Add the modified page (has new Annots entry)
        let pages = doc.get_pages();
        let page_num = self.options.page + 1;
        if let Some(&page_id) = pages.get(&page_num) {
            if let Ok(obj) = doc.get_object(page_id) {
                writer.add_object(page_id, obj.clone());
            }
        }

        // Step 8: Write the incremental update
        let (mut output, byte_range) = writer.write()?;

        // Step 9: Compute hash of the byte-range-selected bytes
        let br_values = byte_range.compute(output.len());
        let range1 = &output[br_values[0]..br_values[0] + br_values[1]];
        let range2 = &output[br_values[2]..br_values[2] + br_values[3]];

        let digest_alg = signer.digest_algorithm();
        let mut hasher = digest_alg.new_hasher();
        hasher.update(range1);
        hasher.update(range2);
        let data_hash = hasher.finalize();

        // Step 10: Build the CMS SignedData
        let cms_profile = match self.options.sub_filter {
            SubFilter::Pades => CmsProfile::Pades,
            SubFilter::Pkcs7 => CmsProfile::Traditional,
        };
        let cms_builder = PdfCmsBuilder::new(signer).profile(cms_profile);
        let cms_der = cms_builder.build(&data_hash)?;

        // Step 11: Check that the CMS signature fits in the allocated space
        if cms_der.len() > self.options.content_size {
            return Err(PdfSignError::Core(CoreError::SignatureTooLarge {
                actual: cms_der.len(),
                allocated: self.options.content_size,
            }));
        }

        // Step 12: Inject the CMS signature into /Contents
        // The hex-encoded signature replaces the zero-placeholder
        let hex_sig = hex::encode_upper(&cms_der);
        let hex_bytes = hex_sig.as_bytes();

        // Write hex signature, left-aligned, zero-padded
        let start = byte_range.contents_offset;
        let end = byte_range.contents_offset + byte_range.contents_length;
        // Fill with zeros first (already there), then overwrite with actual signature
        output[start..start + hex_bytes.len()].copy_from_slice(hex_bytes);
        // Remaining bytes stay as '0' (padding)
        for b in &mut output[start + hex_bytes.len()..end] {
            *b = b'0';
        }

        Ok(output)
    }
}

impl Default for PdfSigner {
    fn default() -> Self {
        Self::new()
    }
}
