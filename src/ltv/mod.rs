//! Long-term validation (LTV) support.
//!
//! Embeds revocation information (OCSP responses, CRLs) and certificates
//! into the PDF's Document Security Store (DSS) for offline validation.
//!
//! # Architecture
//!
//! - [`DssBuilder`] — Collects and builds the DSS dictionary
//! - [`OcspClient`] — Fetches OCSP responses from responders
//! - [`CrlClient`] — Fetches and caches CRLs from distribution points
//! - [`ChainBuilder`] — Discovers intermediate certs via AIA extensions
//!
//! # PAdES Levels
//!
//! | Level | LTV Data |
//! |-------|----------|
//! | B-B   | None |
//! | B-T   | Timestamp only |
//! | B-LT  | DSS with certs, OCSP, CRLs |
//! | B-LTA | DSS + document timestamp |

pub mod chain;
pub mod crl;
pub mod dss;
pub mod ocsp;

// Re-exports
pub use chain::ChainBuilder;
pub use crl::CrlClient;
pub use dss::{DssBuilder, VriEntry, compute_vri_key};
pub use ocsp::{OcspClient, AiaAccessMethod, extract_aia_urls};
