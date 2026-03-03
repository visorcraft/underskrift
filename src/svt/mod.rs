//! # SVT — Signature Validation Tokens (RFC 9321)
//!
//! This module implements issuance and validation of Signature Validation
//! Tokens as defined in [RFC 9321](https://www.rfc-editor.org/rfc/rfc9321).
//!
//! An SVT is a signed JWT that records the result of validating a digital
//! signature at a specific point in time. For PDF signatures, the SVT is
//! typically embedded via a Document Timestamp (`/DocTimeStamp`) dictionary.
//!
//! ## Feature flag
//!
//! This module is gated behind the `svt` cargo feature:
//!
//! ```toml
//! [dependencies]
//! underskrift = { version = "0.1", features = ["svt"] }
//! ```
//!
//! ## Architecture
//!
//! - [`claims`] — Data types for all SVT JWT claim structures
//! - [`algo`] — Algorithm registry mapping JWS algorithms to digest URIs
//! - [`issuer`] — SVT issuance: build claims from verification results, sign JWT
//! - [`validator`] — SVT validation: verify JWT, compare signature hashes
//!
//! ## Quick Start — Issuance
//!
//! ```no_run
//! # use underskrift::svt::*;
//! # fn example() -> Result<(), underskrift::error::SvtError> {
//! // After verifying a PDF signature, build SVT claims:
//! let model = SvtModel::builder()
//!     .issuer_id("https://svt.example.com")
//!     .build();
//!
//! // Use SvtIssuer to create a signed JWT
//! // (requires a signing key and certificate chain)
//! # Ok(())
//! # }
//! ```

pub mod algo;
pub mod claims;
pub mod issuer;
pub mod validator;

// Re-exports for convenience
pub use claims::{
    CertRefType, CertReferenceClaims, PolicyValidationClaims, SVTProfile, SigReferenceClaims,
    SignatureClaims, SignedDataClaims, SvtClaims, TimeValidationClaims, ValidationConclusion,
};
pub use issuer::{SvtIssuer, SvtModel};
pub use validator::{SignatureSvtData, SvtValidationResult, SvtValidator};
