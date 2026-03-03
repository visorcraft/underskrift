//! ETSI TS 119 102-2 signature validation reports.
//!
//! This module generates XML validation reports conforming to
//! **ETSI TS 119 102-2** (v1.3.1) — the standard format for communicating
//! the result of electronic signature validation. It converts the
//! [`VerificationReport`](crate::verify::report::VerificationReport) from
//! the `verify` module into standards-compliant XML.
//!
//! The XML output uses the namespace `http://uri.etsi.org/19102/v1.2.1#`
//! (prefix `vr:`) and includes:
//!
//! - **`SignatureValidationReport`** for each signature found
//! - **`SignatureValidationStatus`** with MainIndication and SubIndications
//! - **`SignerInformation`**, **`ValidationTimeInfo`**, **`SignatureAttributes`**
//! - Optional **`SignatureValidator`** metadata
//!
//! # Feature Gate
//!
//! This module requires the `report` feature, which also enables `verify`.
//!
//! # Example
//!
//! ```no_run
//! # #[cfg(feature = "report")]
//! # {
//! use underskrift::report::{EtsiReportGenerator, ReportOptions};
//! // Assume `report` is a VerificationReport from the verify module
//! # let report = todo!();
//!
//! let opts = ReportOptions {
//!     validator_name: Some("My Validator".into()),
//!     ..Default::default()
//! };
//! let gen = EtsiReportGenerator::new(opts);
//! let xml = gen.generate(&report).unwrap();
//! println!("{}", xml);
//! # }
//! ```

pub mod generator;
pub mod types;

pub use generator::EtsiReportGenerator;
pub use types::{
    MainIndication, POEType, ReportOptions, RepresentationType, SignatureQuality, SubIndication,
    ValidationObject, ValidationObjectCollector, ValidationObjectType, NS_DS, NS_VR, NS_XADES,
    POLICY_BASIC, POLICY_PKIX, POLICY_SVT_PKIX, POLICY_SVT_TS_PKIX, POLICY_TS_PKIX, QUALITY_ADES,
    QUALITY_ETSI, QUALITY_QC, QUALITY_QC_QSCD, REPORT_STATUS_MESSAGE,
    SUBINDICATION_PARTIALLY_SIGNED,
};
