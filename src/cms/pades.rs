//! PAdES-specific CMS construction.
//!
//! PAdES (ETSI.CAdES.detached) requires:
//! - `signingCertificateV2` signed attribute (ESS)
//! - No `signingTime` attribute (time comes from timestamps)
//! - Content type `id-data`
//! - Detached signature (no encapsulated content)
