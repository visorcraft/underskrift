//! The `CryptoSigner` trait — signing key abstraction.
//!
//! This trait is the extension point for custom signing backends. The library
//! provides `SoftwareSigner` for file-based keys; users can implement this
//! trait for HSMs, cloud KMS, remote signing services, etc.

use crate::crypto::algorithm::{DigestAlgorithm, SignatureAlgorithm};
use crate::error::CryptoError;

/// Abstraction over a signing key and its associated certificate chain.
///
/// Implementors provide:
/// - The signing operation (either hash-then-sign or raw-data sign)
/// - The signer's certificate and chain
/// - Algorithm metadata
///
/// # Dual signing methods
///
/// - [`sign_hash`](CryptoSigner::sign_hash): signs a pre-computed hash digest.
///   Best for software keys where you control the full pipeline.
/// - [`sign_data`](CryptoSigner::sign_data): signs raw data bytes. The default
///   implementation hashes with the configured digest algorithm, then calls
///   `sign_hash`. Override this if your backend (e.g., cloud KMS) needs to
///   hash internally.
pub trait CryptoSigner: Send + Sync {
    /// Sign a pre-computed hash digest.
    fn sign_hash(&self, hash: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Sign raw data bytes.
    ///
    /// Default implementation: hash with [`digest_algorithm`], then call [`sign_hash`].
    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let hash = self.digest_algorithm().digest(data);
        self.sign_hash(&hash)
    }

    /// The signing certificate (DER-encoded X.509).
    fn certificate_der(&self) -> &[u8];

    /// The certificate chain (DER-encoded), from signer cert to root.
    /// The first element should be the signer certificate.
    fn certificate_chain_der(&self) -> Vec<&[u8]>;

    /// The digest algorithm to use.
    fn digest_algorithm(&self) -> DigestAlgorithm;

    /// The signature algorithm in use.
    fn signature_algorithm(&self) -> SignatureAlgorithm;
}
