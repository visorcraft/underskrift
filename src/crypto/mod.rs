//! Signing key abstraction and software-based backends.

// Re-export shared crypto from tsp-ltv
pub use tsp_ltv::crypto::algorithm;
pub use tsp_ltv::crypto::verify;

// Local modules (private key operations, signer traits)
pub mod software;
pub mod traits;
