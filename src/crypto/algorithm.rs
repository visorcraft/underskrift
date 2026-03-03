//! Digest and signature algorithm enumerations.

use const_oid::ObjectIdentifier;

/// Supported digest (hash) algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl DigestAlgorithm {
    /// OID for this digest algorithm.
    pub fn oid(&self) -> ObjectIdentifier {
        match self {
            // 2.16.840.1.101.3.4.2.1
            DigestAlgorithm::Sha256 => ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1"),
            // 2.16.840.1.101.3.4.2.2
            DigestAlgorithm::Sha384 => ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2"),
            // 2.16.840.1.101.3.4.2.3
            DigestAlgorithm::Sha512 => ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3"),
        }
    }

    /// Compute the digest of the given data.
    pub fn digest(&self, data: &[u8]) -> Vec<u8> {
        use sha2::Digest;
        match self {
            DigestAlgorithm::Sha256 => sha2::Sha256::digest(data).to_vec(),
            DigestAlgorithm::Sha384 => sha2::Sha384::digest(data).to_vec(),
            DigestAlgorithm::Sha512 => sha2::Sha512::digest(data).to_vec(),
        }
    }

    /// Create a streaming hasher for this algorithm.
    ///
    /// Use this when you need to hash data in multiple chunks (e.g., the two
    /// ByteRange segments for PDF signing).
    pub fn new_hasher(&self) -> DigestHasher {
        use sha2::Digest;
        match self {
            DigestAlgorithm::Sha256 => DigestHasher::Sha256(sha2::Sha256::new()),
            DigestAlgorithm::Sha384 => DigestHasher::Sha384(sha2::Sha384::new()),
            DigestAlgorithm::Sha512 => DigestHasher::Sha512(sha2::Sha512::new()),
        }
    }
}

/// Streaming hasher that supports incremental updates.
pub enum DigestHasher {
    Sha256(sha2::Sha256),
    Sha384(sha2::Sha384),
    Sha512(sha2::Sha512),
}

impl DigestHasher {
    /// Feed data into the hasher.
    pub fn update(&mut self, data: &[u8]) {
        use sha2::Digest;
        match self {
            DigestHasher::Sha256(h) => h.update(data),
            DigestHasher::Sha384(h) => h.update(data),
            DigestHasher::Sha512(h) => h.update(data),
        }
    }

    /// Finalize the hash and return the digest bytes.
    pub fn finalize(self) -> Vec<u8> {
        use sha2::Digest;
        match self {
            DigestHasher::Sha256(h) => h.finalize().to_vec(),
            DigestHasher::Sha384(h) => h.finalize().to_vec(),
            DigestHasher::Sha512(h) => h.finalize().to_vec(),
        }
    }
}

impl Default for DigestAlgorithm {
    fn default() -> Self {
        Self::Sha256
    }
}

/// Supported signature algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// RSA with PKCS#1 v1.5 padding
    RsaPkcs1v15,
    /// RSA with PSS padding
    RsaPss,
    /// ECDSA with P-256 curve
    EcdsaP256,
    /// ECDSA with P-384 curve
    EcdsaP384,
    /// EdDSA with Ed25519 curve
    Ed25519,
}
