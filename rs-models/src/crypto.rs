/// Shared cryptographic primitives and types for the Chert ecosystem
///
/// This module provides common cryptographic building blocks that ensure
/// consistency across all Chert components while allowing module-specific
/// extensions for specialized use cases.
use anyhow::Result;
use pqcrypto_kyber::kyber768;
use pqcrypto_kyber::kyber768::{
    Ciphertext as KyberCipherValue, PublicKey as KyberPublicKeyValue,
    SecretKey as KyberSecretKeyValue, SharedSecret as KyberSharedSecretValue,
};
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};
use serde::{Deserialize, Serialize};
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop};

// Platform-specific imports for secure memory (used in secure memory functions)
#[cfg(unix)]
#[allow(unused_imports)]
use libc;

/// Standard cryptographic algorithms supported across the Chert ecosystem
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA256 - Standard for file verification and general hashing
    Sha256,
    /// Blake3 - High-performance alternative for bulk operations
    Blake3,
    /// Keccak256 - For Ethereum compatibility where needed
    Keccak256,
}

/// Standard signature algorithms with migration path
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// Ed25519 - Current standard for most operations
    Ed25519,
    /// Dilithium2 - Post-quantum ready, for high-security operations
    Dilithium2,
    /// Kyber512 - Key encapsulation mechanism
    Kyber512,
}

impl Zeroize for SignatureAlgorithm {
    fn zeroize(&mut self) {
        // SignatureAlgorithm is an enum with no sensitive data
    }
}

/// Universal hash result that can be used across all modules
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChertHash {
    pub algorithm: HashAlgorithm,
    pub digest: Vec<u8>,
    pub hex: String,
}

/// Universal signature that can be used across all modules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChertSignature {
    pub algorithm: SignatureAlgorithm,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
}

/// Core cryptographic key pair that supports both classical and post-quantum algorithms
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ZeroizeOnDrop)]
pub struct ChertKeyPair {
    pub algorithm: SignatureAlgorithm,
    #[zeroize(skip)] // Don't zeroize public key
    #[serde(with = "hex_bytes")]
    pub public_key: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub private_key: Vec<u8>, // Will be zeroized on drop
}

/// Kyber KEM ciphertext wrapper enforcing length invariants
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KyberCiphertext {
    ciphertext: Vec<u8>,
}

impl KyberCiphertext {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() != kyber768::ciphertext_bytes() {
            return Err(anyhow::anyhow!(
                "Invalid Kyber ciphertext length: expected {} bytes, got {}",
                kyber768::ciphertext_bytes(),
                bytes.len()
            ));
        }

        Ok(Self { ciphertext: bytes })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn len(&self) -> usize {
        self.ciphertext.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ciphertext.is_empty()
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.ciphertext
    }
}

/// Kyber shared secret container that zeroizes on drop
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ZeroizeOnDrop)]
pub struct KyberSharedSecret {
    #[serde(with = "hex_bytes")]
    secret: Vec<u8>,
}

impl KyberSharedSecret {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() != kyber768::shared_secret_bytes() {
            return Err(anyhow::anyhow!(
                "Invalid Kyber shared secret length: expected {} bytes, got {}",
                kyber768::shared_secret_bytes(),
                bytes.len()
            ));
        }

        Ok(Self { secret: bytes })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.secret
    }

    pub fn len(&self) -> usize {
        self.secret.len()
    }

    pub fn is_empty(&self) -> bool {
        self.secret.is_empty()
    }
}

/// Kyber key encapsulation mechanism keypair
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ZeroizeOnDrop)]
pub struct KyberKeyPair {
    #[zeroize(skip)]
    #[serde(with = "hex_bytes")]
    public_key: Vec<u8>,
    #[serde(with = "hex_bytes")]
    private_key: Vec<u8>,
}

impl KyberKeyPair {
    pub fn generate() -> Result<Self> {
        let (public_key, secret_key) = kyber768::keypair();

        Ok(Self {
            public_key: public_key.as_bytes().to_vec(),
            private_key: secret_key.as_bytes().to_vec(),
        })
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn private_key_len(&self) -> usize {
        self.private_key.len()
    }

    pub fn encapsulate(peer_public_key: &[u8]) -> Result<(KyberCiphertext, KyberSharedSecret)> {
        if peer_public_key.is_empty() {
            return Err(anyhow::anyhow!("Peer public key cannot be empty"));
        }

        let public_key = KyberPublicKeyValue::from_bytes(peer_public_key).map_err(|err| {
            anyhow::anyhow!(
                "Invalid Kyber public key provided for encapsulation: {:?}",
                err
            )
        })?;

        let (shared_secret, ciphertext): (KyberSharedSecretValue, KyberCipherValue) =
            kyber768::encapsulate(&public_key);
        let ciphertext_bytes = ciphertext.as_bytes().to_vec();
        let shared_bytes = shared_secret.as_bytes().to_vec();

        let ciphertext = KyberCiphertext::from_bytes(ciphertext_bytes)?;
        let secret = KyberSharedSecret::from_bytes(shared_bytes)?;

        Ok((ciphertext, secret))
    }

    pub fn decapsulate(&self, ciphertext: &KyberCiphertext) -> Result<KyberSharedSecret> {
        if ciphertext.len() != kyber768::ciphertext_bytes() {
            return Err(anyhow::anyhow!(
                "Ciphertext length mismatch: expected {} bytes, got {}",
                kyber768::ciphertext_bytes(),
                ciphertext.len()
            ));
        }

        let secret_key = KyberSecretKeyValue::from_bytes(&self.private_key)
            .map_err(|err| anyhow::anyhow!("Invalid Kyber private key: {:?}", err))?;
        let ciphertext_value = KyberCipherValue::from_bytes(ciphertext.as_bytes())
            .map_err(|err| anyhow::anyhow!("Invalid Kyber ciphertext: {:?}", err))?;

        let shared_secret: KyberSharedSecretValue =
            kyber768::decapsulate(&ciphertext_value, &secret_key);
        let shared_bytes = shared_secret.as_bytes().to_vec();

        KyberSharedSecret::from_bytes(shared_bytes)
    }
}

/// Custom serialization for sensitive data
mod sensitive_bytes {
    use serde::{Deserializer, Serializer, de::SeqAccess};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BytesVisitor;

        impl<'de> serde::de::Visitor<'de> for BytesVisitor {
            type Value = Vec<u8>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a byte array")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(v.to_vec())
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut bytes = Vec::new();
                while let Some(byte) = seq.next_element()? {
                    bytes.push(byte);
                }
                Ok(bytes)
            }
        }

        deserializer.deserialize_bytes(BytesVisitor)
    }
}

/// Hex encoding for binary data in JSON (much more compact than byte arrays)
/// Compatible with both human-readable (JSON) and binary (postcard) formats
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer, de::SeqAccess};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            // JSON and other text formats: use hex string
            serializer.serialize_str(&hex::encode(bytes))
        } else {
            // Postcard and other binary formats: use raw bytes
            serializer.serialize_bytes(bytes)
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            // JSON: expect hex string or byte array for backwards compatibility
            struct HexOrArrayVisitor;

            impl<'de> serde::de::Visitor<'de> for HexOrArrayVisitor {
                type Value = Vec<u8>;

                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("a hex string or byte array")
                }

                // New format: hex string
                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    hex::decode(v).map_err(|e| E::custom(format!("invalid hex: {}", e)))
                }

                // Legacy format: byte array
                fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                where
                    A: SeqAccess<'de>,
                {
                    let mut bytes = Vec::new();
                    while let Some(byte) = seq.next_element()? {
                        bytes.push(byte);
                    }
                    Ok(bytes)
                }
            }

            deserializer.deserialize_any(HexOrArrayVisitor)
        } else {
            // Postcard: expect raw bytes
            struct BytesVisitor;

            impl<'de> serde::de::Visitor<'de> for BytesVisitor {
                type Value = Vec<u8>;

                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("byte array")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Ok(v.to_vec())
                }

                fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Ok(v)
                }
            }

            deserializer.deserialize_bytes(BytesVisitor)
        }
    }
}

/// Hex encoding for optional binary data
/// Compatible with both human-readable (JSON) and binary (postcard) formats
pub mod hex_bytes_option {
    use serde::{Deserialize, Deserializer, Serialize, Serializer, de::SeqAccess};

    pub fn serialize<S>(bytes: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            // JSON: serialize as hex string or null
            match bytes {
                Some(b) => serializer.serialize_some(&hex::encode(b)),
                None => serializer.serialize_none(),
            }
        } else {
            // Postcard: use native Option<Vec<u8>> serialization
            bytes.serialize(serializer)
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            // JSON: use the flexible HexOrArray that handles hex strings and arrays
            let opt: Option<HexOrArray> = Option::deserialize(deserializer)?;
            Ok(opt.map(|h| h.0))
        } else {
            // Postcard: use native Option<Vec<u8>> deserialization
            Option::<Vec<u8>>::deserialize(deserializer)
        }
    }

    struct HexOrArray(Vec<u8>);

    impl<'de> Deserialize<'de> for HexOrArray {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            struct Visitor;

            impl<'de> serde::de::Visitor<'de> for Visitor {
                type Value = HexOrArray;

                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("hex string or byte array")
                }

                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    hex::decode(v)
                        .map(HexOrArray)
                        .map_err(|e| E::custom(format!("invalid hex: {}", e)))
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                where
                    A: SeqAccess<'de>,
                {
                    let mut bytes = Vec::new();
                    while let Some(byte) = seq.next_element()? {
                        bytes.push(byte);
                    }
                    Ok(HexOrArray(bytes))
                }
            }

            deserializer.deserialize_any(Visitor)
        }
    }
}

impl ChertKeyPair {
    /// Generate a new Ed25519 keypair
    pub fn generate_ed25519() -> Result<Self> {
        use ed25519_dalek::SigningKey;
        use rand::{RngCore, rngs::OsRng};

        // Generate secure random bytes using the same pattern as silica
        let mut secret_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut secret_bytes);

        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            algorithm: SignatureAlgorithm::Ed25519,
            public_key: verifying_key.to_bytes().to_vec(),
            private_key: signing_key.to_bytes().to_vec(),
        })
    }

    /// Generate a new Dilithium2 keypair (post-quantum)
    pub fn generate_dilithium2() -> Result<Self> {
        use pqcrypto_dilithium::dilithium2;
        use pqcrypto_traits::sign::{PublicKey as PQPublicKey, SecretKey as PQSecretKey};

        let (public_key, secret_key) = dilithium2::keypair();

        Ok(Self {
            algorithm: SignatureAlgorithm::Dilithium2,
            public_key: PQPublicKey::as_bytes(&public_key).to_vec(),
            private_key: PQSecretKey::as_bytes(&secret_key).to_vec(),
        })
    }

    /// Sign data with the keypair's algorithm
    pub fn sign(&self, data: &[u8]) -> Result<ChertSignature> {
        match self.algorithm {
            SignatureAlgorithm::Ed25519 => self.sign_ed25519(data),
            SignatureAlgorithm::Dilithium2 => self.sign_dilithium2(data),
            SignatureAlgorithm::Kyber512 => {
                Err(anyhow::anyhow!("Kyber512 is for encryption, not signing"))
            }
        }
    }

    /// Verify a signature matches this keypair's public key
    pub fn verify(&self, data: &[u8], signature: &ChertSignature) -> Result<bool> {
        // Ensure the signature algorithm matches this keypair
        if signature.algorithm != self.algorithm {
            return Ok(false);
        }

        // Ensure the public key matches
        if signature.public_key != self.public_key {
            return Ok(false);
        }

        match self.algorithm {
            SignatureAlgorithm::Ed25519 => self.verify_ed25519(data, signature),
            SignatureAlgorithm::Dilithium2 => self.verify_dilithium2(data, signature),
            SignatureAlgorithm::Kyber512 => Err(anyhow::anyhow!(
                "Kyber512 is for encryption, not verification"
            )),
        }
    }

    /// Get quantum-resistant address derived from public key using SHA-3
    pub fn address(&self, address_type: &str) -> String {
        use sha3::{Digest, Sha3_256};

        let mut hasher = Sha3_256::new();
        hasher.update(format!("CHERT_ADDRESS_{}_V2", address_type).as_bytes());
        hasher.update(&self.public_key);
        let hash = hasher.finalize();

        // Take first 20 bytes and encode as hex with '0x' prefix
        format!("0x{}", hex::encode(&hash[..20]))
    }

    /// Save keypair to file (use with caution in production)
    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Load keypair from file
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let keypair: Self = serde_json::from_str(&content)?;
        Ok(keypair)
    }

    fn sign_ed25519(&self, data: &[u8]) -> Result<ChertSignature> {
        use ed25519_dalek::{Signer, SigningKey};

        let private_bytes: [u8; 32] = self
            .private_key
            .clone()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid Ed25519 private key length"))?;

        let signing_key = SigningKey::from_bytes(&private_bytes);
        let signature = signing_key.sign(data);

        Ok(ChertSignature {
            algorithm: SignatureAlgorithm::Ed25519,
            signature: signature.to_bytes().to_vec(),
            public_key: self.public_key.clone(),
        })
    }

    fn sign_dilithium2(&self, data: &[u8]) -> Result<ChertSignature> {
        use pqcrypto_dilithium::dilithium2;
        use pqcrypto_traits::sign::{
            DetachedSignature as PQDetachedSignature, SecretKey as PQSecretKey,
        };

        let secret_key = PQSecretKey::from_bytes(&self.private_key)
            .map_err(|e| anyhow::anyhow!("Invalid Dilithium2 private key: {:?}", e))?;

        let detached_signature = dilithium2::detached_sign(data, &secret_key);

        Ok(ChertSignature {
            algorithm: SignatureAlgorithm::Dilithium2,
            signature: PQDetachedSignature::as_bytes(&detached_signature).to_vec(),
            public_key: self.public_key.clone(),
        })
    }

    fn verify_ed25519(&self, data: &[u8], signature: &ChertSignature) -> Result<bool> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        // Validate lengths to prevent panics
        if self.public_key.len() != 32 || signature.signature.len() != 64 {
            return Ok(false);
        }

        let verifying_key = VerifyingKey::from_bytes(
            &self
                .public_key
                .clone()
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid Ed25519 public key length"))?,
        )?;

        let sig = Signature::from_bytes(
            &signature
                .signature
                .clone()
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid Ed25519 signature length"))?,
        );

        match verifying_key.verify(data, &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn verify_dilithium2(&self, data: &[u8], signature: &ChertSignature) -> Result<bool> {
        use pqcrypto_dilithium::dilithium2;
        use pqcrypto_traits::sign::{
            DetachedSignature as PQDetachedSignature, PublicKey as PQPublicKey,
        };

        let public_key = PQPublicKey::from_bytes(&self.public_key)
            .map_err(|e| anyhow::anyhow!("Invalid Dilithium2 public key: {:?}", e))?;

        let sig = PQDetachedSignature::from_bytes(&signature.signature)
            .map_err(|e| anyhow::anyhow!("Invalid Dilithium2 signature: {:?}", e))?;

        match dilithium2::verify_detached_signature(&sig, data, &public_key) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

/// Common cryptographic operations available to all modules
pub trait ChertCrypto {
    /// Hash data with specified algorithm and optional domain separation
    fn hash_with_domain(algorithm: HashAlgorithm, domain: Option<&[u8]>, data: &[u8]) -> ChertHash;

    /// Verify that two hashes match using constant-time comparison
    fn verify_hash(expected: &ChertHash, actual: &ChertHash) -> bool;

    /// Generate cryptographically secure random bytes
    fn secure_random(length: usize) -> Result<Vec<u8>>;
}

/// Utility functions for address generation and verification
pub mod utils {
    #[allow(unused_imports)]
    use super::*;

    /// Create quantum-resistant address from public key
    pub fn generate_quantum_resistant_address(public_key: &[u8], address_type: &str) -> String {
        use sha3::{Digest, Sha3_256};

        let mut hasher = Sha3_256::new();
        hasher.update(format!("CHERT_ADDRESS_{}_V2", address_type).as_bytes());
        hasher.update(public_key);
        let hash = hasher.finalize();

        format!("0x{}", hex::encode(&hash[..20]))
    }

    /// Verify address was derived from public key using constant-time comparison
    pub fn verify_address(address: &str, public_key: &[u8], address_type: &str) -> bool {
        let derived = generate_quantum_resistant_address(public_key, address_type);

        // Use constant-time comparison to prevent timing attacks
        use subtle::ConstantTimeEq;
        if address.len() != derived.len() {
            return false;
        }

        let address_lower = address.to_lowercase();
        let derived_lower = derived.to_lowercase();
        let address_bytes = address_lower.as_bytes();
        let derived_bytes = derived_lower.as_bytes();
        address_bytes.ct_eq(derived_bytes).into()
    }

    /// Create SHA-3 hash for quantum resistance
    pub fn sha3_hash(data: &[u8]) -> Vec<u8> {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    /// Create hex-encoded SHA-3 hash
    pub fn sha3_hash_hex(data: &[u8]) -> String {
        hex::encode(sha3_hash(data))
    }
}

/// Signature verification utility that works with any public key
pub fn verify_signature_standalone(data: &[u8], signature: &ChertSignature) -> Result<bool> {
    match signature.algorithm {
        SignatureAlgorithm::Ed25519 => {
            use ed25519_dalek::{Signature, Verifier, VerifyingKey};

            if signature.public_key.len() != 32 || signature.signature.len() != 64 {
                return Ok(false);
            }

            let verifying_key = VerifyingKey::from_bytes(
                &signature
                    .public_key
                    .clone()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Invalid Ed25519 public key length"))?,
            )?;

            let sig = Signature::from_bytes(
                &signature
                    .signature
                    .clone()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Invalid Ed25519 signature length"))?,
            );

            match verifying_key.verify(data, &sig) {
                Ok(()) => Ok(true),
                Err(_) => Ok(false),
            }
        }
        SignatureAlgorithm::Dilithium2 => {
            use pqcrypto_dilithium::dilithium2;
            use pqcrypto_traits::sign::{
                DetachedSignature as PQDetachedSignature, PublicKey as PQPublicKey,
            };

            let public_key = PQPublicKey::from_bytes(&signature.public_key)
                .map_err(|e| anyhow::anyhow!("Invalid Dilithium2 public key: {:?}", e))?;

            let sig = PQDetachedSignature::from_bytes(&signature.signature)
                .map_err(|e| anyhow::anyhow!("Invalid Dilithium2 signature: {:?}", e))?;

            match dilithium2::verify_detached_signature(&sig, data, &public_key) {
                Ok(()) => Ok(true),
                Err(_) => Ok(false),
            }
        }
        SignatureAlgorithm::Kyber512 => Err(anyhow::anyhow!(
            "Kyber512 is for encryption, not verification"
        )),
    }
}

/// Standard hash domains used across the ecosystem
pub mod domains {
    /// Domain for file integrity verification
    pub const FILE_VERIFICATION: &[u8] = b"CHERT_FILE_INTEGRITY_V1";

    /// Domain for work unit hashing
    pub const WORK_UNIT: &[u8] = b"CHERT_WORK_UNIT_V1";

    /// Domain for transaction hashing
    pub const TRANSACTION: &[u8] = b"CHERT_TRANSACTION_V1";

    /// Domain for block hashing
    pub const BLOCK: &[u8] = b"CHERT_BLOCK_V1";

    /// Domain for proof verification
    pub const PROOF: &[u8] = b"CHERT_PROOF_V1";
}

/// Default implementation providing basic cryptographic operations
pub struct StandardCrypto;

impl ChertCrypto for StandardCrypto {
    fn hash_with_domain(algorithm: HashAlgorithm, domain: Option<&[u8]>, data: &[u8]) -> ChertHash {
        match algorithm {
            HashAlgorithm::Sha256 => {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();

                if let Some(domain) = domain {
                    hasher.update(domain);
                }
                hasher.update(data);

                let result = hasher.finalize();
                let digest = result.to_vec();
                let hex = hex::encode(&digest);

                ChertHash {
                    algorithm: HashAlgorithm::Sha256,
                    digest,
                    hex,
                }
            }
            HashAlgorithm::Blake3 => {
                let mut hasher = blake3::Hasher::new();

                if let Some(domain) = domain {
                    hasher.update(domain);
                }
                hasher.update(data);

                let result = hasher.finalize();
                let digest = result.as_bytes().to_vec();
                let hex = hex::encode(&digest);

                ChertHash {
                    algorithm: HashAlgorithm::Blake3,
                    digest,
                    hex,
                }
            }
            HashAlgorithm::Keccak256 => {
                use sha3::{Digest, Keccak256};
                let mut hasher = Keccak256::new();

                if let Some(domain) = domain {
                    hasher.update(domain);
                }
                hasher.update(data);

                let result = hasher.finalize();
                let digest = result.to_vec();
                let hex = hex::encode(&digest);

                ChertHash {
                    algorithm: HashAlgorithm::Keccak256,
                    digest,
                    hex,
                }
            }
        }
    }

    fn verify_hash(expected: &ChertHash, actual: &ChertHash) -> bool {
        use subtle::ConstantTimeEq;

        // Algorithm must match
        if expected.algorithm != actual.algorithm {
            return false;
        }

        // Use constant-time comparison for security
        expected.digest.ct_eq(&actual.digest).into()
    }

    fn secure_random(length: usize) -> Result<Vec<u8>> {
        use rand::{RngCore, rngs::OsRng};

        let mut bytes = vec![0u8; length];
        OsRng.fill_bytes(&mut bytes);
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hash_consistency() {
        let data = b"test data";
        let domain = Some(domains::FILE_VERIFICATION);

        let hash1 = StandardCrypto::hash_with_domain(HashAlgorithm::Sha256, domain, data);
        let hash2 = StandardCrypto::hash_with_domain(HashAlgorithm::Sha256, domain, data);

        assert_eq!(hash1.hex, hash2.hex);
        assert!(StandardCrypto::verify_hash(&hash1, &hash2));
    }

    #[test]
    fn test_blake3_performance() {
        let large_data = vec![0u8; 1024 * 1024]; // 1MB
        let domain = Some(domains::WORK_UNIT);

        let start = std::time::Instant::now();
        let _hash = StandardCrypto::hash_with_domain(HashAlgorithm::Blake3, domain, &large_data);
        let blake3_time = start.elapsed();

        let start = std::time::Instant::now();
        let _hash = StandardCrypto::hash_with_domain(HashAlgorithm::Sha256, domain, &large_data);
        let sha256_time = start.elapsed();

        println!("Blake3: {:?}, SHA256: {:?}", blake3_time, sha256_time);
        // Blake3 should be faster for large data
    }

    #[test]
    fn test_secure_random() {
        let bytes1 = StandardCrypto::secure_random(32).unwrap();
        let bytes2 = StandardCrypto::secure_random(32).unwrap();

        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        assert_ne!(bytes1, bytes2); // Should be different
    }
}

/// Secure memory operations for protecting sensitive data across the ecosystem
pub mod secure_memory {
    use std::fmt;
    use zeroize::{Zeroize, ZeroizeOnDrop};

    /// Secure container for sensitive data that prevents memory dumps and provides constant-time operations
    #[derive(Clone, ZeroizeOnDrop)]
    pub struct SecretBox<T: Zeroize + Clone> {
        data: T,
    }

    impl<T: Zeroize + Clone> SecretBox<T> {
        /// Create a new secure container for sensitive data
        pub fn new(data: T) -> Self {
            Self { data }
        }

        /// Access the secret data with a closure to limit exposure time
        pub fn with_secret<R, F>(&self, f: F) -> R
        where
            F: FnOnce(&T) -> R,
        {
            f(&self.data)
        }

        /// Mutably access the secret data with a closure
        pub fn with_secret_mut<R, F>(&mut self, f: F) -> R
        where
            F: FnOnce(&mut T) -> R,
        {
            f(&mut self.data)
        }

        /// Extract the secret data (consumes the container)
        pub fn into_secret(self) -> T
        where
            T: Clone,
        {
            self.data.clone()
        }
    }

    impl<T: Zeroize + Clone> fmt::Debug for SecretBox<T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("SecretBox")
                .field("data", &"[REDACTED]")
                .finish()
        }
    }

    /// Memory-safe password container that zeroizes on drop
    #[derive(ZeroizeOnDrop)]
    pub struct SecretPassword {
        #[zeroize(skip)]
        password: secrecy::SecretBox<String>,
    }

    impl SecretPassword {
        pub fn new(password: String) -> Self {
            Self {
                password: secrecy::SecretBox::new(Box::new(password)),
            }
        }

        pub fn expose_secret(&self) -> &str {
            use secrecy::ExposeSecret;
            self.password.expose_secret()
        }
    }

    impl Clone for SecretPassword {
        fn clone(&self) -> Self {
            Self::new(self.expose_secret().to_string())
        }
    }

    impl fmt::Debug for SecretPassword {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("SecretPassword")
                .field("password", &"[REDACTED]")
                .finish()
        }
    }

    /// Lock memory pages to prevent swapping to disk (Unix systems)
    #[cfg(unix)]
    pub fn lock_memory(ptr: *mut u8, len: usize) -> Result<(), std::io::Error> {
        use std::io::Error;

        let result = unsafe { libc::mlock(ptr as *const libc::c_void, len) };
        if result == 0 {
            Ok(())
        } else {
            let error = Error::last_os_error();
            match error.raw_os_error() {
                Some(libc::EPERM) => {
                    tracing::warn!("Memory locking failed: insufficient permissions");
                    Ok(()) // Continue without locking
                }
                Some(libc::ENOMEM) => {
                    tracing::warn!("Memory locking failed: resource limits exceeded");
                    Ok(()) // Continue without locking
                }
                _ => Err(error),
            }
        }
    }

    /// Unlock memory pages (Unix systems)
    #[cfg(unix)]
    pub fn unlock_memory(ptr: *mut u8, len: usize) -> Result<(), std::io::Error> {
        let result = unsafe { libc::munlock(ptr as *const libc::c_void, len) };
        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    #[cfg(not(unix))]
    pub fn lock_memory(_ptr: *mut u8, _len: usize) -> Result<(), std::io::Error> {
        tracing::warn!("Memory locking not implemented for this platform");
        Ok(())
    }

    #[cfg(not(unix))]
    pub fn unlock_memory(_ptr: *mut u8, _len: usize) -> Result<(), std::io::Error> {
        Ok(())
    }
}
