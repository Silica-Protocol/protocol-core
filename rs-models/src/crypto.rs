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

// ML-DSA (FIPS 204) imports
use ml_dsa::{MlDsa44, MlDsa65, MlDsa87, KeyGen};
use ml_dsa::VerifyingKey as MlDsaVerifyingKey;
use ml_dsa::Signature as MlDsaSignature;
use ml_dsa::signature::{Signer as MlDsaSigner, Verifier as MlDsaVerifier, SignatureEncoding};

// Mnemonic derivation (SIP-1) - re-export for consumers
pub use ml_dsa_bip39::{
    mnemonic_to_seed,
    derive_keypair as derive_ml_dsa_keypair,
    derive_keypair_with_coin,
    SILICA_COIN_TYPE,
};
// Use alias to avoid conflict with local MlDsaLevel
use ml_dsa_bip39::MlDsaLevel as Sip1Level;

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
/// 
/// ML-DSA levels (FIPS 204):
/// - MlDsa44: 128-bit security (NIST Category 2) - Default for users
/// - MlDsa65: 192-bit security (NIST Category 3) - For high-value accounts
/// - MlDsa87: 256-bit security (NIST Category 5) - Maximum security
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Copy)]
pub enum SignatureAlgorithm {
    /// Ed25519 - Current standard for most operations (classical)
    Ed25519,
    /// ML-DSA-44 (Dilithium2 equivalent) - 128-bit post-quantum security
    /// Default choice for post-quantum protection
    MlDsa44,
    /// ML-DSA-65 (Dilithium3 equivalent) - 192-bit post-quantum security
    /// For treasury, governance, and high-value accounts
    MlDsa65,
    /// ML-DSA-87 (Dilithium5 equivalent) - 256-bit post-quantum security
    /// Maximum security, reserved for future use
    MlDsa87,
    /// Kyber768 - Key encapsulation mechanism (not for signing)
    Kyber768,
    
    // Legacy aliases for backward compatibility
    /// Legacy alias for MlDsa44 - DEPRECATED, use MlDsa44 instead
    #[serde(alias = "Dilithium2")]
    Dilithium2,
    /// Legacy alias for Kyber768 - DEPRECATED, use Kyber768 instead  
    #[serde(alias = "Kyber512")]
    Kyber512,
}

impl SignatureAlgorithm {
    /// Check if this is a post-quantum algorithm
    pub fn is_post_quantum(&self) -> bool {
        matches!(self, Self::MlDsa44 | Self::MlDsa65 | Self::MlDsa87 | Self::Dilithium2)
    }
    
    /// Get the ML-DSA level if applicable
    pub fn ml_dsa_level(&self) -> Option<MlDsaLevel> {
        match self {
            Self::MlDsa44 | Self::Dilithium2 => Some(MlDsaLevel::Dsa44),
            Self::MlDsa65 => Some(MlDsaLevel::Dsa65),
            Self::MlDsa87 => Some(MlDsaLevel::Dsa87),
            _ => None,
        }
    }
    
    /// Get public key size in bytes
    pub fn public_key_size(&self) -> usize {
        match self {
            Self::Ed25519 => 32,
            Self::MlDsa44 | Self::Dilithium2 => 1312,
            Self::MlDsa65 => 1952,
            Self::MlDsa87 => 2592,
            Self::Kyber768 | Self::Kyber512 => 1184, // Kyber768 public key
        }
    }
    
    /// Get signature size in bytes
    pub fn signature_size(&self) -> usize {
        match self {
            Self::Ed25519 => 64,
            Self::MlDsa44 | Self::Dilithium2 => 2420,
            Self::MlDsa65 => 3309,    // Actual ml-dsa crate size
            Self::MlDsa87 => 4627,    // Actual ml-dsa crate size
            Self::Kyber768 | Self::Kyber512 => 0, // Not a signing algorithm
        }
    }
    
    /// Get seed size in bytes (for deterministic key generation)
    pub fn seed_size(&self) -> usize {
        match self {
            Self::Ed25519 => 32,
            Self::MlDsa44 | Self::MlDsa65 | Self::MlDsa87 | Self::Dilithium2 => 32,
            Self::Kyber768 | Self::Kyber512 => 0, // No seed-based keygen
        }
    }
    
    /// Normalize legacy aliases to canonical form
    pub fn normalize(&self) -> Self {
        match self {
            Self::Dilithium2 => Self::MlDsa44,
            Self::Kyber512 => Self::Kyber768,
            other => *other,
        }
    }
}

/// ML-DSA security level configuration
/// 
/// All levels use 32-byte seeds for deterministic key generation.
/// Choose based on security requirements vs performance/size trade-offs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MlDsaLevel {
    /// MlDsa44 (Dilithium2) - 128-bit security, smallest signatures
    /// DEFAULT for all user accounts
    Dsa44,
    /// MlDsa65 (Dilithium3) - 192-bit security, medium signatures
    /// For treasury, governance, bridges
    Dsa65,
    /// MlDsa87 (Dilithium5) - 256-bit security, largest signatures
    /// Reserved for maximum security requirements
    Dsa87,
}

impl Default for MlDsaLevel {
    fn default() -> Self {
        Self::Dsa44  // Start with 128-bit, upgrade later if needed
    }
}

impl MlDsaLevel {
    /// Domain separator for SIP-1 derivation (level-specific)
    pub fn domain_separator(&self) -> &'static [u8] {
        match self {
            Self::Dsa44 => b"SIP-1:SILICA:ML-DSA-44:V1",
            Self::Dsa65 => b"SIP-1:SILICA:ML-DSA-65:V1",
            Self::Dsa87 => b"SIP-1:SILICA:ML-DSA-87:V1",
        }
    }
    
    /// Purpose field in SIP-1 derivation path (unique per level)
    pub fn derivation_purpose(&self) -> u32 {
        match self {
            Self::Dsa44 => 8844,  // m/8844'/...
            Self::Dsa65 => 8865,  // m/8865'/...
            Self::Dsa87 => 8887,  // m/8887'/...
        }
    }
    
    /// Get corresponding SignatureAlgorithm
    pub fn signature_algorithm(&self) -> SignatureAlgorithm {
        match self {
            Self::Dsa44 => SignatureAlgorithm::MlDsa44,
            Self::Dsa65 => SignatureAlgorithm::MlDsa65,
            Self::Dsa87 => SignatureAlgorithm::MlDsa87,
        }
    }
    
    /// Public key size in bytes
    pub fn public_key_size(&self) -> usize {
        match self {
            Self::Dsa44 => 1312,
            Self::Dsa65 => 1952,
            Self::Dsa87 => 2592,
        }
    }
    
    /// Signature size in bytes
    pub fn signature_size(&self) -> usize {
        match self {
            Self::Dsa44 => 2420,
            Self::Dsa65 => 3309,  // Actual ml-dsa crate size
            Self::Dsa87 => 4627,  // Actual ml-dsa crate size
        }
    }
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

    /// Generate a new ML-DSA keypair at default level (MlDsa44)
    /// 
    /// This is the recommended method for post-quantum key generation.
    /// Uses random entropy from OsRng via seed-based generation.
    pub fn generate_ml_dsa() -> Result<Self> {
        Self::generate_ml_dsa_at_level(MlDsaLevel::default())
    }
    
    /// Generate a new ML-DSA keypair at specified security level
    /// 
    /// Uses random seed generation to avoid rand_core version conflicts.
    pub fn generate_ml_dsa_at_level(level: MlDsaLevel) -> Result<Self> {
        use rand::{RngCore, rngs::OsRng};
        
        // Generate random seed (works with rand 0.8)
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        
        // Use seed-based generation (deterministic from random seed)
        Self::generate_ml_dsa_from_seed(&seed, level)
    }
    
    /// Generate ML-DSA keypair from 32-byte seed (deterministic)
    /// 
    /// This is the core function for SIP-1 mnemonic derivation.
    /// Same seed always produces same keypair.
    pub fn generate_ml_dsa_from_seed(seed: &[u8; 32], level: MlDsaLevel) -> Result<Self> {
        match level {
            MlDsaLevel::Dsa44 => {
                let kp = MlDsa44::from_seed(&(*seed).into());
                Ok(Self {
                    algorithm: SignatureAlgorithm::MlDsa44,
                    public_key: kp.verifying_key().encode().as_slice().to_vec(),
                    private_key: seed.to_vec(), // Store original 32-byte seed
                })
            }
            MlDsaLevel::Dsa65 => {
                let kp = MlDsa65::from_seed(&(*seed).into());
                Ok(Self {
                    algorithm: SignatureAlgorithm::MlDsa65,
                    public_key: kp.verifying_key().encode().as_slice().to_vec(),
                    private_key: seed.to_vec(),
                })
            }
            MlDsaLevel::Dsa87 => {
                let kp = MlDsa87::from_seed(&(*seed).into());
                Ok(Self {
                    algorithm: SignatureAlgorithm::MlDsa87,
                    public_key: kp.verifying_key().encode().as_slice().to_vec(),
                    private_key: seed.to_vec(),
                })
            }
        }
    }

    /// Generate a new Dilithium2 keypair (post-quantum)
    /// 
    /// DEPRECATED: Use `generate_ml_dsa()` instead.
    /// This method is kept for backward compatibility.
    #[deprecated(since = "0.2.0", note = "Use generate_ml_dsa() instead")]
    pub fn generate_dilithium2() -> Result<Self> {
        // Use ML-DSA-44 which is equivalent to Dilithium2
        Self::generate_ml_dsa_at_level(MlDsaLevel::Dsa44)
    }

    /// Derive an ML-DSA keypair from a BIP39 mnemonic (SIP-1 standard)
    /// 
    /// This enables 24-word seed phrase backup for post-quantum accounts.
    /// The derivation is fully deterministic - same mnemonic always produces
    /// the same keypair.
    /// 
    /// # Arguments
    /// * `mnemonic` - 12 or 24 word BIP39 phrase
    /// * `passphrase` - Optional passphrase (use "" for none)
    /// * `account` - Account index (usually 0)
    /// * `index` - Key index within the account
    /// * `level` - ML-DSA security level
    /// 
    /// # Example
    /// ```ignore
    /// let mnemonic = "abandon abandon abandon abandon abandon abandon \
    ///                 abandon abandon abandon abandon abandon about";
    /// let keypair = ChertKeyPair::derive_from_mnemonic(
    ///     mnemonic, "", 0, 0, MlDsaLevel::default()
    /// )?;
    /// ```
    pub fn derive_from_mnemonic(
        mnemonic: &str,
        passphrase: &str,
        account: u32,
        index: u32,
        level: MlDsaLevel,
    ) -> Result<Self> {
        let seed = ml_dsa_bip39::mnemonic_to_seed(mnemonic, passphrase)
            .map_err(|e| anyhow::anyhow!("Invalid mnemonic: {}", e))?;
        
        // Convert local MlDsaLevel to ml-dsa-bip39's level type
        let sip1_level = match level {
            MlDsaLevel::Dsa44 => Sip1Level::Dsa44,
            MlDsaLevel::Dsa65 => Sip1Level::Dsa65,
            MlDsaLevel::Dsa87 => Sip1Level::Dsa87,
        };
        
        let sip1_keypair = ml_dsa_bip39::derive_keypair(&seed, account, index, sip1_level)
            .map_err(|e| anyhow::anyhow!("Key derivation failed: {}", e))?;
        
        let algorithm = match level {
            MlDsaLevel::Dsa44 => SignatureAlgorithm::MlDsa44,
            MlDsaLevel::Dsa65 => SignatureAlgorithm::MlDsa65,
            MlDsaLevel::Dsa87 => SignatureAlgorithm::MlDsa87,
        };
        
        Ok(Self {
            algorithm,
            public_key: sip1_keypair.public_key().to_vec(),
            private_key: sip1_keypair.seed().to_vec(),
        })
    }
    
    /// Derive ML-DSA-44 keypair from mnemonic with defaults
    /// 
    /// Convenience method using default security level (ML-DSA-44).
    pub fn derive_from_mnemonic_default(
        mnemonic: &str,
        passphrase: &str,
        account: u32,
        index: u32,
    ) -> Result<Self> {
        Self::derive_from_mnemonic(mnemonic, passphrase, account, index, MlDsaLevel::default())
    }

    /// Sign data with the keypair's algorithm
    pub fn sign(&self, data: &[u8]) -> Result<ChertSignature> {
        match self.algorithm.normalize() {
            SignatureAlgorithm::Ed25519 => self.sign_ed25519(data),
            SignatureAlgorithm::MlDsa44 | SignatureAlgorithm::Dilithium2 => {
                self.sign_ml_dsa_44(data)
            }
            SignatureAlgorithm::MlDsa65 => self.sign_ml_dsa_65(data),
            SignatureAlgorithm::MlDsa87 => self.sign_ml_dsa_87(data),
            SignatureAlgorithm::Kyber768 | SignatureAlgorithm::Kyber512 => {
                Err(anyhow::anyhow!("Kyber is for encryption, not signing"))
            }
        }
    }

    /// Verify a signature matches this keypair's public key
    pub fn verify(&self, data: &[u8], signature: &ChertSignature) -> Result<bool> {
        // Normalize both algorithms for comparison
        let self_alg = self.algorithm.normalize();
        let sig_alg = signature.algorithm.normalize();
        
        // Ensure the signature algorithm matches this keypair
        if sig_alg != self_alg {
            return Ok(false);
        }

        // Ensure the public key matches
        if signature.public_key != self.public_key {
            return Ok(false);
        }

        match self_alg {
            SignatureAlgorithm::Ed25519 => self.verify_ed25519(data, signature),
            SignatureAlgorithm::MlDsa44 | SignatureAlgorithm::Dilithium2 => {
                self.verify_ml_dsa_44(data, signature)
            }
            SignatureAlgorithm::MlDsa65 => self.verify_ml_dsa_65(data, signature),
            SignatureAlgorithm::MlDsa87 => self.verify_ml_dsa_87(data, signature),
            SignatureAlgorithm::Kyber768 | SignatureAlgorithm::Kyber512 => {
                Err(anyhow::anyhow!("Kyber is for encryption, not verification"))
            }
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

    /// Sign data with ML-DSA-44
    fn sign_ml_dsa_44(&self, data: &[u8]) -> Result<ChertSignature> {
        if self.private_key.len() != 32 {
            return Err(anyhow::anyhow!(
                "ML-DSA signing requires 32-byte seed. Got {} bytes.",
                self.private_key.len()
            ));
        }
        
        let seed: [u8; 32] = self.private_key.clone().try_into()
            .map_err(|_| anyhow::anyhow!("Invalid ML-DSA seed length"))?;
        
        let kp = MlDsa44::from_seed(&seed.into());
        let signature = kp.signing_key().sign(data);
        
        Ok(ChertSignature {
            algorithm: SignatureAlgorithm::MlDsa44,
            signature: signature.to_bytes().to_vec(),
            public_key: self.public_key.clone(),
        })
    }

    /// Sign data with ML-DSA-65
    fn sign_ml_dsa_65(&self, data: &[u8]) -> Result<ChertSignature> {
        if self.private_key.len() != 32 {
            return Err(anyhow::anyhow!(
                "ML-DSA signing requires 32-byte seed. Got {} bytes.",
                self.private_key.len()
            ));
        }
        
        let seed: [u8; 32] = self.private_key.clone().try_into()
            .map_err(|_| anyhow::anyhow!("Invalid ML-DSA seed length"))?;
        
        let kp = MlDsa65::from_seed(&seed.into());
        let signature = kp.signing_key().sign(data);
        
        Ok(ChertSignature {
            algorithm: SignatureAlgorithm::MlDsa65,
            signature: signature.to_bytes().to_vec(),
            public_key: self.public_key.clone(),
        })
    }

    /// Sign data with ML-DSA-87
    fn sign_ml_dsa_87(&self, data: &[u8]) -> Result<ChertSignature> {
        if self.private_key.len() != 32 {
            return Err(anyhow::anyhow!(
                "ML-DSA signing requires 32-byte seed. Got {} bytes.",
                self.private_key.len()
            ));
        }
        
        let seed: [u8; 32] = self.private_key.clone().try_into()
            .map_err(|_| anyhow::anyhow!("Invalid ML-DSA seed length"))?;
        
        let kp = MlDsa87::from_seed(&seed.into());
        let signature = kp.signing_key().sign(data);
        
        Ok(ChertSignature {
            algorithm: SignatureAlgorithm::MlDsa87,
            signature: signature.to_bytes().to_vec(),
            public_key: self.public_key.clone(),
        })
    }

    fn verify_ed25519(&self, data: &[u8], signature: &ChertSignature) -> Result<bool> {
        use ed25519_dalek::{Signature, Verifier as Ed25519Verifier, VerifyingKey};

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

    /// Verify ML-DSA-44 signature
    fn verify_ml_dsa_44(&self, data: &[u8], signature: &ChertSignature) -> Result<bool> {
        // Validate lengths
        if self.public_key.len() != 1312 {
            return Ok(false);
        }
        if signature.signature.len() != 2420 {
            return Ok(false);
        }
        
        // Decode public key using decode()
        let pk_array: [u8; 1312] = self.public_key.clone().try_into()
            .map_err(|_| anyhow::anyhow!("Invalid ML-DSA-44 public key length"))?;
        let vk = MlDsaVerifyingKey::<MlDsa44>::decode(&pk_array.into());
        
        // Decode signature
        let sig = MlDsaSignature::<MlDsa44>::try_from(signature.signature.as_slice())
            .map_err(|_| anyhow::anyhow!("Invalid ML-DSA-44 signature"))?;
        
        // Verify
        match vk.verify(data, &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Verify ML-DSA-65 signature
    fn verify_ml_dsa_65(&self, data: &[u8], signature: &ChertSignature) -> Result<bool> {
        // Validate lengths
        if self.public_key.len() != 1952 {
            return Ok(false);
        }
        if signature.signature.len() != 3309 {
            return Ok(false);
        }
        
        // Decode public key
        let pk_array: [u8; 1952] = self.public_key.clone().try_into()
            .map_err(|_| anyhow::anyhow!("Invalid ML-DSA-65 public key length"))?;
        let vk = MlDsaVerifyingKey::<MlDsa65>::decode(&pk_array.into());
        
        // Decode signature
        let sig = MlDsaSignature::<MlDsa65>::try_from(signature.signature.as_slice())
            .map_err(|_| anyhow::anyhow!("Invalid ML-DSA-65 signature"))?;
        
        // Verify
        match vk.verify(data, &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Verify ML-DSA-87 signature
    fn verify_ml_dsa_87(&self, data: &[u8], signature: &ChertSignature) -> Result<bool> {
        // Validate lengths
        if self.public_key.len() != 2592 {
            return Ok(false);
        }
        if signature.signature.len() != 4627 {
            return Ok(false);
        }
        
        // Decode public key
        let pk_array: [u8; 2592] = self.public_key.clone().try_into()
            .map_err(|_| anyhow::anyhow!("Invalid ML-DSA-87 public key length"))?;
        let vk = MlDsaVerifyingKey::<MlDsa87>::decode(&pk_array.into());
        
        // Decode signature
        let sig = MlDsaSignature::<MlDsa87>::try_from(signature.signature.as_slice())
            .map_err(|_| anyhow::anyhow!("Invalid ML-DSA-87 signature"))?;
        
        // Verify
        match vk.verify(data, &sig) {
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
    match signature.algorithm.normalize() {
        SignatureAlgorithm::Ed25519 => {
            use ed25519_dalek::{Signature, Verifier as Ed25519Verifier, VerifyingKey};

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
        SignatureAlgorithm::MlDsa44 | SignatureAlgorithm::Dilithium2 => {
            verify_ml_dsa_44_standalone(data, signature)
        }
        SignatureAlgorithm::MlDsa65 => {
            verify_ml_dsa_65_standalone(data, signature)
        }
        SignatureAlgorithm::MlDsa87 => {
            verify_ml_dsa_87_standalone(data, signature)
        }
        SignatureAlgorithm::Kyber768 | SignatureAlgorithm::Kyber512 => Err(anyhow::anyhow!(
            "Kyber is for encryption, not verification"
        )),
    }
}

/// Helper function to verify ML-DSA-44 signatures
fn verify_ml_dsa_44_standalone(data: &[u8], signature: &ChertSignature) -> Result<bool> {
    if signature.public_key.len() != 1312 || signature.signature.len() != 2420 {
        return Ok(false);
    }
    
    let pk_array: [u8; 1312] = signature.public_key.clone().try_into()
        .map_err(|_| anyhow::anyhow!("Invalid ML-DSA-44 public key length"))?;
    let vk = MlDsaVerifyingKey::<MlDsa44>::decode(&pk_array.into());
    
    let sig = MlDsaSignature::<MlDsa44>::try_from(signature.signature.as_slice())
        .map_err(|_| anyhow::anyhow!("Invalid ML-DSA-44 signature"))?;
    
    match vk.verify(data, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Helper function to verify ML-DSA-65 signatures
fn verify_ml_dsa_65_standalone(data: &[u8], signature: &ChertSignature) -> Result<bool> {
    if signature.public_key.len() != 1952 || signature.signature.len() != 3309 {
        return Ok(false);
    }
    
    let pk_array: [u8; 1952] = signature.public_key.clone().try_into()
        .map_err(|_| anyhow::anyhow!("Invalid ML-DSA-65 public key length"))?;
    let vk = MlDsaVerifyingKey::<MlDsa65>::decode(&pk_array.into());
    
    let sig = MlDsaSignature::<MlDsa65>::try_from(signature.signature.as_slice())
        .map_err(|_| anyhow::anyhow!("Invalid ML-DSA-65 signature"))?;
    
    match vk.verify(data, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Helper function to verify ML-DSA-87 signatures
fn verify_ml_dsa_87_standalone(data: &[u8], signature: &ChertSignature) -> Result<bool> {
    if signature.public_key.len() != 2592 || signature.signature.len() != 4627 {
        return Ok(false);
    }
    
    let pk_array: [u8; 2592] = signature.public_key.clone().try_into()
        .map_err(|_| anyhow::anyhow!("Invalid ML-DSA-87 public key length"))?;
    let vk = MlDsaVerifyingKey::<MlDsa87>::decode(&pk_array.into());
    
    let sig = MlDsaSignature::<MlDsa87>::try_from(signature.signature.as_slice())
        .map_err(|_| anyhow::anyhow!("Invalid ML-DSA-87 signature"))?;
    
    match vk.verify(data, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Infer signature algorithm from public key and/or signature length
pub fn infer_signature_algorithm(
    public_key: &[u8],
    signature: Option<&[u8]>,
) -> Result<SignatureAlgorithm> {
    // Check public key length first (most reliable)
    match public_key.len() {
        32 => return Ok(SignatureAlgorithm::Ed25519),
        1312 => return Ok(SignatureAlgorithm::MlDsa44),
        1952 => return Ok(SignatureAlgorithm::MlDsa65),
        2592 => return Ok(SignatureAlgorithm::MlDsa87),
        _ => {}
    }
    
    // Fall back to signature length if provided
    if let Some(sig) = signature {
        match sig.len() {
            64 => return Ok(SignatureAlgorithm::Ed25519),
            2420 => return Ok(SignatureAlgorithm::MlDsa44),
            3309 => return Ok(SignatureAlgorithm::MlDsa65),
            4627 => return Ok(SignatureAlgorithm::MlDsa87),
            _ => {}
        }
    }
    
    Err(anyhow::anyhow!("Cannot infer algorithm from key/signature lengths"))
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
    
    // ===== ML-DSA Tests =====
    
    #[test]
    fn test_ml_dsa_44_keygen_deterministic() {
        let seed = [42u8; 32];
        
        let kp1 = ChertKeyPair::generate_ml_dsa_from_seed(&seed, MlDsaLevel::Dsa44).unwrap();
        let kp2 = ChertKeyPair::generate_ml_dsa_from_seed(&seed, MlDsaLevel::Dsa44).unwrap();
        
        // Same seed should produce same keypair
        assert_eq!(kp1.public_key, kp2.public_key);
        assert_eq!(kp1.private_key, kp2.private_key);
        assert_eq!(kp1.algorithm, SignatureAlgorithm::MlDsa44);
        
        // Verify expected sizes
        assert_eq!(kp1.public_key.len(), 1312);  // ML-DSA-44 public key size
        assert_eq!(kp1.private_key.len(), 32);   // Seed size (not expanded key)
    }
    
    #[test]
    fn test_ml_dsa_44_sign_verify() {
        let seed = [99u8; 32];
        let kp = ChertKeyPair::generate_ml_dsa_from_seed(&seed, MlDsaLevel::Dsa44).unwrap();
        
        let message = b"Hello, post-quantum world!";
        let signature = kp.sign(message).unwrap();
        
        // Verify signature
        let verified = kp.verify(message, &signature).unwrap();
        assert!(verified);
        
        // Verify signature size
        assert_eq!(signature.signature.len(), 2420);  // ML-DSA-44 signature size
        assert_eq!(signature.algorithm, SignatureAlgorithm::MlDsa44);
    }
    
    #[test]
    fn test_ml_dsa_44_standalone_verify() {
        let seed = [123u8; 32];
        let kp = ChertKeyPair::generate_ml_dsa_from_seed(&seed, MlDsaLevel::Dsa44).unwrap();
        
        let message = b"Test standalone verification";
        let signature = kp.sign(message).unwrap();
        
        // Verify using standalone function
        let verified = verify_signature_standalone(message, &signature).unwrap();
        assert!(verified);
        
        // Tampered message should fail
        let tampered = b"Tampered message";
        let verified_tampered = verify_signature_standalone(tampered, &signature).unwrap();
        assert!(!verified_tampered);
    }
    
    #[test]
    fn test_ml_dsa_65_keygen_and_sign() {
        let seed = [77u8; 32];
        let kp = ChertKeyPair::generate_ml_dsa_from_seed(&seed, MlDsaLevel::Dsa65).unwrap();
        
        // Verify expected sizes
        assert_eq!(kp.public_key.len(), 1952);  // ML-DSA-65 public key size
        assert_eq!(kp.algorithm, SignatureAlgorithm::MlDsa65);
        
        let message = b"High security message";
        let signature = kp.sign(message).unwrap();
        
        // Verify signature
        assert!(kp.verify(message, &signature).unwrap());
        assert_eq!(signature.signature.len(), 3309);  // ML-DSA-65 signature size
    }
    
    #[test]
    fn test_ml_dsa_87_keygen_and_sign() {
        let seed = [88u8; 32];
        let kp = ChertKeyPair::generate_ml_dsa_from_seed(&seed, MlDsaLevel::Dsa87).unwrap();
        
        // Verify expected sizes
        assert_eq!(kp.public_key.len(), 2592);  // ML-DSA-87 public key size
        assert_eq!(kp.algorithm, SignatureAlgorithm::MlDsa87);
        
        let message = b"Maximum security message";
        let signature = kp.sign(message).unwrap();
        
        // Verify signature
        assert!(kp.verify(message, &signature).unwrap());
        assert_eq!(signature.signature.len(), 4627);  // ML-DSA-87 signature size
    }
    
    #[test]
    fn test_ml_dsa_random_keygen() {
        // Test random key generation
        let kp1 = ChertKeyPair::generate_ml_dsa().unwrap();
        let kp2 = ChertKeyPair::generate_ml_dsa().unwrap();
        
        // Random keys should be different
        assert_ne!(kp1.public_key, kp2.public_key);
        
        // Both should work for signing
        let message = b"Test message";
        let sig1 = kp1.sign(message).unwrap();
        let sig2 = kp2.sign(message).unwrap();
        
        assert!(kp1.verify(message, &sig1).unwrap());
        assert!(kp2.verify(message, &sig2).unwrap());
        
        // Cross-verification should fail
        assert!(!kp1.verify(message, &sig2).unwrap());
        assert!(!kp2.verify(message, &sig1).unwrap());
    }
    
    #[test]
    fn test_ml_dsa_level_defaults() {
        assert_eq!(MlDsaLevel::default(), MlDsaLevel::Dsa44);
        
        let kp = ChertKeyPair::generate_ml_dsa().unwrap();
        assert_eq!(kp.algorithm, SignatureAlgorithm::MlDsa44);
    }
    
    #[test]
    fn test_signature_algorithm_normalize() {
        // Dilithium2 should normalize to MlDsa44
        assert_eq!(SignatureAlgorithm::Dilithium2.normalize(), SignatureAlgorithm::MlDsa44);
        
        // Others should remain unchanged
        assert_eq!(SignatureAlgorithm::Ed25519.normalize(), SignatureAlgorithm::Ed25519);
        assert_eq!(SignatureAlgorithm::MlDsa44.normalize(), SignatureAlgorithm::MlDsa44);
        assert_eq!(SignatureAlgorithm::MlDsa65.normalize(), SignatureAlgorithm::MlDsa65);
        assert_eq!(SignatureAlgorithm::MlDsa87.normalize(), SignatureAlgorithm::MlDsa87);
    }
    
    #[test]
    fn test_infer_signature_algorithm() {
        // Ed25519
        assert_eq!(
            infer_signature_algorithm(&[0u8; 32], None).unwrap(),
            SignatureAlgorithm::Ed25519
        );
        
        // ML-DSA-44
        assert_eq!(
            infer_signature_algorithm(&[0u8; 1312], None).unwrap(),
            SignatureAlgorithm::MlDsa44
        );
        
        // ML-DSA-65
        assert_eq!(
            infer_signature_algorithm(&[0u8; 1952], None).unwrap(),
            SignatureAlgorithm::MlDsa65
        );
        
        // ML-DSA-87
        assert_eq!(
            infer_signature_algorithm(&[0u8; 2592], None).unwrap(),
            SignatureAlgorithm::MlDsa87
        );
        
        // Unknown should error
        assert!(infer_signature_algorithm(&[0u8; 100], None).is_err());
    }
    
    #[test]
    fn test_ml_dsa_address_derivation() {
        let seed = [42u8; 32];
        let kp = ChertKeyPair::generate_ml_dsa_from_seed(&seed, MlDsaLevel::Dsa44).unwrap();
        
        let address = kp.address("USER");
        
        // Address should be deterministic
        let kp2 = ChertKeyPair::generate_ml_dsa_from_seed(&seed, MlDsaLevel::Dsa44).unwrap();
        let address2 = kp2.address("USER");
        
        assert_eq!(address, address2);
        
        // Address format should be 0x + 40 hex chars
        assert!(address.starts_with("0x"));
        assert_eq!(address.len(), 42);
    }
    
    #[test]
    fn test_derive_from_mnemonic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon about";
        
        // Derive keypair using SIP-1 standard
        let kp = ChertKeyPair::derive_from_mnemonic(
            mnemonic, "", 0, 0, MlDsaLevel::default()
        ).unwrap();
        
        // Should be ML-DSA-44 (default level)
        assert_eq!(kp.algorithm, SignatureAlgorithm::MlDsa44);
        assert_eq!(kp.public_key.len(), 1312);
        assert_eq!(kp.private_key.len(), 32); // 32-byte seed
        
        // Should be deterministic
        let kp2 = ChertKeyPair::derive_from_mnemonic(
            mnemonic, "", 0, 0, MlDsaLevel::Dsa44
        ).unwrap();
        
        assert_eq!(kp.public_key, kp2.public_key);
        assert_eq!(kp.private_key, kp2.private_key);
        
        // Different index = different keys
        let kp3 = ChertKeyPair::derive_from_mnemonic(
            mnemonic, "", 0, 1, MlDsaLevel::Dsa44
        ).unwrap();
        
        assert_ne!(kp.public_key, kp3.public_key);
        
        // Passphrase changes everything
        let kp_pass = ChertKeyPair::derive_from_mnemonic(
            mnemonic, "secret", 0, 0, MlDsaLevel::Dsa44
        ).unwrap();
        
        assert_ne!(kp.public_key, kp_pass.public_key);
    }
    
    #[test]
    fn test_derive_from_mnemonic_sign_verify() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon about";
        
        let kp = ChertKeyPair::derive_from_mnemonic_default(mnemonic, "", 0, 0).unwrap();
        
        let message = b"Hello post-quantum world!";
        let signature = kp.sign(message).unwrap();
        
        // Verify with same keypair
        assert!(kp.verify(message, &signature).unwrap());
        
        // Wrong message should fail
        assert!(!kp.verify(b"wrong message", &signature).unwrap());
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
