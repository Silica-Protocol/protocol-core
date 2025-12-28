use anyhow::{Result, anyhow};
use blake3::Hasher;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Maximum supported length in bytes for plaintext stealth memos.
pub const STEALTH_OUTPUT_MEMO_MAX_BYTES: usize = 1024;
/// Domain separator for stealth output commitments.
pub const STEALTH_OUTPUT_COMMITMENT_DOMAIN: &[u8] = b"CHERT_STEALTH_OUTPUT_V1";

/// Compressed representation of a stealth address consisting of two Ristretto points.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StealthAddressView {
    pub public_key: [u8; 32],
    pub tx_public_key: [u8; 32],
}

impl StealthAddressView {
    /// Borrow both compressed point encodings in a single contiguous buffer.
    pub fn as_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&self.public_key);
        bytes[32..].copy_from_slice(&self.tx_public_key);
        bytes
    }

    /// Construct from concatenated compressed Ristretto points.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 64 {
            return Err(anyhow!(
                "stealth address view requires 64 bytes, received {}",
                bytes.len()
            ));
        }

        let mut public_key = [0u8; 32];
        let mut tx_public_key = [0u8; 32];
        public_key.copy_from_slice(&bytes[..32]);
        tx_public_key.copy_from_slice(&bytes[32..]);

        Ok(Self {
            public_key,
            tx_public_key,
        })
    }
}

/// Encrypted memo payload persisted alongside stealth outputs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StealthEncryptedMemo {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub message_number: u32,
}

impl StealthEncryptedMemo {
    pub fn len(&self) -> usize {
        self.ciphertext.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ciphertext.is_empty()
    }
}

/// Persisted stealth output metadata stored in the ledger.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StealthOutput {
    pub tx_id: String,
    pub index: u32,
    pub commitment: [u8; 32],
    pub address: StealthAddressView,
    pub amount: Option<u64>,
    pub memo_plaintext: Option<String>,
    pub memo_encrypted: Option<StealthEncryptedMemo>,
    pub created_at: DateTime<Utc>,
}

impl StealthOutput {
    /// Construct a stealth output that exposes amount and optional plaintext memo.
    pub fn new_plaintext(
        tx_id: String,
        index: u32,
        address: StealthAddressView,
        amount: u64,
        memo: Option<String>,
        created_at: DateTime<Utc>,
    ) -> Result<Self> {
        if amount == 0 {
            return Err(anyhow!("stealth outputs must carry a non-zero amount"));
        }

        if let Some(ref memo_value) = memo {
            if memo_value.len() > STEALTH_OUTPUT_MEMO_MAX_BYTES {
                return Err(anyhow!(
                    "plaintext memo exceeds {} byte bound",
                    STEALTH_OUTPUT_MEMO_MAX_BYTES
                ));
            }
        }

        let commitment =
            Self::derive_commitment(&tx_id, index, &address, Some(amount), memo.as_deref(), None);

        Ok(Self {
            tx_id,
            index,
            commitment,
            address,
            amount: Some(amount),
            memo_plaintext: memo,
            memo_encrypted: None,
            created_at,
        })
    }

    /// Construct a stealth output that hides the amount inside an encrypted payload.
    pub fn new_encrypted(
        tx_id: String,
        index: u32,
        address: StealthAddressView,
        encrypted_memo: StealthEncryptedMemo,
        created_at: DateTime<Utc>,
    ) -> Result<Self> {
        if encrypted_memo.ciphertext.is_empty() {
            return Err(anyhow!("encrypted memo payload must be present"));
        }

        let commitment =
            Self::derive_commitment(&tx_id, index, &address, None, None, Some(&encrypted_memo));

        Ok(Self {
            tx_id,
            index,
            commitment,
            address,
            amount: None,
            memo_plaintext: None,
            memo_encrypted: Some(encrypted_memo),
            created_at,
        })
    }

    /// Deterministically derive the output commitment without exposing private data.
    pub fn derive_commitment(
        tx_id: &str,
        index: u32,
        address: &StealthAddressView,
        amount: Option<u64>,
        memo_plaintext: Option<&str>,
        memo_encrypted: Option<&StealthEncryptedMemo>,
    ) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(STEALTH_OUTPUT_COMMITMENT_DOMAIN);
        hasher.update(&(tx_id.len() as u32).to_le_bytes());
        hasher.update(tx_id.as_bytes());
        hasher.update(&index.to_le_bytes());
        hasher.update(&address.public_key);
        hasher.update(&address.tx_public_key);

        match amount {
            Some(value) => {
                hasher.update(&[1]);
                hasher.update(&value.to_le_bytes());
            }
            None => {
                hasher.update(&[0]);
            }
        }

        match memo_plaintext {
            Some(text) => {
                hasher.update(&[1]);
                hasher.update(&(text.len() as u32).to_le_bytes());
                hasher.update(text.as_bytes());
            }
            None => {
                hasher.update(&[0]);
            }
        }

        if let Some(encrypted) = memo_encrypted {
            hasher.update(&[1]);
            hasher.update(&encrypted.message_number.to_le_bytes());
            hasher.update(&encrypted.nonce);
            hasher.update(&(encrypted.ciphertext.len() as u32).to_le_bytes());
            hasher.update(&encrypted.ciphertext);
        } else {
            hasher.update(&[0]);
        }

        let digest = hasher.finalize();
        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(digest.as_bytes());
        commitment
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plaintext_commitment_deterministic() {
        let address = StealthAddressView {
            public_key: [1u8; 32],
            tx_public_key: [2u8; 32],
        };
        let created_at = Utc::now();
        let memo = Some("hello world".to_string());

        let output_a = StealthOutput::new_plaintext(
            "tx123".to_string(),
            0,
            address.clone(),
            42,
            memo.clone(),
            created_at,
        )
        .unwrap();
        let output_b = StealthOutput::new_plaintext(
            "tx123".to_string(),
            0,
            address.clone(),
            42,
            memo,
            created_at,
        )
        .unwrap();

        assert_eq!(output_a.commitment, output_b.commitment);
        assert_eq!(output_a.amount, Some(42));
        assert_eq!(output_a.memo_plaintext.as_deref(), Some("hello world"));
    }

    #[test]
    fn test_encrypted_commitment_uses_ciphertext() {
        let address = StealthAddressView {
            public_key: [5u8; 32],
            tx_public_key: [6u8; 32],
        };
        let created_at = Utc::now();
        let encrypted = StealthEncryptedMemo {
            ciphertext: vec![7u8; 48],
            nonce: [8u8; 12],
            message_number: 3,
        };

        let output = StealthOutput::new_encrypted(
            "tx456".to_string(),
            2,
            address.clone(),
            encrypted.clone(),
            created_at,
        )
        .unwrap();

        assert!(output.amount.is_none());
        assert!(output.memo_plaintext.is_none());
        assert_eq!(output.memo_encrypted.as_ref().unwrap().ciphertext.len(), 48);

        let recomputed =
            StealthOutput::derive_commitment("tx456", 2, &address, None, None, Some(&encrypted));
        assert_eq!(output.commitment, recomputed);
    }
}
