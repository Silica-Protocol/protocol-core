//! Core typed IDs for Silica protocol.
//!
//! These types provide type safety for network identifiers across all Silica components.

use std::borrow::Borrow;
use std::fmt::{Display, Formatter};
use std::sync::Arc;

use serde::de::{Deserializer, Error as DeError};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

// ============================================================================
// Constants
// ============================================================================

/// Maximum length of a peer identifier in bytes.
pub const MAX_PEER_ID_LEN: usize = 256;

/// Maximum length of a validator address string in bytes.
pub const MAX_VALIDATOR_LEN: usize = 130;

/// Maximum length of an account address in bytes.
pub const MAX_ACCOUNT_ADDR_LEN: usize = 64;

/// Maximum length of a namespace identifier in bytes.
pub const MAX_NAMESPACE_LEN: usize = 32;

/// Maximum length of a program/contract identifier in bytes.
pub const MAX_PROGRAM_ID_LEN: usize = 64;

// ============================================================================
// PeerId - Network peer identifier
// ============================================================================

/// Canonical peer identifier wrapper with validation.
/// Used for P2P networking, disconnecting, blacklisting peers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct PeerId(Arc<str>);

impl PeerId {
    /// Construct a new peer ID, enforcing length bounds.
    pub fn new(value: impl AsRef<str>) -> anyhow::Result<Self> {
        let value_ref = value.as_ref();
        if value_ref.is_empty() {
            return Err(anyhow::anyhow!("PeerId cannot be empty"));
        }
        if value_ref.len() > MAX_PEER_ID_LEN {
            return Err(anyhow::anyhow!("PeerId exceeds maximum length"));
        }
        if value_ref.chars().any(char::is_control) {
            return Err(anyhow::anyhow!("PeerId contains control characters"));
        }
        Ok(Self(Arc::from(value_ref)))
    }

    /// Borrow the peer ID as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_string(&self) -> String {
        self.as_str().to_string()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.as_str().as_bytes()
    }

    pub fn is_empty(&self) -> bool {
        self.as_str().is_empty()
    }

    pub fn len(&self) -> usize {
        self.as_str().len()
    }

    pub fn chars(&self) -> std::str::Chars<'_> {
        self.as_str().chars()
    }

    pub fn starts_with(&self, prefix: &str) -> bool {
        self.as_str().starts_with(prefix)
    }
}

impl Display for PeerId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for PeerId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for PeerId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value: std::borrow::Cow<'_, str> = std::borrow::Cow::deserialize(deserializer)?;
        PeerId::new(value.as_ref()).map_err(|err| DeError::custom(err.to_string()))
    }
}

impl AsRef<str> for PeerId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for PeerId {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl From<String> for PeerId {
    fn from(s: String) -> Self {
        Self(Arc::from(s))
    }
}

impl From<&str> for PeerId {
    fn from(s: &str) -> Self {
        Self(Arc::from(s))
    }
}

// ============================================================================
// ValidatorAddress - Validator consensus identifier
// ============================================================================

/// Validator address for consensus operations (slashing, voting).
/// This is the validator's identity in the consensus protocol.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct ValidatorAddress(Arc<str>);

impl ValidatorAddress {
    /// Construct a new validator address.
    pub fn new(value: impl AsRef<str>) -> anyhow::Result<Self> {
        let value_ref = value.as_ref();
        if value_ref.is_empty() {
            return Err(anyhow::anyhow!("ValidatorAddress cannot be empty"));
        }
        if value_ref.len() > MAX_VALIDATOR_LEN {
            return Err(anyhow::anyhow!("ValidatorAddress exceeds maximum length"));
        }
        if value_ref.chars().any(char::is_control) {
            return Err(anyhow::anyhow!(
                "ValidatorAddress contains control characters"
            ));
        }
        Ok(Self(Arc::from(value_ref)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_string(&self) -> String {
        self.as_str().to_string()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.as_str().as_bytes()
    }

    pub fn to_lowercase(&self) -> String {
        self.as_str().to_lowercase()
    }

    pub fn is_empty(&self) -> bool {
        self.as_str().is_empty()
    }

    pub fn len(&self) -> usize {
        self.as_str().len()
    }

    pub fn chars(&self) -> std::str::Chars<'_> {
        self.as_str().chars()
    }

    pub fn starts_with(&self, prefix: &str) -> bool {
        self.as_str().starts_with(prefix)
    }
}

impl Display for ValidatorAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for ValidatorAddress {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ValidatorAddress {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value: std::borrow::Cow<'_, str> = std::borrow::Cow::deserialize(deserializer)?;
        ValidatorAddress::new(value.as_ref()).map_err(|err| DeError::custom(err.to_string()))
    }
}

impl AsRef<str> for ValidatorAddress {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for ValidatorAddress {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl From<String> for ValidatorAddress {
    fn from(s: String) -> Self {
        Self(Arc::from(s))
    }
}

impl From<&str> for ValidatorAddress {
    fn from(s: &str) -> Self {
        Self(Arc::from(s))
    }
}

// ============================================================================
// AccountId - Wallet/contract address
// ============================================================================

/// User/contract account address wrapper.
/// Used for wallet operations, staking, transactions.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct AccountId(Arc<str>);

impl AccountId {
    /// Construct a new account ID.
    pub fn new(value: impl AsRef<str>) -> anyhow::Result<Self> {
        let value_ref = value.as_ref();
        if value_ref.is_empty() {
            return Err(anyhow::anyhow!("AccountId cannot be empty"));
        }
        if value_ref.len() > MAX_ACCOUNT_ADDR_LEN {
            return Err(anyhow::anyhow!("AccountId exceeds maximum length"));
        }
        if value_ref.chars().any(char::is_control) {
            return Err(anyhow::anyhow!("AccountId contains control characters"));
        }
        Ok(Self(Arc::from(value_ref)))
    }

    /// Construct an AccountId without validation.
    /// Use with caution - only for known-valid addresses.
    pub fn from_unchecked(value: impl Into<String>) -> Self {
        Self(Arc::from(value.into()))
    }

    /// Borrow the account ID as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_string(&self) -> String {
        self.as_str().to_string()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.as_str().as_bytes()
    }

    pub fn is_empty(&self) -> bool {
        self.as_str().is_empty()
    }

    pub fn len(&self) -> usize {
        self.as_str().len()
    }

    pub fn chars(&self) -> std::str::Chars<'_> {
        self.as_str().chars()
    }

    pub fn starts_with(&self, prefix: &str) -> bool {
        self.as_str().starts_with(prefix)
    }

    pub fn contains(&self, substring: &str) -> bool {
        self.as_str().contains(substring)
    }

    /// Check if the address has valid hex format (0x prefix + 40 hex chars)
    pub fn is_valid_format(&self) -> bool {
        let s = self.as_str();
        s.starts_with("0x") && s.len() == 42
    }

    /// Check if the address contains only valid hex characters (after 0x prefix)
    pub fn has_invalid_chars(&self) -> bool {
        let s = self.as_str();
        if s.starts_with("0x") {
            s[2..].chars().any(|c| !c.is_ascii_hexdigit())
        } else {
            s.chars().any(|c| !c.is_ascii_hexdigit())
        }
    }
}

impl Display for AccountId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for AccountId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AccountId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value: std::borrow::Cow<'_, str> = std::borrow::Cow::deserialize(deserializer)?;
        AccountId::new(value.as_ref()).map_err(|err| DeError::custom(err.to_string()))
    }
}

impl AsRef<str> for AccountId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for AccountId {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl From<String> for AccountId {
    fn from(s: String) -> Self {
        Self(Arc::from(s))
    }
}

impl From<&str> for AccountId {
    fn from(s: &str) -> Self {
        Self(Arc::from(s))
    }
}

// ============================================================================
// Namespace - Shard identifier
// ============================================================================

/// Shard/namespace identifier wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct Namespace(Arc<str>);

impl Namespace {
    pub fn new(value: impl AsRef<str>) -> anyhow::Result<Self> {
        let value_ref = value.as_ref();
        if value_ref.is_empty() {
            return Err(anyhow::anyhow!("Namespace cannot be empty"));
        }
        if value_ref.len() > MAX_NAMESPACE_LEN {
            return Err(anyhow::anyhow!("Namespace exceeds max length"));
        }
        Ok(Self(Arc::from(value_ref)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_string(&self) -> String {
        self.as_str().to_string()
    }

    pub fn is_empty(&self) -> bool {
        self.as_str().is_empty()
    }

    pub fn len(&self) -> usize {
        self.as_str().len()
    }

    pub fn starts_with(&self, prefix: &str) -> bool {
        self.as_str().starts_with(prefix)
    }
}

impl Display for Namespace {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for Namespace {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Namespace {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value: std::borrow::Cow<'_, str> = std::borrow::Cow::deserialize(deserializer)?;
        Namespace::new(value.as_ref()).map_err(|err| DeError::custom(err.to_string()))
    }
}

impl AsRef<str> for Namespace {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl From<String> for Namespace {
    fn from(s: String) -> Self {
        Self(Arc::from(s))
    }
}

impl From<&str> for Namespace {
    fn from(s: &str) -> Self {
        Self(Arc::from(s))
    }
}

// ============================================================================
// ProgramId - Smart contract identifier
// ============================================================================

/// Smart contract/program identifier wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct ProgramId(Arc<str>);

impl ProgramId {
    pub fn new(value: impl AsRef<str>) -> anyhow::Result<Self> {
        let value_ref = value.as_ref();
        if value_ref.is_empty() {
            return Err(anyhow::anyhow!("ProgramId cannot be empty"));
        }
        if value_ref.len() > MAX_PROGRAM_ID_LEN {
            return Err(anyhow::anyhow!("ProgramId exceeds max length"));
        }
        Ok(Self(Arc::from(value_ref)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_string(&self) -> String {
        self.as_str().to_string()
    }

    pub fn is_empty(&self) -> bool {
        self.as_str().is_empty()
    }

    pub fn len(&self) -> usize {
        self.as_str().len()
    }

    pub fn starts_with(&self, prefix: &str) -> bool {
        self.as_str().starts_with(prefix)
    }
}

impl Display for ProgramId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for ProgramId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ProgramId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value: std::borrow::Cow<'_, str> = std::borrow::Cow::deserialize(deserializer)?;
        ProgramId::new(value.as_ref()).map_err(|err| DeError::custom(err.to_string()))
    }
}

impl AsRef<str> for ProgramId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl From<String> for ProgramId {
    fn from(s: String) -> Self {
        Self(Arc::from(s))
    }
}

impl From<&str> for ProgramId {
    fn from(s: &str) -> Self {
        Self(Arc::from(s))
    }
}

// ============================================================================
// VoterId - Governance voting identity
// ============================================================================

/// Voter identity for governance voting - either a regular account or a validator.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum VoterId {
    /// Regular account (token holder)
    Account(AccountId),
    /// Validator node
    Validator(ValidatorAddress),
}

impl VoterId {
    pub fn is_account(&self) -> bool {
        matches!(self, VoterId::Account(_))
    }

    pub fn is_validator(&self) -> bool {
        matches!(self, VoterId::Validator(_))
    }

    pub fn as_account(&self) -> Option<&AccountId> {
        match self {
            VoterId::Account(id) => Some(id),
            VoterId::Validator(_) => None,
        }
    }

    pub fn as_validator(&self) -> Option<&ValidatorAddress> {
        match self {
            VoterId::Account(_) => None,
            VoterId::Validator(id) => Some(id),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            VoterId::Account(id) => id.as_str(),
            VoterId::Validator(id) => id.as_str(),
        }
    }
}

impl From<AccountId> for VoterId {
    fn from(id: AccountId) -> Self {
        VoterId::Account(id)
    }
}

impl From<ValidatorAddress> for VoterId {
    fn from(id: ValidatorAddress) -> Self {
        VoterId::Validator(id)
    }
}
