//! Core typed IDs for Silica protocol.
//!
//! These types provide type safety for network identifiers across all Silica components.

use std::borrow::Borrow;
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use std::sync::Arc;

use serde::de::{Deserializer, Error as DeError};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

// ============================================================================
// Constants
// ============================================================================

/// Maximum length of a peer identifier in bytes.
pub const MAX_PEER_ID_LEN: usize = 68;

/// Maximum length of a validator address string in bytes.
pub const MAX_VALIDATOR_LEN: usize = 43;

/// Maximum length of a worker identifier string in bytes.
pub const MAX_WORKER_ID_LEN: usize = 68;

/// Maximum length of an account address in bytes.
pub const MAX_ACCOUNT_ADDR_LEN: usize = 42;

/// Fixed payload length for account and validator addresses (20 bytes, 40 hex chars).
pub const ADDRESS_HEX_PAYLOAD_LEN: usize = 40;

/// Fixed payload length for peer and worker ids (32 bytes, 64 hex chars).
pub const NODE_ID_HEX_PAYLOAD_LEN: usize = 64;

fn validate_prefixed_hex(
    value: &str,
    prefix: &str,
    payload_hex_len: usize,
    type_name: &str,
) -> anyhow::Result<()> {
    let expected_len = prefix.len() + payload_hex_len;

    if value.len() != expected_len {
        return Err(anyhow::anyhow!(
            "{} must be exactly {} characters (prefix '{}' + {} hex chars)",
            type_name,
            expected_len,
            prefix,
            payload_hex_len
        ));
    }

    if !value.starts_with(prefix) {
        return Err(anyhow::anyhow!(
            "{} must start with '{}'",
            type_name,
            prefix
        ));
    }

    let payload = &value[prefix.len()..];
    if !payload.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow::anyhow!(
            "{} payload must contain only hex characters",
            type_name
        ));
    }

    Ok(())
}

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
        validate_prefixed_hex(
            value_ref,
            "PEER",
            NODE_ID_HEX_PAYLOAD_LEN,
            "PeerId",
        )?;
        Ok(Self(Arc::from(value_ref)))
    }

    /// Explicit parser for network peer identity input.
    pub fn from_peer_str(value: &str) -> anyhow::Result<Self> {
        Self::new(value)
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

impl From<PeerId> for String {
    fn from(p: PeerId) -> Self {
        p.as_string()
    }
}

impl TryFrom<&str> for PeerId {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<String> for PeerId {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl FromStr for PeerId {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
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
        validate_prefixed_hex(
            value_ref,
            "VAL",
            ADDRESS_HEX_PAYLOAD_LEN,
            "ValidatorAddress",
        )?;
        Ok(Self(Arc::from(value_ref)))
    }

    /// Explicit parser for validator consensus identity input.
    pub fn from_validator_str(value: &str) -> anyhow::Result<Self> {
        Self::new(value)
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

impl TryFrom<&str> for ValidatorAddress {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<String> for ValidatorAddress {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ValidatorAddress> for String {
    fn from(v: ValidatorAddress) -> Self {
        v.as_string()
    }
}

impl FromStr for ValidatorAddress {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

// ============================================================================
// WorkerId - Alluvium worker identifier
// ============================================================================

/// Worker identifier for Alluvium data-plane operations.
/// This identifier is distinct from validator consensus identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct WorkerId(Arc<str>);

impl WorkerId {
    /// Construct a new worker identifier.
    pub fn new(value: impl AsRef<str>) -> anyhow::Result<Self> {
        let value_ref = value.as_ref();
        validate_prefixed_hex(
            value_ref,
            "WORK",
            NODE_ID_HEX_PAYLOAD_LEN,
            "WorkerId",
        )?;
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

impl Display for WorkerId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for WorkerId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for WorkerId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value: std::borrow::Cow<'_, str> = std::borrow::Cow::deserialize(deserializer)?;
        WorkerId::new(value.as_ref()).map_err(|err| DeError::custom(err.to_string()))
    }
}

impl AsRef<str> for WorkerId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for WorkerId {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl TryFrom<&str> for WorkerId {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<String> for WorkerId {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<WorkerId> for String {
    fn from(v: WorkerId) -> Self {
        v.as_string()
    }
}

impl FromStr for WorkerId {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
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
        validate_prefixed_hex(value_ref, "0x", ADDRESS_HEX_PAYLOAD_LEN, "AccountId")?;
        Ok(Self(Arc::from(value_ref)))
    }

    /// Explicit parser for account identity input.
    pub fn from_account_str(value: &str) -> anyhow::Result<Self> {
        Self::new(value)
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
        s.starts_with("0x") && s.len() == MAX_ACCOUNT_ADDR_LEN
    }

    /// Check if the address contains only valid hex characters (after 0x prefix)
    pub fn has_invalid_chars(&self) -> bool {
        let s = self.as_str();
        !s[2..].chars().all(|c| c.is_ascii_hexdigit())
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

impl Default for AccountId {
    fn default() -> Self {
        Self(Arc::from("0x0000000000000000000000000000000000000000"))
    }
}

impl TryFrom<&str> for AccountId {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<String> for AccountId {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<AccountId> for String {
    fn from(a: AccountId) -> Self {
        a.as_string()
    }
}

impl FromStr for AccountId {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
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

impl Borrow<str> for Namespace {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl Namespace {
    pub fn as_bytes(&self) -> &[u8] {
        self.as_str().as_bytes()
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

impl std::cmp::PartialOrd for VoterId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::cmp::Ord for VoterId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl AsRef<str> for VoterId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl std::borrow::Borrow<str> for VoterId {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl Display for VoterId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl TryFrom<&str> for VoterId {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.starts_with("VAL") {
            return Ok(VoterId::Validator(ValidatorAddress::new(value)?));
        }

        if value.starts_with("0x") {
            return Ok(VoterId::Account(AccountId::new(value)?));
        }

        Err(anyhow::anyhow!(
            "VoterId must be canonical AccountId (0x...) or ValidatorAddress (VAL...)"
        ))
    }
}

impl TryFrom<String> for VoterId {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}
