//! # Silica Named Accounts & Domain System
//!
//! Implementation of Design Plan 001: Named Accounts & Domain System
//!
//! This module provides human-readable names for accounts, replacing cryptic
//! hex addresses like `0x1a2b3c...` with memorable names like `silica.reserve`
//! or `alice.savings`.
//!
//! ## Domain Structure
//!
//! - `silica.*` - Reserved system namespace (treasury-controlled)
//! - `<name>` - Implicit user namespace (root names like `alice`)
//! - `<name>.<sub>` - User subdomains (like `alice.savings`)
//! - `app.*` - Verified application namespace (governance-approved)
//!
//! ## Security
//!
//! - `silica.*` names can only be registered by `silica.reserve` (treasury)
//! - System names registered at genesis never expire
//! - User names require annual renewal

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during name operations
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NameError {
    /// Name is too short (minimum 3 characters)
    #[error("Name too short: minimum 3 characters, got {0}")]
    TooShort(usize),

    /// Name is too long (maximum 64 characters for full path)
    #[error("Name too long: maximum 64 characters, got {0}")]
    TooLong(usize),

    /// Name contains invalid characters
    #[error("Invalid character '{0}' at position {1}: only a-z, 0-9, and - are allowed")]
    InvalidCharacter(char, usize),

    /// Name has too many labels/segments
    #[error("Too many labels: maximum 3 levels (a.b.c), got {0}")]
    TooManyLabels(usize),

    /// Name starts or ends with hyphen
    #[error("Name cannot start or end with hyphen")]
    InvalidHyphenPosition,

    /// Name uses a reserved prefix
    #[error("Reserved prefix '{0}' cannot be registered by users")]
    ReservedPrefix(String),

    /// Name is on the banned list
    #[error("Name '{0}' is banned")]
    BannedName(String),

    /// Empty label in name
    #[error("Empty label at position {0}")]
    EmptyLabel(usize),

    /// Name already registered
    #[error("Name '{0}' is already registered")]
    AlreadyRegistered(String),

    /// Name not found
    #[error("Name '{0}' not found")]
    NotFound(String),

    /// Unauthorized to register system names
    #[error("Only silica.reserve can register silica.* names")]
    UnauthorizedSystemRegistration,

    /// Name is not in system namespace
    #[error("Name '{0}' is not in silica.* namespace")]
    NotSystemNamespace(String),

    /// Not the owner of the name
    #[error("Not the owner of name '{0}'")]
    NotOwner(String),

    /// Name has expired
    #[error("Name '{0}' has expired")]
    Expired(String),

    /// Cannot modify permanent name
    #[error("Name '{0}' is permanent and cannot be modified")]
    PermanentName(String),
}

// ============================================================================
// Name Validation Configuration
// ============================================================================

/// Configuration for name validation rules
#[derive(Debug, Clone)]
pub struct NameValidation {
    /// Minimum length for a single label
    pub min_label_length: usize,
    /// Maximum length for full name path
    pub max_total_length: usize,
    /// Maximum number of labels (dot-separated segments)
    pub max_labels: usize,
    /// Reserved prefixes that cannot be registered by users
    pub reserved_prefixes: Vec<&'static str>,
    /// Completely banned names
    pub banned_names: Vec<&'static str>,
}

impl Default for NameValidation {
    fn default() -> Self {
        Self {
            min_label_length: 3,
            max_total_length: 64,
            max_labels: 3,
            reserved_prefixes: vec!["silica", "system", "protocol", "_", "app"],
            banned_names: vec![
                "admin", "root", "null", "undefined", "void", "none", "test",
            ],
        }
    }
}

// ============================================================================
// SilicaName - Validated Domain Name
// ============================================================================

/// A validated Silica domain name.
///
/// Names are hierarchical with dots as separators:
/// - `alice` - Root user name
/// - `alice.savings` - Subdomain owned by alice
/// - `silica.reserve` - System account (reserved)
///
/// # Validation Rules
///
/// - Minimum 3 characters per label
/// - Maximum 64 characters total
/// - Only lowercase a-z, 0-9, and hyphen (-)
/// - Cannot start or end with hyphen
/// - Maximum 3 levels deep (a.b.c)
/// - `silica.*` prefix is reserved for system accounts
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SilicaName {
    /// Full name string (e.g., "alice.savings" or "silica.reserve")
    full_name: String,
    /// Parsed labels in order: ["alice", "savings"]
    labels: Vec<String>,
    /// Whether this is a system-reserved name (silica.*)
    is_system: bool,
}

impl SilicaName {
    /// Parse and validate a name string.
    ///
    /// Note: System names (`silica.*`) cannot be parsed with this method.
    /// Use `parse_system()` for system account names.
    ///
    /// # Examples
    ///
    /// ```
    /// use silica_models::naming::SilicaName;
    ///
    /// let name = SilicaName::parse("alice").unwrap();
    /// assert_eq!(name.full_name(), "alice");
    /// assert!(!name.is_system_reserved());
    ///
    /// // System names must use parse_system (reserved prefix)
    /// assert!(SilicaName::parse("silica.reserve").is_err());
    /// ```
    pub fn parse(name: &str) -> Result<Self, NameError> {
        Self::parse_with_config(name, &NameValidation::default())
    }

    /// Parse with custom validation configuration.
    pub fn parse_with_config(name: &str, config: &NameValidation) -> Result<Self, NameError> {
        let name = name.to_lowercase();

        // Check total length
        if name.len() > config.max_total_length {
            return Err(NameError::TooLong(name.len()));
        }

        // Split into labels
        let labels: Vec<String> = name.split('.').map(String::from).collect();

        // Check label count
        if labels.len() > config.max_labels {
            return Err(NameError::TooManyLabels(labels.len()));
        }

        // Validate each label
        for (i, label) in labels.iter().enumerate() {
            Self::validate_label(label, i, config)?;
        }

        // Check for banned names (root label only)
        let root_label = &labels[0];
        if config.banned_names.iter().any(|&b| b == root_label) {
            return Err(NameError::BannedName(root_label.clone()));
        }

        // Determine if system-reserved
        let is_system = root_label == "silica";

        Ok(Self {
            full_name: name,
            labels,
            is_system,
        })
    }

    /// Parse a system name (allows reserved prefixes).
    ///
    /// Use this for `silica.*` system account names.
    ///
    /// # Examples
    ///
    /// ```
    /// use silica_models::naming::SilicaName;
    ///
    /// let system = SilicaName::parse_system("silica.reserve").unwrap();
    /// assert!(system.is_system_reserved());
    /// assert_eq!(system.root_label(), "silica");
    /// ```
    pub fn parse_system(name: &str) -> Result<Self, NameError> {
        let name = name.to_lowercase();
        let config = NameValidation::default();

        if name.len() > config.max_total_length {
            return Err(NameError::TooLong(name.len()));
        }

        let labels: Vec<String> = name.split('.').map(String::from).collect();

        if labels.len() > config.max_labels {
            return Err(NameError::TooManyLabels(labels.len()));
        }

        // Validate labels but skip reserved prefix check
        for (i, label) in labels.iter().enumerate() {
            if label.is_empty() {
                return Err(NameError::EmptyLabel(i));
            }
            if label.len() < config.min_label_length {
                return Err(NameError::TooShort(label.len()));
            }
            Self::validate_characters(label)?;
        }

        let is_system = labels[0] == "silica";

        Ok(Self {
            full_name: name,
            labels,
            is_system,
        })
    }

    /// Validate a single label.
    fn validate_label(label: &str, position: usize, config: &NameValidation) -> Result<(), NameError> {
        // Check empty
        if label.is_empty() {
            return Err(NameError::EmptyLabel(position));
        }

        // Check minimum length
        if label.len() < config.min_label_length {
            return Err(NameError::TooShort(label.len()));
        }

        // Check characters
        Self::validate_characters(label)?;

        // Check reserved prefixes (only for root label)
        if position == 0 && config.reserved_prefixes.iter().any(|&p| p == label) {
            return Err(NameError::ReservedPrefix(label.to_string()));
        }

        Ok(())
    }

    /// Validate that all characters are allowed.
    fn validate_characters(label: &str) -> Result<(), NameError> {
        // Check start/end hyphen
        if label.starts_with('-') || label.ends_with('-') {
            return Err(NameError::InvalidHyphenPosition);
        }

        // Check each character
        for (i, c) in label.chars().enumerate() {
            if !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '-' {
                return Err(NameError::InvalidCharacter(c, i));
            }
        }

        Ok(())
    }

    /// Get the full name string.
    pub fn full_name(&self) -> &str {
        &self.full_name
    }

    /// Get the parsed labels.
    pub fn labels(&self) -> &[String] {
        &self.labels
    }

    /// Check if this is a system-reserved name (silica.*).
    pub fn is_system_reserved(&self) -> bool {
        self.is_system
    }

    /// Get the root label (first segment).
    ///
    /// For "alice.savings", returns "alice".
    /// For "silica.reserve", returns "silica".
    pub fn root_label(&self) -> &str {
        &self.labels[0]
    }

    /// Get the parent name, if any.
    ///
    /// For "alice.savings", returns Some("alice").
    /// For "alice", returns None.
    pub fn parent(&self) -> Option<SilicaName> {
        if self.labels.len() <= 1 {
            return None;
        }

        let parent_labels = &self.labels[..self.labels.len() - 1];
        let parent_name = parent_labels.join(".");

        // Use parse_system to avoid reserved prefix check for silica.*
        if self.is_system {
            SilicaName::parse_system(&parent_name).ok()
        } else {
            SilicaName::parse(&parent_name).ok()
        }
    }

    /// Get the depth (number of labels).
    pub fn depth(&self) -> usize {
        self.labels.len()
    }

    /// Check if this name is a subdomain of another.
    pub fn is_subdomain_of(&self, parent: &SilicaName) -> bool {
        if self.labels.len() <= parent.labels.len() {
            return false;
        }

        self.labels[..parent.labels.len()] == parent.labels[..]
    }
}

impl std::fmt::Display for SilicaName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.full_name)
    }
}

impl TryFrom<&str> for SilicaName {
    type Error = NameError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl TryFrom<String> for SilicaName {
    type Error = NameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

// ============================================================================
// NameRecord - On-Chain Name Registration
// ============================================================================

/// A name registration record stored on-chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NameRecord {
    /// The resolved address
    pub address: String,
    /// Owner address (who can transfer/update)
    pub owner: Option<String>,
    /// When the name was registered
    pub registered_at: DateTime<Utc>,
    /// When the name expires (None = permanent)
    pub expires_at: Option<DateTime<Utc>>,
    /// Whether this is a permanent system name
    pub permanent: bool,
    /// Optional metadata (IPFS hash, etc.)
    pub metadata: Option<Vec<u8>>,
}

impl NameRecord {
    /// Create a new user name record with expiration.
    pub fn new_user(address: String, owner: String, duration_years: u8) -> Self {
        let now = Utc::now();
        let expires_at = now + chrono::Duration::days(365 * duration_years as i64);

        Self {
            address,
            owner: Some(owner),
            registered_at: now,
            expires_at: Some(expires_at),
            permanent: false,
            metadata: None,
        }
    }

    /// Create a permanent system name record.
    pub fn new_system(address: String, owner: Option<String>) -> Self {
        Self {
            address,
            owner,
            registered_at: Utc::now(),
            expires_at: None,
            permanent: true,
            metadata: None,
        }
    }

    /// Check if the name has expired.
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(expires) => Utc::now() > expires,
            None => false, // Permanent names never expire
        }
    }

    /// Check if the name is active (registered and not expired).
    pub fn is_active(&self) -> bool {
        !self.is_expired()
    }

    /// Extend the registration by additional years.
    pub fn extend(&mut self, additional_years: u8) -> Result<(), NameError> {
        if self.permanent {
            return Err(NameError::PermanentName("cannot extend permanent name".into()));
        }

        let base = self.expires_at.unwrap_or_else(Utc::now);
        self.expires_at = Some(base + chrono::Duration::days(365 * additional_years as i64));
        Ok(())
    }
}

// ============================================================================
// NameRegistry - Name Storage & Resolution
// ============================================================================

/// Serialization helper for BTreeMap<SilicaName, NameRecord>
/// 
/// JSON requires string keys, so we serialize SilicaName as its full_name string.
mod names_map_serde {
    use super::*;
    use serde::de::{MapAccess, Visitor};
    use serde::ser::SerializeMap;

    pub fn serialize<S>(
        map: &BTreeMap<SilicaName, NameRecord>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map_ser = serializer.serialize_map(Some(map.len()))?;
        for (k, v) in map {
            map_ser.serialize_entry(k.full_name(), v)?;
        }
        map_ser.end()
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<BTreeMap<SilicaName, NameRecord>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct NamesMapVisitor;

        impl<'de> Visitor<'de> for NamesMapVisitor {
            type Value = BTreeMap<SilicaName, NameRecord>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a map with string keys representing SilicaName")
            }

            fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut map = BTreeMap::new();
                while let Some((key, value)) = access.next_entry::<String, NameRecord>()? {
                    // Parse the string key back to SilicaName
                    // Use parse_system to allow silica.* names
                    let name = SilicaName::parse_system(&key)
                        .map_err(|_| serde::de::Error::custom(format!("invalid name: {}", key)))?;
                    map.insert(name, value);
                }
                Ok(map)
            }
        }

        deserializer.deserialize_map(NamesMapVisitor)
    }
}

/// Serialization helper for BTreeMap<String, SilicaName>
mod reverse_map_serde {
    use super::*;
    use serde::de::{MapAccess, Visitor};
    use serde::ser::SerializeMap;

    pub fn serialize<S>(
        map: &BTreeMap<String, SilicaName>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map_ser = serializer.serialize_map(Some(map.len()))?;
        for (k, v) in map {
            map_ser.serialize_entry(k, v.full_name())?;
        }
        map_ser.end()
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<BTreeMap<String, SilicaName>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ReverseMapVisitor;

        impl<'de> Visitor<'de> for ReverseMapVisitor {
            type Value = BTreeMap<String, SilicaName>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a map with string keys and string values representing SilicaName")
            }

            fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut map = BTreeMap::new();
                while let Some((key, value)) = access.next_entry::<String, String>()? {
                    let name = SilicaName::parse_system(&value)
                        .map_err(|_| serde::de::Error::custom(format!("invalid name: {}", value)))?;
                    map.insert(key, name);
                }
                Ok(map)
            }
        }

        deserializer.deserialize_map(ReverseMapVisitor)
    }
}

/// Registry for name → address mapping.
///
/// This is the core data structure for the naming system, typically
/// stored in protocol state.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NameRegistry {
    /// Forward resolution: name → record
    #[serde(with = "names_map_serde")]
    names: BTreeMap<SilicaName, NameRecord>,
    /// Reverse resolution: address → primary name
    #[serde(with = "reverse_map_serde")]
    reverse: BTreeMap<String, SilicaName>,
}

impl NameRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a registry initialized with genesis system names.
    ///
    /// This registers all `silica.*` system accounts defined in the protocol.
    pub fn with_genesis_names(genesis_accounts: &GenesisNameConfig) -> Self {
        let mut registry = Self::new();

        // Register keyless system accounts
        for (name, address) in &genesis_accounts.keyless_accounts {
            // Use parse_system to bypass reserved prefix validation
            if let Ok(parsed) = SilicaName::parse_system(name) {
                let record = NameRecord::new_system(address.clone(), None);
                registry.names.insert(parsed.clone(), record);
                registry.reverse.insert(address.clone(), parsed);
            }
        }

        // Register keyed system accounts (owned by silica.reserve)
        for (name, address) in &genesis_accounts.keyed_accounts {
            if let Ok(parsed) = SilicaName::parse_system(name) {
                // All keyed system names are owned by silica.reserve
                let record = NameRecord::new_system(
                    address.clone(),
                    Some("silica.reserve".to_string()),
                );
                registry.names.insert(parsed.clone(), record);
                registry.reverse.insert(address.clone(), parsed);
            }
        }

        registry
    }

    /// Resolve a name to its address.
    pub fn resolve(&self, name: &SilicaName) -> Result<&str, NameError> {
        let record = self
            .names
            .get(name)
            .ok_or_else(|| NameError::NotFound(name.full_name().to_string()))?;

        if record.is_expired() {
            return Err(NameError::Expired(name.full_name().to_string()));
        }

        Ok(&record.address)
    }

    /// Resolve a name string to its address.
    pub fn resolve_str(&self, name: &str) -> Result<&str, NameError> {
        // Try parsing as system name first (for silica.*)
        let parsed = if name.starts_with("silica.") {
            SilicaName::parse_system(name)?
        } else {
            SilicaName::parse(name)?
        };
        self.resolve(&parsed)
    }

    /// Reverse lookup: get the primary name for an address.
    pub fn reverse_resolve(&self, address: &str) -> Option<&SilicaName> {
        self.reverse.get(address)
    }

    /// Get the full record for a name.
    pub fn get_record(&self, name: &SilicaName) -> Option<&NameRecord> {
        self.names.get(name)
    }

    /// Get the total number of registered names.
    pub fn name_count(&self) -> usize {
        self.names.len()
    }

    /// Register a new user name.
    pub fn register_user(
        &mut self,
        name: SilicaName,
        address: String,
        owner: String,
        duration_years: u8,
    ) -> Result<(), NameError> {
        // Check not already registered
        if self.names.contains_key(&name) {
            return Err(NameError::AlreadyRegistered(name.full_name().to_string()));
        }

        // Check not trying to register system name
        if name.is_system_reserved() {
            return Err(NameError::UnauthorizedSystemRegistration);
        }

        let record = NameRecord::new_user(address.clone(), owner, duration_years);
        self.names.insert(name.clone(), record);
        self.reverse.insert(address, name);

        Ok(())
    }

    /// Register a new system name (treasury only).
    ///
    /// # Arguments
    ///
    /// * `caller` - The account attempting to register (must be "silica.reserve")
    /// * `name` - The system name to register (must start with "silica.")
    /// * `address` - The address to map to
    pub fn register_system(
        &mut self,
        caller: &str,
        name: SilicaName,
        address: String,
    ) -> Result<(), NameError> {
        // Only silica.reserve can register system names
        if caller != "silica.reserve" {
            return Err(NameError::UnauthorizedSystemRegistration);
        }

        // Must be a system name
        if !name.is_system_reserved() {
            return Err(NameError::NotSystemNamespace(name.full_name().to_string()));
        }

        // Check not already registered
        if self.names.contains_key(&name) {
            return Err(NameError::AlreadyRegistered(name.full_name().to_string()));
        }

        let record = NameRecord::new_system(address.clone(), Some(caller.to_string()));
        self.names.insert(name.clone(), record);
        self.reverse.insert(address, name);

        Ok(())
    }

    /// Transfer name ownership.
    pub fn transfer(
        &mut self,
        name: &SilicaName,
        caller: &str,
        new_owner: String,
    ) -> Result<(), NameError> {
        let record = self
            .names
            .get_mut(name)
            .ok_or_else(|| NameError::NotFound(name.full_name().to_string()))?;

        // Check ownership
        match &record.owner {
            Some(owner) if owner != caller => {
                return Err(NameError::NotOwner(name.full_name().to_string()));
            }
            None => {
                return Err(NameError::PermanentName(name.full_name().to_string()));
            }
            _ => {}
        }

        record.owner = Some(new_owner);
        Ok(())
    }

    /// Update the address for a name.
    pub fn update_address(
        &mut self,
        name: &SilicaName,
        caller: &str,
        new_address: String,
    ) -> Result<(), NameError> {
        let record = self
            .names
            .get_mut(name)
            .ok_or_else(|| NameError::NotFound(name.full_name().to_string()))?;

        // Check ownership
        match &record.owner {
            Some(owner) if owner != caller => {
                return Err(NameError::NotOwner(name.full_name().to_string()));
            }
            None => {
                return Err(NameError::PermanentName(name.full_name().to_string()));
            }
            _ => {}
        }

        // Update reverse mapping
        self.reverse.remove(&record.address);
        self.reverse.insert(new_address.clone(), name.clone());

        record.address = new_address;
        Ok(())
    }

    /// Renew a name registration.
    pub fn renew(
        &mut self,
        name: &SilicaName,
        caller: &str,
        additional_years: u8,
    ) -> Result<(), NameError> {
        let record = self
            .names
            .get_mut(name)
            .ok_or_else(|| NameError::NotFound(name.full_name().to_string()))?;

        // Check ownership
        match &record.owner {
            Some(owner) if owner != caller => {
                return Err(NameError::NotOwner(name.full_name().to_string()));
            }
            _ => {}
        }

        record.extend(additional_years)
    }

    /// Set reverse resolution preference for an address.
    pub fn set_reverse(&mut self, address: &str, name: SilicaName, caller: &str) -> Result<(), NameError> {
        // Verify caller owns the name
        let record = self
            .names
            .get(&name)
            .ok_or_else(|| NameError::NotFound(name.full_name().to_string()))?;

        match &record.owner {
            Some(owner) if owner != caller => {
                return Err(NameError::NotOwner(name.full_name().to_string()));
            }
            _ => {}
        }

        // Verify the name points to this address
        if record.address != address {
            return Err(NameError::NotOwner(format!(
                "Name {} does not resolve to {}",
                name.full_name(),
                address
            )));
        }

        self.reverse.insert(address.to_string(), name);
        Ok(())
    }

    /// Get all registered names (for iteration/export).
    pub fn all_names(&self) -> impl Iterator<Item = (&SilicaName, &NameRecord)> {
        self.names.iter()
    }

    /// Get count of registered names.
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// Check if registry is empty.
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}

// ============================================================================
// Genesis Configuration
// ============================================================================

/// Configuration for genesis system names.
///
/// Separates keyless accounts (protocol-controlled, no private keys)
/// from keyed accounts (have Dilithium2 keypairs).
#[derive(Debug, Clone, Default)]
pub struct GenesisNameConfig {
    /// Keyless system accounts (address is fixed, no owner)
    pub keyless_accounts: Vec<(String, String)>,
    /// Keyed system accounts (address from keypair, owned by silica.reserve)
    pub keyed_accounts: Vec<(String, String)>,
}

impl GenesisNameConfig {
    /// Create default genesis configuration with all silica.* system names.
    pub fn default_system_names() -> Self {
        Self {
            // Keyless accounts (reserved address range 0x00-0xff)
            keyless_accounts: vec![
                ("silica.void".into(), "0x0000000000000000000000000000000000000000".into()),
                ("silica.furnace".into(), "0x0000000000000000000000000000000000000001".into()),
                ("silica.origin".into(), "0x0000000000000000000000000000000000000002".into()),
                ("silica.levy".into(), "0x0000000000000000000000000000000000000003".into()),
                ("silica.conduit".into(), "0x0000000000000000000000000000000000000004".into()),
                ("silica.registry".into(), "0x0000000000000000000000000000000000000005".into()),
            ],
            // Keyed accounts (addresses will be set from genesis keypairs)
            // These are placeholders - actual addresses derived from Dilithium2 public keys
            keyed_accounts: vec![
                ("silica.reserve".into(), "".into()),   // Treasury
                ("silica.geyser".into(), "".into()),    // Mining/staking rewards
                ("silica.council".into(), "".into()),   // Governance
                ("silica.well".into(), "".into()),      // Testnet faucet
                ("silica.forge".into(), "".into()),     // Developer fund
                ("silica.bedrock".into(), "".into()),   // Staking deposits
                ("silica.basalt".into(), "".into()),    // Insurance fund
                ("silica.prism".into(), "".into()),     // Oracle rewards
                ("silica.quarry".into(), "".into()),    // Community grants
            ],
        }
    }

    /// Set the address for a keyed account (called during genesis generation).
    pub fn set_keyed_address(&mut self, name: &str, address: String) {
        for (n, addr) in &mut self.keyed_accounts {
            if n == name {
                *addr = address;
                return;
            }
        }
    }
}

// ============================================================================
// Constants
// ============================================================================

/// The treasury account that controls system namespace
pub const SYSTEM_TREASURY_NAME: &str = "silica.reserve";

/// All genesis system account names
pub const GENESIS_SYSTEM_NAMES: &[&str] = &[
    // Keyless
    "silica.void",
    "silica.furnace",
    "silica.origin",
    "silica.levy",
    "silica.conduit",
    "silica.registry",
    // Keyed
    "silica.reserve",
    "silica.geyser",
    "silica.council",
    "silica.well",
    "silica.forge",
    "silica.bedrock",
    "silica.basalt",
    "silica.prism",
    "silica.quarry",
];

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_names() {
        assert!(SilicaName::parse("alice").is_ok());
        assert!(SilicaName::parse("bob123").is_ok());
        assert!(SilicaName::parse("my-name").is_ok());
        assert!(SilicaName::parse("alice.savings").is_ok());
        assert!(SilicaName::parse("corp.dept.team").is_ok());
    }

    #[test]
    fn test_invalid_names() {
        // Too short
        assert!(matches!(
            SilicaName::parse("ab"),
            Err(NameError::TooShort(_))
        ));

        // Invalid characters (uppercase gets lowercased, so test actual invalid chars)
        assert!(matches!(
            SilicaName::parse("alice@home"),
            Err(NameError::InvalidCharacter(_, _))
        ));
        assert!(matches!(
            SilicaName::parse("alice_home"),
            Err(NameError::InvalidCharacter(_, _))
        ));
        assert!(matches!(
            SilicaName::parse("alice home"),
            Err(NameError::InvalidCharacter(_, _))
        ));

        // Invalid hyphen
        assert!(matches!(
            SilicaName::parse("-alice"),
            Err(NameError::InvalidHyphenPosition)
        ));
        assert!(matches!(
            SilicaName::parse("alice-"),
            Err(NameError::InvalidHyphenPosition)
        ));

        // Too many labels
        assert!(matches!(
            SilicaName::parse("a.b.c.d"),
            Err(NameError::TooManyLabels(_))
        ));

        // Reserved prefix
        assert!(matches!(
            SilicaName::parse("silica.test"),
            Err(NameError::ReservedPrefix(_))
        ));

        // Banned name
        assert!(matches!(
            SilicaName::parse("admin"),
            Err(NameError::BannedName(_))
        ));
        
        // Uppercase is lowercased and valid
        let name = SilicaName::parse("Alice").unwrap();
        assert_eq!(name.full_name(), "alice");
    }

    #[test]
    fn test_system_names() {
        let name = SilicaName::parse_system("silica.reserve").unwrap();
        assert!(name.is_system_reserved());
        assert_eq!(name.root_label(), "silica");

        let name = SilicaName::parse_system("silica.furnace").unwrap();
        assert!(name.is_system_reserved());
    }

    #[test]
    fn test_parent() {
        let name = SilicaName::parse("alice.savings").unwrap();
        let parent = name.parent().unwrap();
        assert_eq!(parent.full_name(), "alice");
        assert!(parent.parent().is_none());
    }

    #[test]
    fn test_subdomain() {
        let parent = SilicaName::parse("alice").unwrap();
        let child = SilicaName::parse("alice.savings").unwrap();
        let other = SilicaName::parse("bob.savings").unwrap();

        assert!(child.is_subdomain_of(&parent));
        assert!(!other.is_subdomain_of(&parent));
        assert!(!parent.is_subdomain_of(&child));
    }

    #[test]
    fn test_registry_genesis() {
        let config = GenesisNameConfig::default_system_names();
        let registry = NameRegistry::with_genesis_names(&config);

        // Should have all keyless accounts
        assert!(registry.resolve_str("silica.void").is_ok());
        assert!(registry.resolve_str("silica.furnace").is_ok());
        assert!(registry.resolve_str("silica.origin").is_ok());
        assert!(registry.resolve_str("silica.levy").is_ok());

        // Check addresses
        assert_eq!(
            registry.resolve_str("silica.void").unwrap(),
            "0x0000000000000000000000000000000000000000"
        );
        assert_eq!(
            registry.resolve_str("silica.furnace").unwrap(),
            "0x0000000000000000000000000000000000000001"
        );
    }

    #[test]
    fn test_registry_user_registration() {
        let mut registry = NameRegistry::new();

        let name = SilicaName::parse("alice").unwrap();
        let result = registry.register_user(
            name.clone(),
            "0x1234".into(),
            "0x1234".into(),
            1,
        );
        assert!(result.is_ok());

        // Should resolve
        assert_eq!(registry.resolve(&name).unwrap(), "0x1234");

        // Should not allow duplicate
        let result = registry.register_user(
            name,
            "0x5678".into(),
            "0x5678".into(),
            1,
        );
        assert!(matches!(result, Err(NameError::AlreadyRegistered(_))));
    }

    #[test]
    fn test_registry_system_registration() {
        let mut registry = NameRegistry::new();

        // Regular user cannot register system name
        let name = SilicaName::parse_system("silica.newaccount").unwrap();
        let result = registry.register_system(
            "some-user",
            name.clone(),
            "0x1234".into(),
        );
        assert!(matches!(result, Err(NameError::UnauthorizedSystemRegistration)));

        // Treasury can register system name
        let result = registry.register_system(
            "silica.reserve",
            name.clone(),
            "0x1234".into(),
        );
        assert!(result.is_ok());
        assert_eq!(registry.resolve(&name).unwrap(), "0x1234");
    }

    #[test]
    fn test_reverse_resolution() {
        let config = GenesisNameConfig::default_system_names();
        let registry = NameRegistry::with_genesis_names(&config);

        let name = registry.reverse_resolve("0x0000000000000000000000000000000000000000");
        assert!(name.is_some());
        assert_eq!(name.unwrap().full_name(), "silica.void");
    }

    #[test]
    fn test_name_expiration() {
        let mut record = NameRecord::new_user("0x1234".into(), "0x1234".into(), 1);
        assert!(!record.is_expired());
        assert!(record.is_active());

        // Manually set expired
        record.expires_at = Some(Utc::now() - chrono::Duration::days(1));
        assert!(record.is_expired());
        assert!(!record.is_active());
    }

    #[test]
    fn test_permanent_names() {
        let record = NameRecord::new_system("0x1234".into(), None);
        assert!(record.permanent);
        assert!(!record.is_expired());
        assert!(record.expires_at.is_none());
    }
}
