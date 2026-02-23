//! # Reserved System Addresses
//!
//! Implementation of Design Plan 002: Reserved System Addresses
//!
//! This module defines a reserved address range (0x00-0xff) for system accounts
//! with well-known, deterministic addresses. These addresses have special
//! protocol-level behaviors and are mapped to named accounts (`silica.*`).
//!
//! ## Address Categories
//!
//! ### Keyless Accounts (Reserved Range)
//! Fixed addresses with NO private keys - controlled entirely by protocol logic:
//! - `silica.void` (0x...0000) - Catchall rejection
//! - `silica.furnace` (0x...0001) - Token burn
//! - `silica.origin` (0x...0002) - Block reward source
//! - `silica.levy` (0x...0003) - Fee/slash collection
//! - `silica.conduit` (0x...0004) - Bridge operations
//! - `silica.registry` (0x...0005) - Name registry
//!
//! ### Keyed Accounts (Cryptographic Addresses)
//! Addresses derived from Dilithium2 public keys at genesis:
//! - `silica.reserve`, `silica.geyser`, `silica.council`, etc.
//!
//! See Design Plan 005 for keyed account generation.

use serde::{Deserialize, Serialize};

// ============================================================================
// Address Constants - Keyless System Accounts
// ============================================================================

/// Void address - rejects all transactions (catchall)
pub const SYSTEM_VOID: &str = "0x0000000000000000000000000000000000000000";

/// Furnace address - burns tokens permanently
pub const SYSTEM_FURNACE: &str = "0x0000000000000000000000000000000000000001";

/// Origin address - source of new coins (block rewards)
pub const SYSTEM_ORIGIN: &str = "0x0000000000000000000000000000000000000002";

/// Levy address - collects fees and slashed funds
pub const SYSTEM_LEVY: &str = "0x0000000000000000000000000000000000000003";

/// Conduit address - cross-chain bridge operations
pub const SYSTEM_CONDUIT: &str = "0x0000000000000000000000000000000000000004";

/// Registry address - name registry contract
pub const SYSTEM_REGISTRY: &str = "0x0000000000000000000000000000000000000005";

/// End of reserved address range
pub const SYSTEM_RESERVED_END: &str = "0x00000000000000000000000000000000000000ff";

/// All keyless system addresses with their names
pub const KEYLESS_SYSTEM_ACCOUNTS: &[(&str, &str)] = &[
    (SYSTEM_VOID, "silica.void"),
    (SYSTEM_FURNACE, "silica.furnace"),
    (SYSTEM_ORIGIN, "silica.origin"),
    (SYSTEM_LEVY, "silica.levy"),
    (SYSTEM_CONDUIT, "silica.conduit"),
    (SYSTEM_REGISTRY, "silica.registry"),
];

/// Names of all keyed system accounts (addresses derived from genesis keypairs)
pub const KEYED_SYSTEM_ACCOUNT_NAMES: &[&str] = &[
    "silica.reserve", // Treasury
    "silica.geyser",  // Mining/staking rewards
    "silica.council", // Governance
    "silica.well",    // Testnet faucet
    "silica.forge",   // Developer fund
    "silica.bedrock", // Staking deposits
    "silica.basalt",  // Insurance fund
    "silica.prism",   // Oracle rewards
    "silica.quarry",  // Community grants
];

// ============================================================================
// System Account Types
// ============================================================================

/// Types of system accounts in the reserved address range
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SystemAccountType {
    /// Void address (0x...0000) - rejects all transactions
    Void,
    /// Furnace address (0x...0001) - burns tokens on receipt
    Furnace,
    /// Origin address (0x...0002) - source of block rewards
    Origin,
    /// Levy address (0x...0003) - fee/slash collection pool
    Levy,
    /// Conduit address (0x...0004) - bridge operations
    Conduit,
    /// Registry address (0x...0005) - name registry
    Registry,
    /// Reserved but unallocated (0x...0006 - 0x...00ff)
    Reserved,
}

impl SystemAccountType {
    /// Get the fixed address for this system account type
    pub fn address(&self) -> &'static str {
        match self {
            Self::Void => SYSTEM_VOID,
            Self::Furnace => SYSTEM_FURNACE,
            Self::Origin => SYSTEM_ORIGIN,
            Self::Levy => SYSTEM_LEVY,
            Self::Conduit => SYSTEM_CONDUIT,
            Self::Registry => SYSTEM_REGISTRY,
            Self::Reserved => SYSTEM_RESERVED_END, // Placeholder
        }
    }

    /// Get the silica.* name for this system account type
    pub fn name(&self) -> &'static str {
        match self {
            Self::Void => "silica.void",
            Self::Furnace => "silica.furnace",
            Self::Origin => "silica.origin",
            Self::Levy => "silica.levy",
            Self::Conduit => "silica.conduit",
            Self::Registry => "silica.registry",
            Self::Reserved => "silica.reserved",
        }
    }

    /// Get the default permissions for this account type
    pub fn default_permissions(&self) -> SystemPermissions {
        match self {
            Self::Void => SystemPermissions::REJECT_ALL,
            Self::Furnace => {
                SystemPermissions::RECEIVE_ONLY.union(SystemPermissions::BURN_ON_RECEIVE)
            }
            Self::Origin => SystemPermissions::MINT_SOURCE,
            Self::Levy => SystemPermissions::RECEIVE_ONLY.union(SystemPermissions::FEE_COLLECTION),
            Self::Conduit => SystemPermissions::BRIDGE_OPERATIONS,
            Self::Registry => SystemPermissions::NAME_REGISTRY,
            Self::Reserved => SystemPermissions::UNINITIALIZED,
        }
    }

    /// Check if this account type can receive tokens
    pub fn can_receive(&self) -> bool {
        !matches!(self, Self::Void)
    }

    /// Check if this account type burns tokens on receipt
    pub fn burns_on_receive(&self) -> bool {
        matches!(self, Self::Furnace)
    }

    /// Check if this account type can mint new tokens
    pub fn can_mint(&self) -> bool {
        matches!(self, Self::Origin)
    }
}

impl std::fmt::Display for SystemAccountType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ============================================================================
// System Permissions (Bitflags)
// ============================================================================

/// System account permission flags.
///
/// These flags control what operations are allowed for system accounts.
/// Implemented manually to avoid bitflags dependency in core models.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[repr(transparent)]
pub struct SystemPermissions(u32);

impl SystemPermissions {
    /// Cannot receive any transactions (void)
    pub const REJECT_ALL: Self = Self(0);
    /// Can only receive, never send
    pub const RECEIVE_ONLY: Self = Self(1 << 0);
    /// Burns tokens on receipt (furnace)
    pub const BURN_ON_RECEIVE: Self = Self(1 << 1);
    /// Can send to other accounts (internal use)
    pub const INTERNAL_SEND: Self = Self(1 << 2);
    /// Can mint new tokens (origin)
    pub const MINT_SOURCE: Self = Self(1 << 3);
    /// Can execute governance proposals (council)
    pub const EXECUTE_PROPOSALS: Self = Self(1 << 4);
    /// Rate-limited sends (well/faucet)
    pub const RATE_LIMITED_SEND: Self = Self(1 << 5);
    /// Bridge operations - lock, mint, burn (conduit)
    pub const BRIDGE_OPERATIONS: Self = Self(1 << 6);
    /// Fee collection rights (levy)
    pub const FEE_COLLECTION: Self = Self(1 << 7);
    /// Name registry operations
    pub const NAME_REGISTRY: Self = Self(1 << 8);
    /// Staking deposit management (bedrock)
    pub const STAKING_DEPOSITS: Self = Self(1 << 9);
    /// Insurance fund operations (basalt)
    pub const INSURANCE_FUND: Self = Self(1 << 10);
    /// Uninitialized/reserved
    pub const UNINITIALIZED: Self = Self(1 << 31);

    /// Create permissions from raw bits
    #[inline]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Get raw bits
    #[inline]
    pub const fn bits(&self) -> u32 {
        self.0
    }

    /// Check if empty (REJECT_ALL)
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.0 == 0
    }

    /// Check if contains a permission
    #[inline]
    pub const fn contains(&self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Union of two permission sets
    #[inline]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Intersection of two permission sets
    #[inline]
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Check if can receive tokens
    #[inline]
    pub const fn can_receive(&self) -> bool {
        self.0 != 0 // REJECT_ALL is 0
    }

    /// Check if burns on receive
    #[inline]
    pub const fn burns_on_receive(&self) -> bool {
        self.contains(Self::BURN_ON_RECEIVE)
    }

    /// Check if can send tokens
    #[inline]
    pub const fn can_send(&self) -> bool {
        self.contains(Self::INTERNAL_SEND)
            || self.contains(Self::RATE_LIMITED_SEND)
            || self.contains(Self::BRIDGE_OPERATIONS)
    }

    /// Check if can mint tokens
    #[inline]
    pub const fn can_mint(&self) -> bool {
        self.contains(Self::MINT_SOURCE)
    }
}

impl std::ops::BitOr for SystemPermissions {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        self.union(rhs)
    }
}

impl std::ops::BitAnd for SystemPermissions {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Self) -> Self::Output {
        self.intersection(rhs)
    }
}

impl std::ops::BitOrAssign for SystemPermissions {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

// ============================================================================
// Address Validation Functions
// ============================================================================

/// Check if an address is in the reserved system range (0x00-0xff).
///
/// Reserved addresses are the first 256 addresses (suffix 0x00 to 0xff)
/// and are used for keyless system accounts.
///
/// # Examples
///
/// ```
/// use silica_models::system_addresses::is_reserved_address;
///
/// assert!(is_reserved_address("0x0000000000000000000000000000000000000000"));
/// assert!(is_reserved_address("0x00000000000000000000000000000000000000ff"));
/// assert!(!is_reserved_address("0x1234567890123456789012345678901234567890"));
/// ```
pub fn is_reserved_address(address: &str) -> bool {
    // Must be 42 characters (0x + 40 hex chars)
    if address.len() != 42 {
        return false;
    }

    // Must start with 0x
    if !address.starts_with("0x") && !address.starts_with("0X") {
        return false;
    }

    let hex_part = &address[2..];

    // Validate hex characters
    if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }

    // Check if first 38 characters are zeros (leaving 2 chars = 1 byte for suffix)
    // This means addresses 0x00...0000 through 0x00...00ff are reserved
    hex_part[..38].chars().all(|c| c == '0')
}

/// Get the system account type from a reserved address.
///
/// Returns `None` if the address is not in the reserved range.
///
/// # Examples
///
/// ```
/// use silica_models::system_addresses::{system_account_from_address, SystemAccountType};
///
/// let account_type = system_account_from_address("0x0000000000000000000000000000000000000000");
/// assert_eq!(account_type, Some(SystemAccountType::Void));
///
/// let account_type = system_account_from_address("0x0000000000000000000000000000000000000001");
/// assert_eq!(account_type, Some(SystemAccountType::Furnace));
/// ```
pub fn system_account_from_address(address: &str) -> Option<SystemAccountType> {
    if !is_reserved_address(address) {
        return None;
    }

    // Parse the last 2 hex characters as the suffix
    let suffix = u8::from_str_radix(&address[40..], 16).ok()?;

    Some(match suffix {
        0x00 => SystemAccountType::Void,
        0x01 => SystemAccountType::Furnace,
        0x02 => SystemAccountType::Origin,
        0x03 => SystemAccountType::Levy,
        0x04 => SystemAccountType::Conduit,
        0x05 => SystemAccountType::Registry,
        _ => SystemAccountType::Reserved,
    })
}

/// Get the system account name from a reserved address.
///
/// Returns the `silica.*` name if the address is a known system account,
/// or `None` if it's not in the reserved range or is an unallocated reserved address.
pub fn system_name_from_address(address: &str) -> Option<&'static str> {
    let account_type = system_account_from_address(address)?;

    match account_type {
        SystemAccountType::Reserved => None,
        _ => Some(account_type.name()),
    }
}

/// Get the reserved address for a system account name.
///
/// Only works for keyless system accounts (silica.void, silica.furnace, etc.).
/// Returns `None` for keyed accounts (silica.reserve, silica.geyser, etc.)
/// as their addresses are derived from public keys.
pub fn address_from_system_name(name: &str) -> Option<&'static str> {
    for (addr, n) in KEYLESS_SYSTEM_ACCOUNTS {
        if *n == name {
            return Some(addr);
        }
    }
    None
}

/// Check if a name refers to a keyless system account.
pub fn is_keyless_system_name(name: &str) -> bool {
    KEYLESS_SYSTEM_ACCOUNTS.iter().any(|(_, n)| *n == name)
}

/// Check if a name refers to a keyed system account.
pub fn is_keyed_system_name(name: &str) -> bool {
    KEYED_SYSTEM_ACCOUNT_NAMES.contains(&name)
}

/// Check if a name is any system name (keyless or keyed).
pub fn is_system_name(name: &str) -> bool {
    is_keyless_system_name(name) || is_keyed_system_name(name)
}

// ============================================================================
// Transaction Validation Errors
// ============================================================================

/// Errors related to system address operations
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SystemAddressError {
    /// Transaction to void address not allowed
    #[error("Cannot send to void address - all transactions are rejected")]
    VoidAddressNotAllowed,

    /// Cannot send from keyless account
    #[error("Cannot send from keyless system account '{0}'")]
    KeylessAccountCannotSend(String),

    /// Invalid recipient for system operation
    #[error("Invalid recipient for system operation: {0}")]
    InvalidRecipient(String),

    /// Reserved address cannot be used as user account
    #[error("Address {0} is reserved for system use")]
    ReservedAddressNotAllowed(String),

    /// Operation not permitted for this account type
    #[error("Operation '{0}' not permitted for account type {1}")]
    OperationNotPermitted(String, SystemAccountType),
}

// ============================================================================
// Transaction Validation Functions
// ============================================================================

/// Validate that a transaction recipient is allowed.
///
/// Returns an error if:
/// - Recipient is void address (all transactions rejected)
/// - Recipient is a reserved but unallocated address
pub fn validate_recipient(recipient: &str) -> Result<(), SystemAddressError> {
    if !is_reserved_address(recipient) {
        return Ok(());
    }

    let account_type = system_account_from_address(recipient)
        .ok_or_else(|| SystemAddressError::InvalidRecipient(recipient.to_string()))?;

    match account_type {
        SystemAccountType::Void => Err(SystemAddressError::VoidAddressNotAllowed),
        SystemAccountType::Reserved => Err(SystemAddressError::ReservedAddressNotAllowed(
            recipient.to_string(),
        )),
        _ => Ok(()), // Other system accounts can receive
    }
}

/// Validate that a sender is allowed to send.
///
/// Keyless system accounts cannot send (they have no private keys).
/// Returns an error if the sender is a keyless system account.
pub fn validate_sender(sender: &str) -> Result<(), SystemAddressError> {
    if !is_reserved_address(sender) {
        return Ok(());
    }

    let account_type = system_account_from_address(sender);

    match account_type {
        Some(SystemAccountType::Origin) => Ok(()), // Origin can "send" (mint)
        Some(account_type) => Err(SystemAddressError::KeylessAccountCannotSend(
            account_type.name().to_string(),
        )),
        None => Ok(()),
    }
}

/// Check if a transaction to this address should burn tokens.
pub fn should_burn_on_receive(recipient: &str) -> bool {
    system_account_from_address(recipient)
        .map(|t| t.burns_on_receive())
        .unwrap_or(false)
}

/// Check if creating an account at this address should be rejected.
///
/// User accounts cannot be created in the reserved address range.
pub fn is_account_creation_blocked(address: &str) -> bool {
    is_reserved_address(address)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reserved_address_detection() {
        // Should be reserved
        assert!(is_reserved_address(SYSTEM_VOID));
        assert!(is_reserved_address(SYSTEM_FURNACE));
        assert!(is_reserved_address(SYSTEM_ORIGIN));
        assert!(is_reserved_address(SYSTEM_LEVY));
        assert!(is_reserved_address(SYSTEM_CONDUIT));
        assert!(is_reserved_address(SYSTEM_REGISTRY));
        assert!(is_reserved_address(SYSTEM_RESERVED_END));
        assert!(is_reserved_address(
            "0x000000000000000000000000000000000000007f"
        ));

        // Should NOT be reserved
        assert!(!is_reserved_address(
            "0x0000000000000000000000000000000000000100"
        ));
        assert!(!is_reserved_address(
            "0x1234567890123456789012345678901234567890"
        ));
        assert!(!is_reserved_address("not-an-address"));
        assert!(!is_reserved_address("0x123")); // Too short
    }

    #[test]
    fn test_system_account_from_address() {
        assert_eq!(
            system_account_from_address(SYSTEM_VOID),
            Some(SystemAccountType::Void)
        );
        assert_eq!(
            system_account_from_address(SYSTEM_FURNACE),
            Some(SystemAccountType::Furnace)
        );
        assert_eq!(
            system_account_from_address(SYSTEM_ORIGIN),
            Some(SystemAccountType::Origin)
        );
        assert_eq!(
            system_account_from_address(SYSTEM_LEVY),
            Some(SystemAccountType::Levy)
        );
        assert_eq!(
            system_account_from_address(SYSTEM_CONDUIT),
            Some(SystemAccountType::Conduit)
        );
        assert_eq!(
            system_account_from_address(SYSTEM_REGISTRY),
            Some(SystemAccountType::Registry)
        );

        // Reserved but unallocated
        assert_eq!(
            system_account_from_address("0x00000000000000000000000000000000000000ff"),
            Some(SystemAccountType::Reserved)
        );

        // Not reserved
        assert_eq!(
            system_account_from_address("0x1234567890123456789012345678901234567890"),
            None
        );
    }

    #[test]
    fn test_system_name_from_address() {
        assert_eq!(system_name_from_address(SYSTEM_VOID), Some("silica.void"));
        assert_eq!(
            system_name_from_address(SYSTEM_FURNACE),
            Some("silica.furnace")
        );
        assert_eq!(
            system_name_from_address(SYSTEM_ORIGIN),
            Some("silica.origin")
        );
        assert_eq!(system_name_from_address(SYSTEM_LEVY), Some("silica.levy"));

        // Reserved but unallocated returns None
        assert_eq!(
            system_name_from_address("0x00000000000000000000000000000000000000ff"),
            None
        );

        // Non-reserved returns None
        assert_eq!(
            system_name_from_address("0x1234567890123456789012345678901234567890"),
            None
        );
    }

    #[test]
    fn test_address_from_system_name() {
        assert_eq!(address_from_system_name("silica.void"), Some(SYSTEM_VOID));
        assert_eq!(
            address_from_system_name("silica.furnace"),
            Some(SYSTEM_FURNACE)
        );
        assert_eq!(
            address_from_system_name("silica.origin"),
            Some(SYSTEM_ORIGIN)
        );
        assert_eq!(address_from_system_name("silica.levy"), Some(SYSTEM_LEVY));

        // Keyed accounts return None (address derived from pubkey)
        assert_eq!(address_from_system_name("silica.reserve"), None);
        assert_eq!(address_from_system_name("silica.geyser"), None);

        // Non-existent returns None
        assert_eq!(address_from_system_name("silica.nonexistent"), None);
        assert_eq!(address_from_system_name("alice"), None);
    }

    #[test]
    fn test_system_name_classification() {
        // Keyless
        assert!(is_keyless_system_name("silica.void"));
        assert!(is_keyless_system_name("silica.furnace"));
        assert!(!is_keyless_system_name("silica.reserve"));
        assert!(!is_keyless_system_name("alice"));

        // Keyed
        assert!(is_keyed_system_name("silica.reserve"));
        assert!(is_keyed_system_name("silica.geyser"));
        assert!(is_keyed_system_name("silica.council"));
        assert!(!is_keyed_system_name("silica.void"));
        assert!(!is_keyed_system_name("alice"));

        // Any system name
        assert!(is_system_name("silica.void"));
        assert!(is_system_name("silica.reserve"));
        assert!(!is_system_name("alice"));
    }

    #[test]
    fn test_system_permissions() {
        // Test basic operations
        let perms = SystemPermissions::RECEIVE_ONLY | SystemPermissions::BURN_ON_RECEIVE;
        assert!(perms.contains(SystemPermissions::RECEIVE_ONLY));
        assert!(perms.contains(SystemPermissions::BURN_ON_RECEIVE));
        assert!(!perms.contains(SystemPermissions::INTERNAL_SEND));

        // Test can_receive
        assert!(perms.can_receive());
        assert!(!SystemPermissions::REJECT_ALL.can_receive());

        // Test burns_on_receive
        assert!(perms.burns_on_receive());
        assert!(!SystemPermissions::RECEIVE_ONLY.burns_on_receive());

        // Test can_send
        assert!(SystemPermissions::INTERNAL_SEND.can_send());
        assert!(SystemPermissions::RATE_LIMITED_SEND.can_send());
        assert!(!SystemPermissions::RECEIVE_ONLY.can_send());

        // Test can_mint
        assert!(SystemPermissions::MINT_SOURCE.can_mint());
        assert!(!SystemPermissions::RECEIVE_ONLY.can_mint());
    }

    #[test]
    fn test_account_type_permissions() {
        // Void rejects all
        let perms = SystemAccountType::Void.default_permissions();
        assert!(!perms.can_receive());

        // Furnace burns
        let perms = SystemAccountType::Furnace.default_permissions();
        assert!(perms.can_receive());
        assert!(perms.burns_on_receive());
        assert!(!perms.can_send());

        // Origin can mint
        let perms = SystemAccountType::Origin.default_permissions();
        assert!(perms.can_mint());

        // Levy receives fees
        let perms = SystemAccountType::Levy.default_permissions();
        assert!(perms.can_receive());
        assert!(perms.contains(SystemPermissions::FEE_COLLECTION));
    }

    #[test]
    fn test_validate_recipient() {
        // Normal address is OK
        assert!(validate_recipient("0x1234567890123456789012345678901234567890").is_ok());

        // Furnace is OK (burns)
        assert!(validate_recipient(SYSTEM_FURNACE).is_ok());

        // Levy is OK (collects fees)
        assert!(validate_recipient(SYSTEM_LEVY).is_ok());

        // Void is NOT OK
        assert!(matches!(
            validate_recipient(SYSTEM_VOID),
            Err(SystemAddressError::VoidAddressNotAllowed)
        ));

        // Reserved unallocated is NOT OK
        assert!(matches!(
            validate_recipient("0x00000000000000000000000000000000000000ff"),
            Err(SystemAddressError::ReservedAddressNotAllowed(_))
        ));
    }

    #[test]
    fn test_validate_sender() {
        // Normal address is OK
        assert!(validate_sender("0x1234567890123456789012345678901234567890").is_ok());

        // Origin is OK (can mint)
        assert!(validate_sender(SYSTEM_ORIGIN).is_ok());

        // Void cannot send
        assert!(matches!(
            validate_sender(SYSTEM_VOID),
            Err(SystemAddressError::KeylessAccountCannotSend(_))
        ));

        // Furnace cannot send
        assert!(matches!(
            validate_sender(SYSTEM_FURNACE),
            Err(SystemAddressError::KeylessAccountCannotSend(_))
        ));

        // Levy cannot send (receives only)
        assert!(matches!(
            validate_sender(SYSTEM_LEVY),
            Err(SystemAddressError::KeylessAccountCannotSend(_))
        ));
    }

    #[test]
    fn test_should_burn_on_receive() {
        assert!(should_burn_on_receive(SYSTEM_FURNACE));
        assert!(!should_burn_on_receive(SYSTEM_VOID));
        assert!(!should_burn_on_receive(SYSTEM_LEVY));
        assert!(!should_burn_on_receive(
            "0x1234567890123456789012345678901234567890"
        ));
    }

    #[test]
    fn test_account_creation_blocked() {
        // Reserved range is blocked
        assert!(is_account_creation_blocked(SYSTEM_VOID));
        assert!(is_account_creation_blocked(SYSTEM_FURNACE));
        assert!(is_account_creation_blocked(
            "0x00000000000000000000000000000000000000ff"
        ));

        // Normal addresses are not blocked
        assert!(!is_account_creation_blocked(
            "0x1234567890123456789012345678901234567890"
        ));
    }
}
