//! Deterministic test fixtures for strongly-typed identity values.
//!
//! These helpers generate format-valid IDs while keeping tests concise.

use crate::types::{AccountId, PeerId, ValidatorAddress, WorkerId};

fn hex_payload(counter: u64, hex_len: usize) -> String {
    format!("{counter:0width$x}", width = hex_len)
}

/// Generate a deterministic account ID: `0x` + 40 hex chars.
pub fn account_id(counter: u64) -> AccountId {
    let encoded = format!("0x{}", hex_payload(counter, 40));
    AccountId::new(encoded).expect("generated test AccountId must be valid")
}

/// Generate a deterministic validator address: `VAL` + 40 hex chars.
pub fn validator_address(counter: u64) -> ValidatorAddress {
    let encoded = format!("VAL{}", hex_payload(counter, 40));
    ValidatorAddress::new(encoded).expect("generated test ValidatorAddress must be valid")
}

/// Generate a deterministic peer id: `PEER` + 64 hex chars.
pub fn peer_id(counter: u64) -> PeerId {
    let encoded = format!("PEER{}", hex_payload(counter, 64));
    PeerId::new(encoded).expect("generated test PeerId must be valid")
}

/// Generate a deterministic worker id: `WORK` + 64 hex chars.
pub fn worker_id(counter: u64) -> WorkerId {
    let encoded = format!("WORK{}", hex_payload(counter, 64));
    WorkerId::new(encoded).expect("generated test WorkerId must be valid")
}
