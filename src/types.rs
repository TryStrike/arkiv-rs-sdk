//! Shared primitives: 20-byte addresses, 32-byte words, hex helpers, chain constants.
//!
//! This module is final. No module owner edits it; everything else builds on it.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha3::{Digest, Keccak256};

use crate::error::{Error, Result};

/// The Arkiv engine contract every `execute` call is sent to.
pub const ARKIV_ADDRESS: Address = Address([
    0x44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x44,
]);
/// Chain id of the Rabdi testnet.
pub const RABDI_CHAIN_ID: u64 = 7_794_095;
/// Public JSON-RPC endpoint of the Rabdi testnet.
pub const RABDI_RPC: &str = "https://rpc.rabdi.db-chain.testnet.arkiv.network";
/// Block time in seconds.
pub const BLOCK_TIME_SECS: u64 = 2;
/// Longest lifetime the protocol accepts, in blocks (about 182.5 days).
pub const MAX_LIFETIME_BLOCKS: u64 = 7_884_000;
/// 4-byte selector of `execute((uint8,bytes)[])`.
pub const EXECUTE_SELECTOR: [u8; 4] = [0x49, 0x65, 0x00, 0x44];
/// 4-byte selector of `entityNonce(address)`.
pub const ENTITY_NONCE_SELECTOR: [u8; 4] = [0x36, 0x91, 0x7b, 0xfd];

/// Keccak-256 of `data`.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// The `EntityCreated(bytes32,address,uint64,uint8)` event topic. Topic 1 of that log is the entity key.
pub fn entity_created_topic() -> B256 {
    B256(keccak256(b"EntityCreated(bytes32,address,uint64,uint8)"))
}

/// Decodes hex with or without a `0x` prefix.
pub fn hex_decode(s: &str) -> Result<Vec<u8>> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s)).map_err(|_| Error::InvalidHex(s.to_string()))
}

/// Encodes bytes as `0x`-prefixed lowercase hex.
pub fn hex_encode(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// Parses a JSON-RPC QUANTITY (`0x1a`) into a `u64`.
pub fn parse_quantity(s: &str) -> Result<u64> {
    let digits = s
        .strip_prefix("0x")
        .ok_or_else(|| Error::Decode(format!("not a quantity: {s}")))?;
    u64::from_str_radix(digits, 16).map_err(|_| Error::Decode(format!("not a quantity: {s}")))
}

/// Formats a `u64` as a JSON-RPC QUANTITY, with no leading zeros.
pub fn quantity(n: u64) -> String {
    format!("{n:#x}")
}

macro_rules! fixed_bytes {
    ($(#[$meta:meta])* $name:ident, $len:expr) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
        pub struct $name(pub [u8; $len]);

        impl $name {
            /// The raw bytes.
            pub fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "0x{}", hex::encode(self.0))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self)
            }
        }

        impl FromStr for $name {
            type Err = Error;
            fn from_str(s: &str) -> Result<Self> {
                let bytes = hex_decode(s)?;
                let arr: [u8; $len] = bytes
                    .try_into()
                    .map_err(|_| Error::InvalidHex(format!("{s}: expected {} bytes", $len)))?;
                Ok(Self(arr))
            }
        }

        impl From<[u8; $len]> for $name {
            fn from(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
                s.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                s.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

fixed_bytes!(
    /// A 20-byte Ethereum address. Displays as lowercase `0x` hex; parses any case.
    Address,
    20
);
fixed_bytes!(
    /// A 32-byte word: entity keys, transaction hashes, topics.
    B256,
    32
);

/// An entity key (32 bytes, derived by the engine).
pub type Key = B256;
/// A transaction hash.
pub type TxHash = B256;

impl Address {
    /// The address left-padded to a 32-byte ABI word.
    pub fn to_word(&self) -> [u8; 32] {
        let mut word = [0u8; 32];
        word[12..].copy_from_slice(&self.0);
        word
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_round_trip_and_case() {
        let a: Address = "0x0F05df479fcb23b2281e28813fb47e57e47d1bb7"
            .parse()
            .unwrap();
        assert_eq!(a.to_string(), "0x0f05df479fcb23b2281e28813fb47e57e47d1bb7");
        assert_eq!(a.to_word()[..12], [0u8; 12]);
        assert!("0x1234".parse::<Address>().is_err());
        assert!("zz".parse::<B256>().is_err());
    }

    #[test]
    fn constants_match_derived_values() {
        assert_eq!(
            ARKIV_ADDRESS.to_string(),
            "0x4400000000000000000000000000000000000044"
        );
        assert_eq!(
            &keccak256(b"execute((uint8,bytes)[])")[..4],
            &EXECUTE_SELECTOR
        );
        assert_eq!(
            &keccak256(b"entityNonce(address)")[..4],
            &ENTITY_NONCE_SELECTOR
        );
    }

    #[test]
    fn quantities() {
        assert_eq!(parse_quantity("0x64").unwrap(), 100);
        assert_eq!(quantity(100), "0x64");
        assert!(parse_quantity("64").is_err());
    }
}
