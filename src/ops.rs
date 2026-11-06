//! Entity operations, `execute` calldata, and size-capped batching.
//!
//! All ABI encoding lives here, in a private minimal encoder: 32-byte words, `bytes` cells and
//! the attribute array. Layouts match the official SDK byte for byte (golden vectors in tests).

use std::time::Duration;

use crate::attributes::{normalize, validate_name, Attribute, TOMBSTONE_TYPE_BYTE};
use crate::error::{Error, Result};
use crate::types::{
    keccak256, Address, Key, ARKIV_ADDRESS, B256, BLOCK_TIME_SECS, EXECUTE_SELECTOR,
    MAX_LIFETIME_BLOCKS,
};

/// Default cap on `execute` calldata bytes. The public node answers 413 to request bodies past
/// about 200 KB and a batch goes up twice as hex (gas estimate, then the signed tx).
pub const DEFAULT_MAX_CALLDATA: usize = 60_000;
/// Operation tags of the `execute` ABI's tagged union.
pub const OP_CREATE: u8 = 1;
/// Tag of a patch.
pub const OP_PATCH: u8 = 2;
/// Tag of an expiry extension.
pub const OP_EXTEND_EXPIRY: u8 = 3;
/// Tag of an ownership transfer.
pub const OP_TRANSFER_OWNERSHIP: u8 = 4;
/// Tag of a delete.
pub const OP_DELETE: u8 = 5;

/// How long an entity lives, as the wire pair `(expiresAt, minLifetime)`. The engine takes
/// whichever lands later. At least one is non-zero and `min_lifetime` is at most
/// [`MAX_LIFETIME_BLOCKS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Expiry {
    /// Absolute block height, or 0.
    pub expires_at: u64,
    /// Lifetime in blocks counted from the block the operation lands in, or 0.
    pub min_lifetime: u64,
}

impl Expiry {
    /// A lifetime of `blocks` blocks. Errors on 0 or above the protocol maximum.
    ///
    /// ```
    /// use arkiv::Expiry;
    ///
    /// assert_eq!(Expiry::blocks(600).unwrap().min_lifetime, 600);
    /// assert_eq!(Expiry::seconds(60).unwrap().min_lifetime, 30);
    /// assert!(Expiry::blocks(0).is_err());
    /// assert!(Expiry::blocks(7_884_001).is_err());
    /// ```
    pub fn blocks(blocks: u64) -> Result<Expiry> {
        let expiry = Expiry {
            expires_at: 0,
            min_lifetime: blocks,
        };
        expiry.validate()?;
        Ok(expiry)
    }
    /// A lifetime in seconds; must be a positive multiple of the 2 s block time.
    pub fn seconds(seconds: u64) -> Result<Expiry> {
        if !seconds.is_multiple_of(BLOCK_TIME_SECS) {
            return Err(Error::InvalidExpiry(format!(
                "{seconds} s is not a multiple of the {BLOCK_TIME_SECS} s block time"
            )));
        }
        Expiry::blocks(seconds / BLOCK_TIME_SECS)
    }
    /// A lifetime from a [`Duration`] at the 2 s block time. Partial blocks round up and anything
    /// past the protocol maximum is capped at it, so long lifetimes never fail. Errors on a zero duration.
    pub fn from_duration(duration: Duration) -> Result<Expiry> {
        let secs = duration.as_secs() + u64::from(duration.subsec_nanos() > 0);
        let blocks = secs.div_ceil(BLOCK_TIME_SECS).min(MAX_LIFETIME_BLOCKS);
        Expiry::blocks(blocks)
    }
    /// Checks the pair: not both zero, `min_lifetime` within the protocol maximum.
    pub fn validate(&self) -> Result<()> {
        if self.expires_at == 0 && self.min_lifetime == 0 {
            return Err(Error::InvalidExpiry("expiry is zero".into()));
        }
        if self.min_lifetime > MAX_LIFETIME_BLOCKS {
            return Err(Error::InvalidExpiry(format!(
                "{} blocks is over the protocol maximum of {MAX_LIFETIME_BLOCKS}",
                self.min_lifetime
            )));
        }
        Ok(())
    }
    /// An absolute deadline block.
    pub fn at_block(block: u64) -> Result<Expiry> {
        let expiry = Expiry {
            expires_at: block,
            min_lifetime: 0,
        };
        expiry.validate()?;
        Ok(expiry)
    }
    /// The longest lifetime the protocol allows.
    pub fn max() -> Expiry {
        Expiry {
            expires_at: 0,
            min_lifetime: MAX_LIFETIME_BLOCKS,
        }
    }
}

/// Creation flags, packed into one byte: bit 0 readonly, bit 1 permissionless extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CreationFlags {
    /// Nobody can change the entity once written, its creator included.
    pub readonly: bool,
    /// Anyone may extend the entity's expiry.
    pub permissionless_extension: bool,
}

impl CreationFlags {
    /// Packs the flags into the wire byte.
    pub fn to_byte(self) -> u8 {
        u8::from(self.readonly) | u8::from(self.permissionless_extension) << 1
    }
    /// Unpacks a wire byte. Unknown bits are ignored.
    pub fn from_byte(byte: u8) -> CreationFlags {
        CreationFlags {
            readonly: byte & 1 != 0,
            permissionless_extension: byte & 2 != 0,
        }
    }
}

/// Creates one entity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Create {
    /// Attributes, already validated; sorted by [`normalize`] at encode time.
    pub attributes: Vec<Attribute>,
    /// Lifetime.
    pub expiry: Expiry,
    /// Creation flags.
    pub flags: CreationFlags,
    /// The 128-bit salt mixed into the entity key. Fixed at construction so encoding is deterministic.
    pub salt: u128,
}

impl Create {
    /// A create with a fresh random salt and default flags (writable).
    ///
    /// ```
    /// use arkiv::{Attribute, Create, Expiry};
    ///
    /// let attrs = vec![Attribute::schema("demo.items").unwrap()];
    /// let create = Create::new(attrs, Expiry::blocks(600).unwrap()).unwrap().readonly();
    /// assert!(create.flags.readonly);
    /// ```
    pub fn new(attributes: Vec<Attribute>, expiry: Expiry) -> Result<Create> {
        expiry.validate()?;
        let attributes = normalize(attributes)?;
        let mut salt = [0u8; 16];
        getrandom::getrandom(&mut salt).map_err(|e| Error::Random(e.to_string()))?;
        Ok(Create {
            attributes,
            expiry,
            flags: CreationFlags::default(),
            salt: u128::from_be_bytes(salt),
        })
    }
    /// Marks the entity readonly.
    pub fn readonly(mut self) -> Create {
        self.flags.readonly = true;
        self
    }
    /// Replaces the salt, for keys predicted ahead with [`predict_entity_key`].
    pub fn with_salt(mut self, salt: u128) -> Create {
        self.salt = salt;
        self
    }
}

/// Changes attributes of an existing entity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Patch {
    /// The entity to change.
    pub key: Key,
    /// Attributes to write.
    pub set: Vec<Attribute>,
    /// Attribute names to remove (encoded as tombstones).
    pub unset: Vec<String>,
}

/// One operation of an `execute` batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    /// Create an entity.
    Create(Create),
    /// Patch an entity.
    Patch(Patch),
    /// Push an entity's expiry out. Shortening reverts on chain.
    ExtendExpiry {
        /// The entity.
        key: Key,
        /// The new expiry.
        expiry: Expiry,
    },
    /// Hand an entity to a new owner.
    TransferOwnership {
        /// The entity.
        key: Key,
        /// The new owner.
        new_owner: Address,
    },
    /// Delete an entity before it expires.
    Delete {
        /// The entity.
        key: Key,
    },
}

impl Op {
    /// The wire tag: one of the `OP_*` constants.
    pub fn tag(&self) -> u8 {
        match self {
            Op::Create(_) => OP_CREATE,
            Op::Patch(_) => OP_PATCH,
            Op::ExtendExpiry { .. } => OP_EXTEND_EXPIRY,
            Op::TransferOwnership { .. } => OP_TRANSFER_OWNERSHIP,
            Op::Delete { .. } => OP_DELETE,
        }
    }
    /// `abi.encode` of the payload struct the tag selects (the `operationData` bytes).
    pub fn data(&self) -> Result<Vec<u8>> {
        match self {
            Op::Create(c) => {
                c.expiry.validate()?;
                let mut out = word(0x20).to_vec();
                for v in [
                    c.salt,
                    c.expiry.expires_at.into(),
                    c.expiry.min_lifetime.into(),
                    c.flags.to_byte().into(),
                    0xa0,
                ] {
                    out.extend(word(v));
                }
                out.extend(array(&entries(c.attributes.clone())?));
                Ok(out)
            }
            Op::Patch(p) => {
                if p.set.is_empty() && p.unset.is_empty() {
                    return Err(Error::InvalidValue {
                        kind: "patch",
                        reason: "empty patch changes nothing".into(),
                    });
                }
                let mut all = entries(p.set.clone())?;
                for name in &p.unset {
                    validate_name(name)?;
                    all.push(Entry {
                        name: name_word(name),
                        type_byte: TOMBSTONE_TYPE_BYTE,
                        value: Vec::new(),
                    });
                }
                all.sort_by_key(|e| e.name);
                if let Some(w) = all.windows(2).find(|w| w[0].name == w[1].name) {
                    return Err(Error::DuplicateAttribute(word_name(&w[0].name)));
                }
                // A struct with a dynamic member: abi.encode leads with the 0x20 offset word.
                let mut out = word(0x20).to_vec();
                out.extend(p.key.0);
                out.extend(word(0x40));
                out.extend(array(&all));
                Ok(out)
            }
            Op::ExtendExpiry { key, expiry } => {
                expiry.validate()?;
                let mut out = key.0.to_vec();
                out.extend(word(expiry.expires_at.into()));
                out.extend(word(expiry.min_lifetime.into()));
                Ok(out)
            }
            Op::TransferOwnership { key, new_owner } => {
                let mut out = key.0.to_vec();
                out.extend(new_owner.to_word());
                Ok(out)
            }
            Op::Delete { key } => Ok(key.0.to_vec()),
        }
    }
    /// Bytes this op adds to `execute` calldata: 128 + the payload padded to a multiple of 32.
    pub fn calldata_len(&self) -> Result<usize> {
        Ok(128 + pad32(self.data()?.len()))
    }
}

impl From<Create> for Op {
    fn from(c: Create) -> Op {
        Op::Create(c)
    }
}

impl From<Patch> for Op {
    fn from(p: Patch) -> Op {
        Op::Patch(p)
    }
}

/// One attribute tuple `(bytes32 name, uint8 typeId, bytes value)`, ready to encode.
struct Entry {
    name: [u8; 32],
    type_byte: u8,
    value: Vec<u8>,
}

fn word(value: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&value.to_be_bytes());
    w
}

fn pad32(n: usize) -> usize {
    n.div_ceil(32) * 32
}

fn name_word(name: &str) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[..name.len()].copy_from_slice(name.as_bytes());
    w
}

fn word_name(w: &[u8; 32]) -> String {
    let end = w.iter().position(|&b| b == 0).unwrap_or(32);
    String::from_utf8_lossy(&w[..end]).into_owned()
}

/// Validates, sorts and converts attributes to wire entries.
fn entries(attributes: Vec<Attribute>) -> Result<Vec<Entry>> {
    normalize(attributes)?
        .iter()
        .map(|a| {
            Ok(Entry {
                name: a.name_word(),
                type_byte: a.type_byte(),
                value: a.value.encode()?,
            })
        })
        .collect()
}

/// `abi.encode` of `(bytes32,uint8,bytes)[]`: count, offsets, then each tuple.
fn array(items: &[Entry]) -> Vec<u8> {
    let mut out = word(items.len() as u128).to_vec();
    let mut offset = items.len() * 32;
    for e in items {
        out.extend(word(offset as u128));
        offset += 128 + pad32(e.value.len());
    }
    for e in items {
        out.extend(e.name);
        out.extend(word(e.type_byte.into()));
        out.extend(word(96));
        out.extend(word(e.value.len() as u128));
        out.extend(&e.value);
        out.resize(out.len() + pad32(e.value.len()) - e.value.len(), 0);
    }
    out
}

/// Bytes of calldata outside the ops: selector, array offset word, array length word.
const CALLDATA_OVERHEAD: usize = 4 + 64;

/// `execute(ops)` calldata: the 4-byte selector followed by `abi.encode(ops)`.
/// Errors with [`Error::EmptyBatch`] on no ops.
pub fn execute_calldata(ops: &[Op]) -> Result<Vec<u8>> {
    if ops.is_empty() {
        return Err(Error::EmptyBatch);
    }
    let datas = ops.iter().map(Op::data).collect::<Result<Vec<_>>>()?;
    let mut out = EXECUTE_SELECTOR.to_vec();
    out.extend(word(0x20));
    out.extend(word(ops.len() as u128));
    let mut offset = ops.len() * 32;
    for d in &datas {
        out.extend(word(offset as u128));
        offset += 96 + pad32(d.len());
    }
    for (op, d) in ops.iter().zip(&datas) {
        out.extend(word(op.tag().into()));
        out.extend(word(0x40));
        out.extend(word(d.len() as u128));
        out.extend(d);
        out.resize(out.len() + pad32(d.len()) - d.len(), 0);
    }
    Ok(out)
}

/// How many leading ops of `ops` fit under `max_calldata` bytes of calldata (at least 1).
/// Sizes each op with [`Op::calldata_len`] (which encodes it once). Bounds calldata only, not gas. Errors with
/// [`Error::OpTooLarge`] when the first op alone is over the cap.
pub fn fit(ops: &[Op], max_calldata: usize) -> Result<usize> {
    if ops.is_empty() {
        return Err(Error::EmptyBatch);
    }
    let mut total = CALLDATA_OVERHEAD;
    for (i, op) in ops.iter().enumerate() {
        let len = op.calldata_len()?;
        if total + len > max_calldata {
            if i == 0 {
                return Err(Error::OpTooLarge {
                    index: 0,
                    size: CALLDATA_OVERHEAD + len,
                    cap: max_calldata,
                });
            }
            return Ok(i);
        }
        total += len;
    }
    Ok(ops.len())
}

/// Splits `ops` into consecutive batches that each fit under `max_calldata`, order preserved.
///
/// ```
/// use arkiv::ops::{execute_calldata, split};
/// use arkiv::{Attribute, Create, Expiry, Op};
///
/// let ops: Vec<Op> = (0..10)
///     .map(|n| {
///         let attrs = vec![Attribute::schema("demo.items").unwrap(), Attribute::u64("n", n).unwrap()];
///         Op::Create(Create::new(attrs, Expiry::blocks(600).unwrap()).unwrap())
///     })
///     .collect();
/// let batches = split(ops, 2_000).unwrap();
/// assert!(batches.len() > 1);
/// for batch in &batches {
///     assert!(execute_calldata(batch).unwrap().len() <= 2_000);
/// }
/// ```
pub fn split(ops: Vec<Op>, max_calldata: usize) -> Result<Vec<Vec<Op>>> {
    let mut batches = Vec::new();
    let mut batch: Vec<Op> = Vec::new();
    let mut total = CALLDATA_OVERHEAD;
    for (index, op) in ops.into_iter().enumerate() {
        let len = op.calldata_len()?;
        if CALLDATA_OVERHEAD + len > max_calldata {
            return Err(Error::OpTooLarge {
                index,
                size: CALLDATA_OVERHEAD + len,
                cap: max_calldata,
            });
        }
        if total + len > max_calldata {
            batches.push(std::mem::take(&mut batch));
            total = CALLDATA_OVERHEAD;
        }
        total += len;
        batch.push(op);
    }
    if !batch.is_empty() {
        batches.push(batch);
    }
    Ok(batches)
}

/// The key the engine will mint for a create: `keccak256(chainId ++ registry ++ owner ++ nonce ++ salt)`
/// with `chainId` as uint256, `registry` and `owner` as 20 bytes, `nonce` as uint64, `salt` as uint128.
/// `nonce` is the owner's entity nonce (see `Client::entity_nonce`), plus the create's index in the batch.
pub fn predict_entity_key(chain_id: u64, owner: Address, nonce: u64, salt: u128) -> Key {
    let mut buf = word(chain_id.into()).to_vec();
    buf.extend(ARKIV_ADDRESS.0);
    buf.extend(owner.0);
    buf.extend(nonce.to_be_bytes());
    buf.extend(salt.to_be_bytes());
    B256(keccak256(&buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{hex_decode, hex_encode, RABDI_CHAIN_ID};

    use serde_json::Value as Json;

    fn vectors() -> Json {
        serde_json::from_str(include_str!("../tests/vectors/viem.json")).expect("vectors parse")
    }

    fn vec_hex(name: &str) -> Vec<u8> {
        hex_decode(vectors()[name].as_str().expect("string vector")).expect("hex")
    }

    fn key() -> Key {
        "0x59c5ddf06b5605e27833d0a02c8f6e96cebf9f334a6470b39e31eccb34895807"
            .parse()
            .expect("key")
    }

    fn owner() -> Address {
        "0x0f05df479fcb23b2281e28813fb47e57e47d1bb7"
            .parse()
            .expect("address")
    }

    fn demo_create(salt: u128, blocks: u64) -> Create {
        let attrs = vec![Attribute::schema("demo.items").expect("schema")];
        Create::new(attrs, Expiry::blocks(blocks).expect("expiry"))
            .expect("create")
            .with_salt(salt)
    }

    fn delete() -> Op {
        Op::Delete { key: key() }
    }

    /// Hand-built ABI word from a hex literal of any length up to 64 digits.
    fn w(hex: &str) -> String {
        format!("{hex:0>64}")
    }

    fn text_create(len: usize) -> Op {
        let attrs = vec![
            Attribute::schema("t").expect("s"),
            Attribute::str("v", &"x".repeat(len)).expect("v"),
        ];
        Op::Create(
            Create::new(attrs, Expiry::blocks(100).expect("e"))
                .expect("c")
                .with_salt(1),
        )
    }

    /// The vector's attribute list, in the order viem encoded it, as wire entries.
    fn vector_entries() -> Vec<Entry> {
        vectors()["attributes"]
            .as_array()
            .expect("array")
            .iter()
            .map(|a| {
                let name = hex_decode(a["name"].as_str().expect("name")).expect("hex");
                Entry {
                    name: name.try_into().expect("32 bytes"),
                    type_byte: a["typeId"].as_u64().expect("type") as u8,
                    value: hex_decode(a["value"].as_str().expect("value")).expect("hex"),
                }
            })
            .collect()
    }

    /// Splits a golden `execute` call into `(tag, operationData)` pairs.
    fn decode_execute(call: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let b = &call[4..];
        let at = |p: usize| usize::from_be_bytes(b[p + 24..p + 32].try_into().expect("8 bytes"));
        let n = at(32);
        (0..n)
            .map(|i| {
                let start = 64 + at(64 + i * 32);
                let len = at(start + 64);
                (b[start + 31], b[start + 96..start + 96 + len].to_vec())
            })
            .collect()
    }

    // ---- Expiry ----

    #[test]
    fn expiry_blocks_accepts_range() {
        assert_eq!(
            Expiry::blocks(1).expect("ok"),
            Expiry {
                expires_at: 0,
                min_lifetime: 1
            }
        );
        assert_eq!(
            Expiry::blocks(MAX_LIFETIME_BLOCKS)
                .expect("ok")
                .min_lifetime,
            7_884_000
        );
    }

    #[test]
    fn expiry_blocks_rejects_zero_and_over_max() {
        assert!(matches!(Expiry::blocks(0), Err(Error::InvalidExpiry(_))));
        assert!(matches!(
            Expiry::blocks(MAX_LIFETIME_BLOCKS + 1),
            Err(Error::InvalidExpiry(_))
        ));
        assert!(matches!(
            Expiry::blocks(u64::MAX),
            Err(Error::InvalidExpiry(_))
        ));
    }

    #[test]
    fn expiry_seconds_uses_two_second_blocks() {
        assert_eq!(Expiry::seconds(2).expect("ok").min_lifetime, 1);
        assert_eq!(Expiry::seconds(3600).expect("ok").min_lifetime, 1800);
        assert_eq!(
            Expiry::seconds(2 * MAX_LIFETIME_BLOCKS)
                .expect("ok")
                .min_lifetime,
            MAX_LIFETIME_BLOCKS
        );
    }

    #[test]
    fn expiry_seconds_rejects_odd_zero_and_over_max() {
        assert!(Expiry::seconds(1).is_err());
        assert!(Expiry::seconds(3).is_err());
        assert!(Expiry::seconds(0).is_err());
        assert!(Expiry::seconds(2 * MAX_LIFETIME_BLOCKS + 2).is_err());
    }

    #[test]
    fn expiry_from_duration_rounds_up_and_caps() {
        assert_eq!(
            Expiry::from_duration(Duration::from_secs(4))
                .expect("ok")
                .min_lifetime,
            2
        );
        assert_eq!(
            Expiry::from_duration(Duration::from_secs(5))
                .expect("ok")
                .min_lifetime,
            3
        );
        assert_eq!(
            Expiry::from_duration(Duration::from_millis(1))
                .expect("ok")
                .min_lifetime,
            1
        );
        assert_eq!(
            Expiry::from_duration(Duration::from_secs(86_400))
                .expect("ok")
                .min_lifetime,
            43_200
        );
        let ten_years = Duration::from_secs(10 * 365 * 86_400);
        assert_eq!(
            Expiry::from_duration(ten_years).expect("capped"),
            Expiry::max()
        );
        assert!(Expiry::from_duration(Duration::ZERO).is_err());
    }

    #[test]
    fn expiry_at_block_and_max() {
        assert_eq!(
            Expiry::at_block(500).expect("ok"),
            Expiry {
                expires_at: 500,
                min_lifetime: 0
            }
        );
        assert!(Expiry::at_block(0).is_err());
        assert_eq!(Expiry::max().min_lifetime, 7_884_000);
        assert!(Expiry::max().validate().is_ok());
    }

    #[test]
    fn expiry_validate_catches_hand_built_pairs() {
        assert!(Expiry {
            expires_at: 0,
            min_lifetime: 0
        }
        .validate()
        .is_err());
        assert!(Expiry {
            expires_at: 9,
            min_lifetime: MAX_LIFETIME_BLOCKS + 1
        }
        .validate()
        .is_err());
        assert!(Expiry {
            expires_at: u64::MAX,
            min_lifetime: 5
        }
        .validate()
        .is_ok());
    }

    // ---- flags ----

    #[test]
    fn flags_pack_and_unpack() {
        let f = |readonly, permissionless_extension| CreationFlags {
            readonly,
            permissionless_extension,
        };
        assert_eq!(f(false, false).to_byte(), 0);
        assert_eq!(f(true, false).to_byte(), 1);
        assert_eq!(f(false, true).to_byte(), 2);
        assert_eq!(f(true, true).to_byte(), 3);
        for b in 0..=3u8 {
            assert_eq!(CreationFlags::from_byte(b).to_byte(), b);
        }
        assert_eq!(CreationFlags::from_byte(0xfc), CreationFlags::default());
        assert_eq!(CreationFlags::from_byte(0xff).to_byte(), 3);
    }

    // ---- Create ----

    #[test]
    fn create_new_is_writable_with_random_salt() {
        let attrs = || vec![Attribute::schema("demo.items").expect("schema")];
        let a = Create::new(attrs(), Expiry::max()).expect("a");
        let b = Create::new(attrs(), Expiry::max()).expect("b");
        assert!(!a.flags.readonly && !a.flags.permissionless_extension);
        assert_ne!(a.salt, b.salt);
    }

    #[test]
    fn create_new_rejects_bad_expiry_and_duplicates() {
        let attrs = vec![Attribute::schema("a").expect("a")];
        let zero = Expiry {
            expires_at: 0,
            min_lifetime: 0,
        };
        assert!(matches!(
            Create::new(attrs, zero),
            Err(Error::InvalidExpiry(_))
        ));
        let dup = vec![
            Attribute::str("a", "1").expect("a"),
            Attribute::str("a", "2").expect("a"),
        ];
        assert!(matches!(
            Create::new(dup, Expiry::max()),
            Err(Error::DuplicateAttribute(_))
        ));
    }

    #[test]
    fn create_readonly_and_with_salt_builders() {
        let c = demo_create(1, 10).readonly().with_salt(77);
        assert!(c.flags.readonly);
        assert_eq!(c.salt, 77);
        assert_eq!(Op::Create(c).tag(), OP_CREATE);
    }

    #[test]
    fn create_sorts_attributes_by_name_word() {
        let attrs = vec![
            Attribute::str("zeta", "1").expect("z"),
            Attribute::schema("s").expect("s"),
            Attribute::str("alpha", "2").expect("a"),
        ];
        let c = Create::new(attrs, Expiry::max()).expect("c");
        let names: Vec<_> = c.attributes.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, ["alpha", "arkiv.schema", "zeta"]);
        let reversed = {
            let mut r = c.clone();
            r.attributes.reverse();
            r
        };
        assert_eq!(
            Op::Create(c).data().expect("a"),
            Op::Create(reversed).data().expect("b")
        );
    }

    // ---- golden vectors ----

    #[test]
    fn golden_selector_matches() {
        assert_eq!(
            hex_encode(&EXECUTE_SELECTOR),
            vectors()["selector"].as_str().expect("s")
        );
    }

    #[test]
    fn golden_create_op_data_via_encoder() {
        let mut data = word(0x20).to_vec();
        for v in [
            0x0102030405060708090a0b0c0d0e0f10u128,
            0,
            7_800_000,
            1,
            0xa0,
        ] {
            data.extend(word(v));
        }
        data.extend(array(&vector_entries()));
        assert_eq!(data, vec_hex("createOpData"));
    }

    #[test]
    fn golden_create_op_data_sorted_matches_public_path() {
        // viem encodes in the given order; ours sorts, so compare against the sorted re-encoding.
        let mut entries = vector_entries();
        entries.sort_by_key(|e| e.name);
        let attrs: Vec<Attribute> = entries
            .iter()
            .map(|e| {
                let name = word_name(&e.name);
                let indexed = e.type_byte & 0x80 != 0;
                let a = match e.type_byte & 0x7f {
                    8 => Attribute::str(&name, std::str::from_utf8(&e.value).expect("utf8")),
                    3 => Attribute::u64(
                        &name,
                        u64::from_be_bytes(e.value[24..].try_into().expect("8")),
                    ),
                    1 => Attribute::bool(&name, e.value[31] == 1),
                    9 => Attribute::addr(&name, Address(e.value[12..].try_into().expect("20"))),
                    5 => Attribute::dec(
                        &name,
                        crate::attributes::Decimal(i128::from_be_bytes(
                            e.value[16..].try_into().expect("16"),
                        )),
                    ),
                    2 => Attribute::i32(
                        &name,
                        i32::from_be_bytes(e.value[28..].try_into().expect("4")),
                    ),
                    10 => Attribute::key(&name, B256(e.value.clone().try_into().expect("32"))),
                    7 => Attribute::bytes(&name, e.value.clone()),
                    t => panic!("type {t}"),
                }
                .expect("attr");
                if indexed {
                    a.indexed().expect("indexed")
                } else {
                    a
                }
            })
            .collect();
        let create = Create::new(attrs, Expiry::blocks(7_800_000).expect("e"))
            .expect("c")
            .readonly()
            .with_salt(0x0102030405060708090a0b0c0d0e0f10);
        let mut expected = word(0x20).to_vec();
        for v in [
            0x0102030405060708090a0b0c0d0e0f10u128,
            0,
            7_800_000,
            1,
            0xa0,
        ] {
            expected.extend(word(v));
        }
        expected.extend(array(&entries));
        assert_eq!(Op::Create(create).data().expect("data"), expected);
    }

    #[test]
    fn golden_execute_create() {
        let golden = vec_hex("executeCreate");
        let ops = decode_execute(&golden);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].0, OP_CREATE);
        assert_eq!(ops[0].1, vec_hex("createOpData"));
        let length = 4 + 64 + 128 + pad32(ops[0].1.len());
        assert_eq!(golden.len(), length);
    }

    #[test]
    fn golden_two_creates_exact() {
        let golden = vec_hex("executeTwoCreates");
        let parts = decode_execute(&golden);
        assert_eq!(parts[0].1, vec_hex("createOpData"));
        // Second op: schema only, salt 2, 100 blocks, writable.
        let second = Op::Create(demo_create(2, 100));
        assert_eq!(second.data().expect("data"), parts[1].1);
        assert_eq!(second.tag(), parts[1].0);
        assert_eq!(
            golden.len(),
            4 + 64 + 128 * 2 + pad32(parts[0].1.len()) + pad32(parts[1].1.len())
        );
    }

    #[test]
    fn golden_empty_encodes_but_is_refused() {
        assert_eq!(vec_hex("executeEmpty").len(), 4 + 64);
        assert!(matches!(execute_calldata(&[]), Err(Error::EmptyBatch)));
    }

    #[test]
    fn golden_patch() {
        let patch = Patch {
            key: key(),
            set: vec![Attribute::u64("count", 42)
                .expect("c")
                .indexed()
                .expect("i")],
            unset: vec!["flag".into()],
        };
        assert_eq!(
            Op::Patch(patch).data().expect("data"),
            vec_hex("patchOpData")
        );
    }

    #[test]
    fn golden_extend_transfer_delete() {
        let extend = Op::ExtendExpiry {
            key: key(),
            expiry: Expiry {
                expires_at: 0,
                min_lifetime: 1000,
            },
        };
        assert_eq!(extend.data().expect("d"), vec_hex("extendOpData"));
        assert_eq!(extend.tag(), 3);
        let transfer = Op::TransferOwnership {
            key: key(),
            new_owner: owner(),
        };
        assert_eq!(transfer.data().expect("d"), vec_hex("transferOpData"));
        assert_eq!(transfer.tag(), 4);
        assert_eq!(delete().data().expect("d"), vec_hex("deleteOpData"));
        assert_eq!(delete().tag(), 5);
    }

    #[test]
    fn golden_mixed_execute_exact_bytes() {
        let golden = vec_hex("executeMixed");
        let parts = decode_execute(&golden);
        let tags: Vec<u8> = parts.iter().map(|p| p.0).collect();
        assert_eq!(tags, [OP_CREATE, OP_DELETE, OP_EXTEND_EXPIRY]);
        let salt = u128::from_be_bytes(parts[0].1[32..64][16..].try_into().expect("16"));
        let ops = vec![
            Op::Create(demo_create(salt, 100)),
            delete(),
            Op::ExtendExpiry {
                key: key(),
                expiry: Expiry {
                    expires_at: 0,
                    min_lifetime: 1000,
                },
            },
        ];
        assert_eq!(execute_calldata(&ops).expect("calldata"), golden);
    }

    #[test]
    fn golden_predict_key() {
        let v = &vectors()["predictKey"];
        let salt =
            u128::from_str_radix(v["salt"].as_str().expect("s").trim_start_matches("0x"), 16)
                .expect("salt");
        let got = predict_entity_key(
            v["chainId"].as_u64().expect("c"),
            v["owner"].as_str().expect("o").parse().expect("a"),
            v["nonce"].as_u64().expect("n"),
            salt,
        );
        assert_eq!(got.to_string(), v["key"].as_str().expect("k"));
    }

    #[test]
    fn predict_key_changes_with_every_input() {
        let base = predict_entity_key(RABDI_CHAIN_ID, owner(), 1, 1);
        assert_ne!(base, predict_entity_key(RABDI_CHAIN_ID + 1, owner(), 1, 1));
        assert_ne!(
            base,
            predict_entity_key(RABDI_CHAIN_ID, Address([1; 20]), 1, 1)
        );
        assert_ne!(base, predict_entity_key(RABDI_CHAIN_ID, owner(), 2, 1));
        assert_ne!(base, predict_entity_key(RABDI_CHAIN_ID, owner(), 1, 2));
        assert_eq!(base, predict_entity_key(RABDI_CHAIN_ID, owner(), 1, 1));
    }

    // ---- hand-written exact bytes ----

    #[test]
    fn delete_calldata_exact_bytes() {
        let k = "59c5ddf06b5605e27833d0a02c8f6e96cebf9f334a6470b39e31eccb34895807";
        let expected = format!(
            "0x49650044{}{}{}{}{}{}{}",
            w("20"), // offset of the array
            w("1"),  // one op
            w("20"), // offset of op 0
            w("5"),  // tag
            w("40"), // offset of the bytes
            w("20"), // 32 data bytes
            k
        );
        assert_eq!(
            hex_encode(&execute_calldata(&[delete()]).expect("c")),
            expected
        );
    }

    #[test]
    fn transfer_and_extend_data_exact_bytes() {
        let k = "59c5ddf06b5605e27833d0a02c8f6e96cebf9f334a6470b39e31eccb34895807";
        let t = Op::TransferOwnership {
            key: key(),
            new_owner: owner(),
        };
        assert_eq!(
            hex_encode(&t.data().expect("t")),
            format!("0x{k}{}", w("0f05df479fcb23b2281e28813fb47e57e47d1bb7"))
        );
        let e = Op::ExtendExpiry {
            key: key(),
            expiry: Expiry {
                expires_at: 99,
                min_lifetime: 0,
            },
        };
        assert_eq!(
            hex_encode(&e.data().expect("e")),
            format!("0x{k}{}{}", w("63"), w("0"))
        );
    }

    #[test]
    fn minimal_create_data_exact_bytes() {
        let op = Op::Create(demo_create(7, 100).readonly());
        let name = format!("{:0<64}", "61726b69762e736368656d61");
        let value = format!("{:0<64}", "64656d6f2e6974656d73");
        let expected = format!(
            "0x{}{}{}{}{}{}{}{}{}{}{}{}{}{}",
            w("20"),
            w("7"),
            w("0"),
            w("64"),
            w("1"),
            w("a0"), // head
            w("1"),
            w("20"), // array count, offset
            name,
            w("88"),
            w("60"),
            w("a"),
            value, // the attribute
            ""
        );
        assert_eq!(hex_encode(&op.data().expect("d")), expected);
    }

    #[test]
    fn permissionless_extension_flag_reaches_the_wire() {
        let mut c = demo_create(1, 10);
        c.flags = CreationFlags {
            readonly: true,
            permissionless_extension: true,
        };
        let data = Op::Create(c).data().expect("d");
        assert_eq!(data[4 * 32 + 31], 3);
    }

    #[test]
    fn expires_at_and_min_lifetime_land_in_their_words() {
        let c = Create::new(
            vec![Attribute::schema("a").expect("s")],
            Expiry {
                expires_at: 123_456,
                min_lifetime: 789,
            },
        )
        .expect("c");
        let data = Op::Create(c).data().expect("d");
        assert_eq!(&data[2 * 32 + 24..3 * 32], &123_456u64.to_be_bytes());
        assert_eq!(&data[3 * 32 + 24..4 * 32], &789u64.to_be_bytes());
    }

    // ---- patch ----

    #[test]
    fn patch_merges_set_and_unset_in_name_order() {
        let p = Patch {
            key: key(),
            set: vec![Attribute::str("zzz", "v").expect("z")],
            unset: vec!["aaa".into(), "mmm".into()],
        };
        let data = Op::Patch(p).data().expect("d");
        // First tuple starts after the struct offset, key, offset word, count word and three offset words.
        let first = 32 + 3 * 32 + 3 * 32;
        assert_eq!(&data[first..first + 3], b"aaa");
        assert_eq!(data[first + 63], TOMBSTONE_TYPE_BYTE);
        let second = first + 128;
        assert_eq!(&data[second..second + 3], b"mmm");
        let third = second + 128;
        assert_eq!(&data[third..third + 3], b"zzz");
        assert_eq!(data[third + 63], 8);
    }

    #[test]
    fn patch_rejects_duplicates_and_bad_names() {
        let both = Patch {
            key: key(),
            set: vec![Attribute::str("a", "1").expect("a")],
            unset: vec!["a".into()],
        };
        assert!(matches!(Op::Patch(both).data(), Err(Error::DuplicateAttribute(n)) if n == "a"));
        let twice = Patch {
            key: key(),
            set: vec![],
            unset: vec!["a".into(), "a".into()],
        };
        assert!(matches!(
            Op::Patch(twice).data(),
            Err(Error::DuplicateAttribute(_))
        ));
        for bad in ["", "1a", "a b", "and", "$key", &"x".repeat(33)] {
            let p = Patch {
                key: key(),
                set: vec![],
                unset: vec![bad.into()],
            };
            assert!(Op::Patch(p).data().is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn patch_from_impl_and_tag() {
        let p = Patch {
            key: key(),
            set: vec![],
            unset: vec!["a".into()],
        };
        let op: Op = p.into();
        assert_eq!(op.tag(), OP_PATCH);
        let c: Op = demo_create(1, 1).into();
        assert_eq!(c.tag(), OP_CREATE);
    }

    // ---- validation in encode ----

    #[test]
    fn extend_rejects_zero_and_oversized_expiry() {
        let bad = |e| {
            Op::ExtendExpiry {
                key: key(),
                expiry: e,
            }
            .data()
        };
        assert!(bad(Expiry {
            expires_at: 0,
            min_lifetime: 0
        })
        .is_err());
        assert!(bad(Expiry {
            expires_at: 0,
            min_lifetime: MAX_LIFETIME_BLOCKS + 1
        })
        .is_err());
        assert!(execute_calldata(&[Op::ExtendExpiry {
            key: key(),
            expiry: Expiry {
                expires_at: 0,
                min_lifetime: 0
            }
        }])
        .is_err());
    }

    #[test]
    fn create_with_hand_set_bad_expiry_fails_at_encode() {
        let mut c = demo_create(1, 10);
        c.expiry = Expiry {
            expires_at: 0,
            min_lifetime: 0,
        };
        assert!(matches!(Op::Create(c).data(), Err(Error::InvalidExpiry(_))));
    }

    // ---- calldata_len ----

    #[test]
    fn calldata_len_matches_encoding_for_every_value_size() {
        for len in (0..=140).chain([255, 256, 257, 1000]) {
            let op = text_create(len);
            let alone = execute_calldata(std::slice::from_ref(&op)).expect("c");
            assert_eq!(
                alone.len(),
                4 + 64 + op.calldata_len().expect("len"),
                "value len {len}"
            );
            assert_eq!(op.data().expect("d").len() % 32, 0);
        }
    }

    #[test]
    fn calldata_len_matches_for_a_mixed_batch() {
        let ops = vec![
            text_create(5),
            delete(),
            Op::TransferOwnership {
                key: key(),
                new_owner: owner(),
            },
            text_create(70),
            Op::ExtendExpiry {
                key: key(),
                expiry: Expiry::max(),
            },
            Op::Patch(Patch {
                key: key(),
                set: vec![Attribute::str("a", "hello").expect("a")],
                unset: vec!["b".into()],
            }),
        ];
        let sum: usize = ops.iter().map(|o| o.calldata_len().expect("l")).sum();
        assert_eq!(execute_calldata(&ops).expect("c").len(), 68 + sum);
    }

    #[test]
    fn fixed_size_ops_have_fixed_lengths() {
        assert_eq!(delete().calldata_len().expect("l"), 160);
        assert_eq!(
            Op::TransferOwnership {
                key: key(),
                new_owner: owner()
            }
            .calldata_len()
            .expect("l"),
            192
        );
        assert_eq!(
            Op::ExtendExpiry {
                key: key(),
                expiry: Expiry::max()
            }
            .calldata_len()
            .expect("l"),
            224
        );
    }

    // ---- fit ----

    #[test]
    fn fit_counts_exact_boundary() {
        let ops: Vec<Op> = (0..10).map(|_| delete()).collect();
        // Each delete adds 160; overhead is 68.
        assert_eq!(fit(&ops, 68 + 160 * 3).expect("f"), 3);
        assert_eq!(fit(&ops, 68 + 160 * 3 - 1).expect("f"), 2);
        assert_eq!(fit(&ops, 68 + 160 * 3 + 159).expect("f"), 3);
        assert_eq!(fit(&ops, 68 + 160).expect("f"), 1);
        assert_eq!(fit(&ops, usize::MAX).expect("f"), 10);
    }

    #[test]
    fn fit_result_never_exceeds_cap_and_is_maximal() {
        let ops: Vec<Op> = (0..30).map(|i| text_create(i * 13)).collect();
        for cap in (800..6000).step_by(137) {
            let n = fit(&ops, cap).expect("fit");
            assert!(n >= 1);
            assert!(execute_calldata(&ops[..n]).expect("c").len() <= cap);
            if n < ops.len() {
                assert!(execute_calldata(&ops[..=n]).expect("c").len() > cap);
            }
        }
    }

    #[test]
    fn fit_errors() {
        assert!(matches!(fit(&[], 1000), Err(Error::EmptyBatch)));
        assert!(matches!(
            fit(&[delete()], 100),
            Err(Error::OpTooLarge {
                index: 0,
                size: 228,
                cap: 100
            })
        ));
        // Exactly at the cap is fine.
        assert_eq!(fit(&[delete()], 228).expect("f"), 1);
        assert!(fit(&[delete()], 227).is_err());
    }

    // ---- split ----

    #[test]
    fn split_exact_multiples() {
        let ops: Vec<Op> = (0..9).map(|_| delete()).collect();
        let sizes: Vec<usize> = split(ops, 68 + 160 * 3)
            .expect("s")
            .iter()
            .map(Vec::len)
            .collect();
        assert_eq!(sizes, [3, 3, 3]);
    }

    #[test]
    fn split_remainder_and_single_batch() {
        let ops: Vec<Op> = (0..10).map(|_| delete()).collect();
        let sizes: Vec<usize> = split(ops.clone(), 68 + 160 * 3)
            .expect("s")
            .iter()
            .map(Vec::len)
            .collect();
        assert_eq!(sizes, [3, 3, 3, 1]);
        let whole = split(ops, DEFAULT_MAX_CALLDATA).expect("s");
        assert_eq!(whole.len(), 1);
        assert_eq!(whole[0].len(), 10);
    }

    #[test]
    fn split_one_op_per_batch_at_tight_cap() {
        let ops: Vec<Op> = (0..4).map(|_| delete()).collect();
        let batches = split(ops, 228).expect("s");
        assert_eq!(batches.len(), 4);
        assert!(batches.iter().all(|b| b.len() == 1));
    }

    #[test]
    fn split_empty_is_no_batches() {
        assert!(split(vec![], 1000).expect("s").is_empty());
    }

    #[test]
    fn split_reports_the_global_index_of_an_oversized_op() {
        let ops = vec![delete(), delete(), text_create(5000), delete()];
        match split(ops, 1000) {
            Err(Error::OpTooLarge { index, size, cap }) => {
                assert_eq!(index, 2);
                assert_eq!(cap, 1000);
                assert!(size > 5000);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn split_preserves_order_and_respects_cap() {
        let ops: Vec<Op> = (0..40).map(|i| text_create((i * 29) % 300)).collect();
        for cap in [1500usize, 2048, 4000, 9000] {
            let batches = split(ops.clone(), cap).expect("s");
            let flat: Vec<Op> = batches.iter().flatten().cloned().collect();
            assert_eq!(flat, ops, "order at cap {cap}");
            for (i, b) in batches.iter().enumerate() {
                assert!(!b.is_empty());
                assert!(execute_calldata(b).expect("c").len() <= cap, "cap {cap}");
                if let Some(next) = batches.get(i + 1) {
                    let mut grown = b.clone();
                    grown.push(next[0].clone());
                    assert!(
                        execute_calldata(&grown).expect("c").len() > cap,
                        "greedy at cap {cap}"
                    );
                }
            }
        }
    }

    #[test]
    fn split_agrees_with_repeated_fit() {
        let ops: Vec<Op> = (0..25).map(|i| text_create(i * 41)).collect();
        let cap = 3000;
        let mut rest = ops.as_slice();
        let mut via_fit = Vec::new();
        while !rest.is_empty() {
            let n = fit(rest, cap).expect("fit");
            via_fit.push(n);
            rest = &rest[n..];
        }
        let via_split: Vec<usize> = split(ops, cap).expect("s").iter().map(Vec::len).collect();
        assert_eq!(via_fit, via_split);
    }

    #[test]
    fn default_cap_keeps_a_fifty_round_backlog_under_the_413_limit() {
        let ops: Vec<Op> = (0..500).map(|i| text_create(180 + i % 7)).collect();
        let batches = split(ops, DEFAULT_MAX_CALLDATA).expect("s");
        assert!(batches.len() > 1);
        for b in &batches {
            let data = execute_calldata(b).expect("c");
            assert!(data.len() <= DEFAULT_MAX_CALLDATA);
            // Each request body (estimate, then the signed tx) carries the data as hex.
            assert!(data.len() * 2 < 200_000);
        }
    }

    #[test]
    fn execute_calldata_starts_with_selector_and_array_offset() {
        let data = execute_calldata(&[delete(), delete()]).expect("c");
        assert_eq!(&data[..4], &EXECUTE_SELECTOR);
        assert_eq!(&data[4..36], &word(0x20));
        assert_eq!(&data[36..68], &word(2));
        assert_eq!(&data[68..100], &word(64));
        assert_eq!(&data[100..132], &word(64 + 128));
    }

    #[test]
    fn constants_match_the_protocol() {
        assert_eq!(DEFAULT_MAX_CALLDATA, 60_000);
        assert_eq!(
            [
                OP_CREATE,
                OP_PATCH,
                OP_EXTEND_EXPIRY,
                OP_TRANSFER_OWNERSHIP,
                OP_DELETE
            ],
            [1, 2, 3, 4, 5]
        );
    }

    #[test]
    fn empty_patch_is_rejected() {
        let p = Patch {
            key: key(),
            set: vec![],
            unset: vec![],
        };
        assert!(Op::Patch(p).data().is_err());
    }
}
