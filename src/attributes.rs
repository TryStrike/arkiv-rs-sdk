//! Typed attributes and their wire encoding.
//!
//! Names follow the `Ident32` grammar, values encode to the cell the chain stores, and
//! [`normalize`] orders a set of attributes the way the engine requires.

use crate::error::{Error, Result};
use crate::types::{hex_decode, Address, Key};

/// Bit 7 of the type byte: set when the node should index the attribute.
pub const INDEXED_FLAG: u8 = 0x80;
/// Most attributes one entity may carry. The `arkiv.schema` tag counts.
pub const MAX_ATTRIBUTES: usize = 32;
/// Longest attribute name in bytes (the on-chain `bytes32` cell).
pub const MAX_NAME_BYTES: usize = 32;
/// Most bytes all `bytes` values of one create or patch may total.
pub const MAX_ENTITY_BYTES: usize = 128 * 1024;
/// Longest single `bytes` value.
pub const MAX_BYTES_LEN: usize = 128 * 1024;
/// Name of the system attribute that tags an entity with its schema.
pub const SCHEMA_ATTRIBUTE: &str = "arkiv.schema";
/// Decimal places of the `dec` type.
pub const DECIMAL_SCALE: u32 = 18;

/// Attribute value types and their wire ids (low seven bits of the type byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttrType {
    /// Id 1.
    Bool,
    /// Id 2.
    I32,
    /// Id 3.
    U64,
    /// Id 4.
    U256,
    /// Id 5.
    Dec,
    /// Id 7. Stored, never indexed.
    Bytes,
    /// Id 8.
    Str,
    /// Id 9.
    Addr,
    /// Id 10 (the node reports id 6, `bytes32`, as `key`).
    Key,
}

impl AttrType {
    /// The wire id, without the indexed flag.
    pub fn id(self) -> u8 {
        match self {
            AttrType::Bool => 1,
            AttrType::I32 => 2,
            AttrType::U64 => 3,
            AttrType::U256 => 4,
            AttrType::Dec => 5,
            AttrType::Bytes => 7,
            AttrType::Str => 8,
            AttrType::Addr => 9,
            AttrType::Key => 10,
        }
    }
    /// The tag the query language and RPC use: `bool`, `i32`, `u64`, `u256`, `dec`, `bytes`, `str`, `addr`, `key`.
    pub fn tag(self) -> &'static str {
        match self {
            AttrType::Bool => "bool",
            AttrType::I32 => "i32",
            AttrType::U64 => "u64",
            AttrType::U256 => "u256",
            AttrType::Dec => "dec",
            AttrType::Bytes => "bytes",
            AttrType::Str => "str",
            AttrType::Addr => "addr",
            AttrType::Key => "key",
        }
    }
    /// Parses an RPC type tag. `bytes32` maps to [`AttrType::Key`].
    pub fn from_tag(tag: &str) -> Result<AttrType> {
        Ok(match tag {
            "bool" => AttrType::Bool,
            "i32" => AttrType::I32,
            "u64" => AttrType::U64,
            "u256" => AttrType::U256,
            "dec" => AttrType::Dec,
            "bytes" => AttrType::Bytes,
            "str" => AttrType::Str,
            "addr" => AttrType::Addr,
            "key" | "bytes32" => AttrType::Key,
            _ => return Err(bad("type", format!("unknown type tag {tag:?}"))),
        })
    }
    /// Splits a wire type byte into type and indexed flag.
    pub fn from_type_byte(byte: u8) -> Result<(AttrType, bool)> {
        let ty = match byte & !INDEXED_FLAG {
            1 => AttrType::Bool,
            2 => AttrType::I32,
            3 => AttrType::U64,
            4 => AttrType::U256,
            5 => AttrType::Dec,
            6 | 10 => AttrType::Key,
            7 => AttrType::Bytes,
            8 => AttrType::Str,
            9 => AttrType::Addr,
            _ => return Err(bad("type", format!("unknown type byte {byte:#04x}"))),
        };
        Ok((ty, byte & INDEXED_FLAG != 0))
    }
    /// False only for [`AttrType::Bytes`].
    pub fn is_indexable(self) -> bool {
        self != AttrType::Bytes
    }
}

fn bad(kind: &'static str, reason: impl Into<String>) -> Error {
    Error::InvalidValue {
        kind,
        reason: reason.into(),
    }
}

fn pow10(n: u32) -> i128 {
    10i128.pow(n)
}

/// A fixed-point number with 18 decimal places, held as `value * 10^18` in an `i128`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Decimal(pub i128);

impl Decimal {
    /// Parses `[+-]digits[.digits]` with at most 18 fraction digits. No exponents.
    pub fn parse(s: &str) -> Result<Decimal> {
        let err = |r: &str| bad("dec", format!("{r}: {s:?}"));
        let (neg, rest) = match s.as_bytes().first() {
            Some(b'-') => (true, &s[1..]),
            Some(b'+') => (false, &s[1..]),
            _ => (false, s),
        };
        let (int, frac) = match rest.split_once('.') {
            Some((i, f)) => (i, Some(f)),
            None => (rest, None),
        };
        let digits = |t: &str| !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit());
        if !digits(int) {
            return Err(err("expected digits before the point"));
        }
        let frac = frac.unwrap_or("");
        if !frac.is_empty() && !digits(frac) {
            return Err(err("bad fraction"));
        }
        if rest.contains('.') && frac.is_empty() {
            return Err(err("empty fraction"));
        }
        if frac.len() > DECIMAL_SCALE as usize {
            return Err(err("more than 18 fraction digits"));
        }
        let mut acc: i128 = 0;
        for b in int.bytes().chain(frac.bytes()) {
            acc = acc
                .checked_mul(10)
                .and_then(|a| a.checked_add((b - b'0') as i128))
                .ok_or_else(|| err("out of range"))?;
        }
        let missing = DECIMAL_SCALE - frac.len() as u32;
        acc = acc
            .checked_mul(pow10(missing))
            .ok_or_else(|| err("out of range"))?;
        Ok(Decimal(if neg { -acc } else { acc }))
    }
    /// A fixed-point integer at `scale` decimals, as Strike stores money: `from_scaled(150, 2)` is 1.50.
    pub fn from_scaled(value: i64, scale: u32) -> Result<Decimal> {
        if scale > DECIMAL_SCALE {
            return Err(bad("dec", format!("scale {scale} is over {DECIMAL_SCALE}")));
        }
        // i64 * 10^18 always fits in i128.
        Ok(Decimal(value as i128 * pow10(DECIMAL_SCALE - scale)))
    }
    /// The scaled integer units (`value * 10^18`).
    pub fn units(self) -> i128 {
        self.0
    }
}

impl std::fmt::Display for Decimal {
    /// Canonical form: no trailing zeros, no trailing dot, `-` for negatives, `0` for zero.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let abs = self.0.unsigned_abs();
        let one = pow10(DECIMAL_SCALE) as u128;
        let (int, frac) = (abs / one, abs % one);
        let sign = if self.0 < 0 { "-" } else { "" };
        if frac == 0 {
            return write!(f, "{sign}{int}");
        }
        let frac = format!("{frac:018}");
        write!(f, "{sign}{int}.{}", frac.trim_end_matches('0'))
    }
}

/// A typed attribute value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// Boolean.
    Bool(bool),
    /// Signed 32-bit integer.
    I32(i32),
    /// Unsigned 64-bit integer.
    U64(u64),
    /// Unsigned 256-bit integer, big-endian.
    U256([u8; 32]),
    /// Fixed-point decimal.
    Dec(Decimal),
    /// Opaque bytes, up to [`MAX_BYTES_LEN`].
    Bytes(Vec<u8>),
    /// UTF-8 string.
    Str(String),
    /// Address.
    Addr(Address),
    /// Entity key (32 bytes).
    Key(Key),
}

fn word_from_u128(v: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}

fn word_from_i128(v: i128) -> [u8; 32] {
    let mut w = [if v < 0 { 0xff } else { 0 }; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}

/// Decimal digits to a big-endian 256-bit integer, rejecting overflow.
fn u256_from_decimal(s: &str) -> Result<[u8; 32]> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad("u256", format!("not a number: {s:?}")));
    }
    let mut out = [0u8; 32];
    for d in s.bytes() {
        let mut carry = (d - b'0') as u32;
        for byte in out.iter_mut().rev() {
            let v = *byte as u32 * 10 + carry;
            *byte = (v & 0xff) as u8;
            carry = v >> 8;
        }
        if carry != 0 {
            return Err(bad("u256", "out of range"));
        }
    }
    Ok(out)
}

fn u256_from_hex(s: &str) -> Result<[u8; 32]> {
    let digits = s.strip_prefix("0x").unwrap_or(s);
    if digits.is_empty() {
        return Err(bad("u256", "empty quantity"));
    }
    let padded = if digits.len() % 2 == 1 {
        format!("0{digits}")
    } else {
        digits.to_string()
    };
    let bytes = hex_decode(&padded).map_err(|_| bad("u256", format!("bad hex {s:?}")))?;
    if bytes.len() > 32 {
        return Err(bad("u256", "out of range"));
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(out)
}

fn parse_u64(s: &str) -> Result<u64> {
    let r = match s.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16),
        None => s.parse::<u64>(),
    };
    r.map_err(|_| bad("u64", format!("not a u64: {s:?}")))
}

impl Value {
    /// The type of this value.
    pub fn attr_type(&self) -> AttrType {
        match self {
            Value::Bool(_) => AttrType::Bool,
            Value::I32(_) => AttrType::I32,
            Value::U64(_) => AttrType::U64,
            Value::U256(_) => AttrType::U256,
            Value::Dec(_) => AttrType::Dec,
            Value::Bytes(_) => AttrType::Bytes,
            Value::Str(_) => AttrType::Str,
            Value::Addr(_) => AttrType::Addr,
            Value::Key(_) => AttrType::Key,
        }
    }
    /// The bytes that go in the attribute's `value` cell: a 32-byte word for scalars
    /// (two's complement for `i32` and `dec`), raw UTF-8 for `str`, raw bytes for `bytes`.
    pub fn encode(&self) -> Result<Vec<u8>> {
        Ok(match self {
            Value::Bool(b) => word_from_u128(*b as u128).to_vec(),
            Value::I32(v) => word_from_i128(*v as i128).to_vec(),
            Value::U64(v) => word_from_u128(*v as u128).to_vec(),
            Value::U256(w) => w.to_vec(),
            Value::Dec(d) => word_from_i128(d.0).to_vec(),
            Value::Bytes(b) => {
                if b.len() > MAX_BYTES_LEN {
                    return Err(bad(
                        "bytes",
                        format!("{} bytes, the maximum is {MAX_BYTES_LEN}", b.len()),
                    ));
                }
                b.clone()
            }
            Value::Str(s) => {
                if s.contains('\0') {
                    return Err(bad("str", "contains a NUL byte"));
                }
                s.as_bytes().to_vec()
            }
            Value::Addr(a) => a.to_word().to_vec(),
            Value::Key(k) => k.0.to_vec(),
        })
    }
    /// Decodes a JSON-RPC attribute value by its declared type tag: `u64` and `u256` arrive as
    /// `0x` quantities (decimal strings also accepted), `dec` as a decimal string, `i32` as a number,
    /// `bool` as a boolean, `str`/`addr`/`key`/`bytes` as strings (`bytes` as `0x` hex).
    pub fn from_rpc(tag: &str, value: &serde_json::Value) -> Result<Value> {
        use serde_json::Value as J;
        let ty = AttrType::from_tag(tag)?;
        let kind = ty.tag();
        let text = || match value {
            J::String(s) => Ok(s.as_str()),
            other => Err(bad(kind, format!("expected a string, got {other}"))),
        };
        Ok(match ty {
            AttrType::Bool => match value {
                J::Bool(b) => Value::Bool(*b),
                other => return Err(bad(kind, format!("expected a boolean, got {other}"))),
            },
            AttrType::I32 => {
                let n = match value {
                    J::Number(n) => n.as_i64(),
                    J::String(s) => s.parse::<i64>().ok(),
                    _ => None,
                };
                let n = n.and_then(|n| i32::try_from(n).ok());
                Value::I32(n.ok_or_else(|| bad(kind, format!("not an i32: {value}")))?)
            }
            AttrType::U64 => match value {
                J::Number(n) => Value::U64(
                    n.as_u64()
                        .ok_or_else(|| bad(kind, format!("not a u64: {value}")))?,
                ),
                _ => Value::U64(parse_u64(text()?)?),
            },
            AttrType::U256 => match value {
                J::Number(n) => Value::U256(u256_from_decimal(&n.to_string())?),
                _ => {
                    let s = text()?;
                    Value::U256(if s.starts_with("0x") {
                        u256_from_hex(s)?
                    } else {
                        u256_from_decimal(s)?
                    })
                }
            },
            AttrType::Dec => match value {
                J::Number(n) => Value::Dec(Decimal::parse(&n.to_string())?),
                _ => Value::Dec(Decimal::parse(text()?)?),
            },
            AttrType::Bytes => {
                let b = hex_decode(text()?).map_err(|_| bad(kind, "bad hex"))?;
                if b.len() > MAX_BYTES_LEN {
                    return Err(bad(kind, "too long"));
                }
                Value::Bytes(b)
            }
            AttrType::Str => Value::Str(text()?.to_string()),
            AttrType::Addr => Value::Addr(text()?.parse().map_err(|_| bad(kind, "bad address"))?),
            AttrType::Key => Value::Key(text()?.parse().map_err(|_| bad(kind, "bad key"))?),
        })
    }
}

/// One named attribute of an entity, ready to write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    /// The attribute name, validated by [`validate_name`].
    pub name: String,
    /// The typed value.
    pub value: Value,
    /// Whether the node should index it. Always false for `bytes`.
    pub indexed: bool,
}

impl Attribute {
    /// Builds an attribute, validating the name and rejecting an indexed `bytes` value.
    pub fn new(name: &str, value: Value, indexed: bool) -> Result<Attribute> {
        validate_name(name)?;
        if indexed && !value.attr_type().is_indexable() {
            return Err(bad("bytes", "bytes values cannot be indexed"));
        }
        value.encode()?;
        Ok(Attribute {
            name: name.to_string(),
            value,
            indexed,
        })
    }
    /// Unindexed string.
    ///
    /// ```
    /// use arkiv::Attribute;
    ///
    /// let a = Attribute::str("note", "hi").unwrap();
    /// assert!(!a.indexed);
    /// let a = a.indexed().unwrap();
    /// assert_eq!(a.type_byte(), 0x88); // str (8) with the indexed bit
    /// assert!(Attribute::str("bad name", "x").is_err());
    /// ```
    pub fn str(name: &str, value: &str) -> Result<Attribute> {
        Self::new(name, Value::Str(value.to_string()), false)
    }
    /// Unindexed `u64`.
    pub fn u64(name: &str, value: u64) -> Result<Attribute> {
        Self::new(name, Value::U64(value), false)
    }
    /// Unindexed decimal.
    pub fn dec(name: &str, value: Decimal) -> Result<Attribute> {
        Self::new(name, Value::Dec(value), false)
    }
    /// Unindexed address.
    pub fn addr(name: &str, value: Address) -> Result<Attribute> {
        Self::new(name, Value::Addr(value), false)
    }
    /// Unindexed boolean.
    pub fn bool(name: &str, value: bool) -> Result<Attribute> {
        Self::new(name, Value::Bool(value), false)
    }
    /// Unindexed `i32`.
    pub fn i32(name: &str, value: i32) -> Result<Attribute> {
        Self::new(name, Value::I32(value), false)
    }
    /// Unindexed entity key.
    pub fn key(name: &str, value: Key) -> Result<Attribute> {
        Self::new(name, Value::Key(value), false)
    }
    /// Unindexed bytes.
    pub fn bytes(name: &str, value: Vec<u8>) -> Result<Attribute> {
        Self::new(name, Value::Bytes(value), false)
    }
    /// The `arkiv.schema` tag: an indexed string.
    pub fn schema(tag: &str) -> Result<Attribute> {
        Self::new(SCHEMA_ATTRIBUTE, Value::Str(tag.to_string()), true)
    }
    /// Returns the attribute with the indexed flag set. Errors for `bytes`.
    pub fn indexed(self) -> Result<Attribute> {
        Self::new(&self.name, self.value, true)
    }
    /// The type byte: [`AttrType::id`] OR [`INDEXED_FLAG`] when indexed.
    pub fn type_byte(&self) -> u8 {
        self.value.attr_type().id() | if self.indexed { INDEXED_FLAG } else { 0 }
    }
    /// The name as a 32-byte word, UTF-8 left-aligned, zero padded on the right.
    pub fn name_word(&self) -> [u8; 32] {
        let mut w = [0u8; 32];
        let n = self.name.len().min(MAX_NAME_BYTES);
        w[..n].copy_from_slice(&self.name.as_bytes()[..n]);
        w
    }
}

/// A tombstone: unsets an attribute in a patch (type byte 0, empty value).
pub const TOMBSTONE_TYPE_BYTE: u8 = 0;

const RESERVED: &[&str] = &[
    "and",
    "or",
    "not",
    "true",
    "false",
    "between",
    "startswith",
    "exists",
    "typeof",
    "order",
    "by",
    "asc",
    "desc",
    "bool",
    "i32",
    "u64",
    "u256",
    "dec",
    "bytes",
    "str",
    "addr",
    "key",
];

/// Validates a name against the `Ident32` grammar: a letter, then letters, digits, `.`, `-`, `_`;
/// at most 32 bytes; no `--`; not starting with `$`; not a reserved query word
/// (`and or not true false between startswith exists typeof order by asc desc bool i32 u64 u256 dec bytes str addr key`, case-insensitive).
pub fn validate_name(name: &str) -> Result<()> {
    let fail = |reason: &str| {
        Err(Error::InvalidAttributeName {
            name: name.to_string(),
            reason: reason.to_string(),
        })
    };
    if name.is_empty() {
        return fail("empty");
    }
    if name.len() > MAX_NAME_BYTES {
        return fail("longer than 32 bytes");
    }
    if !name.as_bytes()[0].is_ascii_alphabetic() {
        return fail("must start with a letter");
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        return fail("only letters, digits, '.', '-' and '_' are allowed");
    }
    if name.contains("--") {
        return fail("contains \"--\"");
    }
    if RESERVED.iter().any(|r| r.eq_ignore_ascii_case(name)) {
        return fail("reserved query word");
    }
    Ok(())
}

/// Validates and orders attributes for the wire: rejects duplicates, more than [`MAX_ATTRIBUTES`],
/// and more than [`MAX_ENTITY_BYTES`] of `bytes` values, then sorts strictly ascending by the
/// 32-byte name word (the engine requires this order).
pub fn normalize(mut attributes: Vec<Attribute>) -> Result<Vec<Attribute>> {
    if attributes.len() > MAX_ATTRIBUTES {
        return Err(Error::TooManyAttributes {
            got: attributes.len(),
            max: MAX_ATTRIBUTES,
        });
    }
    let total: usize = attributes
        .iter()
        .map(|a| {
            if let Value::Bytes(b) = &a.value {
                b.len()
            } else {
                0
            }
        })
        .sum();
    if total > MAX_ENTITY_BYTES {
        return Err(Error::EntityTooLarge {
            got: total,
            max: MAX_ENTITY_BYTES,
        });
    }
    attributes.sort_by_key(|a| a.name_word());
    if let Some(w) = attributes
        .windows(2)
        .find(|w| w[0].name_word() == w[1].name_word())
    {
        return Err(Error::DuplicateAttribute(w[0].name.clone()));
    }
    Ok(attributes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::B256;
    use serde_json::json;

    fn addr() -> Address {
        "0x0f05df479fcb23b2281e28813fb47e57e47d1bb7"
            .parse()
            .unwrap()
    }
    fn d(s: &str) -> Decimal {
        Decimal::parse(s).unwrap()
    }

    #[test]
    fn type_ids_tags_round_trip() {
        use AttrType::*;
        for t in [Bool, I32, U64, U256, Dec, Bytes, Str, Addr, Key] {
            assert_eq!(AttrType::from_tag(t.tag()).unwrap(), t);
            assert_eq!(AttrType::from_type_byte(t.id()).unwrap(), (t, false));
            assert_eq!(
                AttrType::from_type_byte(t.id() | INDEXED_FLAG).unwrap(),
                (t, true)
            );
        }
        assert_eq!(AttrType::from_tag("bytes32").unwrap(), Key);
        assert_eq!(AttrType::from_type_byte(6).unwrap().0, Key);
        assert!(AttrType::from_tag("float").is_err());
        assert!(AttrType::from_type_byte(0).is_err());
        assert!(AttrType::from_type_byte(0x80).is_err());
        assert!(AttrType::from_type_byte(11).is_err());
        assert!(!Bytes.is_indexable() && Str.is_indexable());
    }

    #[test]
    fn decimal_parse_ok() {
        assert_eq!(d("1.5").0, 1_500_000_000_000_000_000);
        assert_eq!(d("0").0, 0);
        assert_eq!(d("-0").0, 0);
        assert_eq!(d("+2").0, 2 * 10i128.pow(18));
        assert_eq!(d("0.000000000000000001").0, 1);
        assert_eq!(d("-12.34").0, -12_340_000_000_000_000_000);
        assert_eq!(d("007.50").0, 7_500_000_000_000_000_000);
    }

    #[test]
    fn decimal_parse_rejects() {
        for s in [
            "",
            "-",
            "+",
            ".",
            ".5",
            "5.",
            "1e3",
            "1E3",
            "1.2.3",
            "abc",
            "1 ",
            " 1",
            "0x10",
            "1.0000000000000000001",
            "--1",
            "1,5",
        ] {
            assert!(Decimal::parse(s).is_err(), "{s:?}");
        }
        assert!(Decimal::parse(&"9".repeat(40)).is_err());
    }

    #[test]
    fn decimal_display_canonical() {
        assert_eq!(d("1.50").to_string(), "1.5");
        assert_eq!(d("2.000").to_string(), "2");
        assert_eq!(d("-0.5").to_string(), "-0.5");
        assert_eq!(
            d("0.000000000000000001").to_string(),
            "0.000000000000000001"
        );
        assert_eq!(d("0").to_string(), "0");
        assert_eq!(d("0.05").to_string(), "0.05");
        assert_eq!(Decimal(i128::MIN).to_string().chars().next(), Some('-'));
    }

    #[test]
    fn decimal_round_trip() {
        for s in [
            "0",
            "1",
            "-1",
            "123.456",
            "-0.000000000000000001",
            "99999999999999999999",
            "0.1",
        ] {
            assert_eq!(d(s).to_string(), s);
            assert_eq!(d(&d(s).to_string()), d(s));
        }
    }

    #[test]
    fn decimal_scaled() {
        assert_eq!(Decimal::from_scaled(150, 2).unwrap(), d("1.5"));
        assert_eq!(Decimal::from_scaled(-5, 0).unwrap(), d("-5"));
        assert_eq!(Decimal::from_scaled(1, 18).unwrap().units(), 1);
        assert_eq!(
            Decimal::from_scaled(i64::MIN, 0).unwrap().to_string(),
            "-9223372036854775808"
        );
        assert!(Decimal::from_scaled(1, 19).is_err());
    }

    #[test]
    fn decimal_ordering() {
        assert!(d("-1") < d("0") && d("0.1") < d("0.2") && d("10") > d("9.99"));
    }

    #[test]
    fn encode_scalars() {
        let w = |v: &Value| v.encode().unwrap();
        assert_eq!(w(&Value::Bool(true))[31], 1);
        assert_eq!(w(&Value::Bool(false)), vec![0; 32]);
        assert_eq!(w(&Value::U64(42))[24..], 42u64.to_be_bytes());
        assert_eq!(w(&Value::U64(u64::MAX))[..24], [0; 24]);
        assert_eq!(w(&Value::I32(-7)), [vec![0xff; 31], vec![0xf9]].concat());
        assert_eq!(w(&Value::I32(i32::MIN))[..28], [0xff; 28]);
        assert_eq!(w(&Value::I32(i32::MAX))[..28], [0; 28]);
        assert_eq!(w(&Value::Addr(addr()))[..12], [0; 12]);
        assert_eq!(w(&Value::Addr(addr()))[12..], addr().0);
        assert_eq!(w(&Value::Key(B256([7; 32]))), vec![7; 32]);
        assert_eq!(w(&Value::U256([9; 32])), vec![9; 32]);
        assert_eq!(
            w(&Value::Dec(d("1.5")))[24..],
            1_500_000_000_000_000_000u64.to_be_bytes()
        );
        assert_eq!(
            w(&Value::Dec(d("-1"))),
            (-(10i128.pow(18)))
                .to_be_bytes()
                .iter()
                .fold(vec![0xff; 16], |mut v, b| {
                    v.push(*b);
                    v
                })
        );
    }

    #[test]
    fn encode_str_bytes() {
        assert_eq!(
            Value::Str("héllo".into()).encode().unwrap(),
            "héllo".as_bytes()
        );
        assert_eq!(
            Value::Str(String::new()).encode().unwrap(),
            Vec::<u8>::new()
        );
        assert!(Value::Str("a\0b".into()).encode().is_err());
        assert_eq!(Value::Bytes(vec![1, 2]).encode().unwrap(), vec![1, 2]);
        assert!(Value::Bytes(vec![0; MAX_BYTES_LEN]).encode().is_ok());
        assert!(Value::Bytes(vec![0; MAX_BYTES_LEN + 1]).encode().is_err());
    }

    #[test]
    fn from_rpc_each_type() {
        let r = |t: &str, v: serde_json::Value| Value::from_rpc(t, &v).unwrap();
        assert_eq!(r("str", json!("x")), Value::Str("x".into()));
        assert_eq!(r("bool", json!(true)), Value::Bool(true));
        assert_eq!(r("i32", json!(-5)), Value::I32(-5));
        assert_eq!(r("u64", json!("0x7b")), Value::U64(123));
        assert_eq!(r("u64", json!("123")), Value::U64(123));
        assert_eq!(r("u64", json!(123)), Value::U64(123));
        assert_eq!(r("dec", json!("1.5")), Value::Dec(d("1.5")));
        assert_eq!(r("dec", json!(2)), Value::Dec(d("2")));
        assert_eq!(
            r("addr", json!("0x0F05DF479FCB23B2281E28813FB47E57E47D1BB7")),
            Value::Addr(addr())
        );
        assert_eq!(
            r("key", json!(format!("0x{}", "11".repeat(32)))),
            Value::Key(B256([0x11; 32]))
        );
        assert_eq!(
            r("bytes32", json!(format!("0x{}", "11".repeat(32)))),
            Value::Key(B256([0x11; 32]))
        );
        assert_eq!(
            r("bytes", json!("0xdeadbeef")),
            Value::Bytes(vec![0xde, 0xad, 0xbe, 0xef])
        );
        assert_eq!(r("bytes", json!("0x")), Value::Bytes(vec![]));
    }

    #[test]
    fn from_rpc_u256() {
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(
            Value::from_rpc("u256", &json!("0x1")).unwrap(),
            Value::U256(one)
        );
        assert_eq!(
            Value::from_rpc("u256", &json!("1")).unwrap(),
            Value::U256(one)
        );
        let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        assert_eq!(
            Value::from_rpc("u256", &json!(max)).unwrap(),
            Value::U256([0xff; 32])
        );
        let over = "115792089237316195423570985008687907853269984665640564039457584007913129639936";
        assert!(Value::from_rpc("u256", &json!(over)).is_err());
        assert!(Value::from_rpc("u256", &json!(format!("0x1{}", "0".repeat(64)))).is_err());
        assert_eq!(
            Value::from_rpc("u256", &json!(format!("0x{}", "ff".repeat(32)))).unwrap(),
            Value::U256([0xff; 32])
        );
        assert!(Value::from_rpc("u256", &json!("0x")).is_err());
        assert!(Value::from_rpc("u256", &json!("-1")).is_err());
        assert!(Value::from_rpc("u256", &json!("zz")).is_err());
    }

    #[test]
    fn from_rpc_rejects() {
        let bad =
            |t: &str, v: serde_json::Value| assert!(Value::from_rpc(t, &v).is_err(), "{t} {v}");
        bad("nope", json!(1));
        bad("bool", json!("true"));
        bad("bool", json!(1));
        bad("i32", json!(2147483648i64));
        bad("i32", json!(1.5));
        bad("i32", json!(true));
        bad("u64", json!("0xzz"));
        bad("u64", json!("-1"));
        bad("u64", json!("18446744073709551616"));
        bad("u64", json!(null));
        bad("dec", json!("1e3"));
        bad("dec", json!(true));
        bad("str", json!(5));
        bad("addr", json!("0x1234"));
        bad("addr", json!(5));
        bad("key", json!("0x1234"));
        bad("bytes", json!("0xabc"));
        bad("bytes", json!(5));
    }

    #[test]
    fn value_round_trip_via_rpc() {
        assert_eq!(
            Value::from_rpc("u64", &json!(format!("{:#x}", u64::MAX))).unwrap(),
            Value::U64(u64::MAX)
        );
        let v = Value::Dec(d("-3.25"));
        assert_eq!(
            Value::from_rpc("dec", &json!(d("-3.25").to_string())).unwrap(),
            v
        );
    }

    #[test]
    fn name_grammar() {
        for n in [
            "a",
            "arkiv.schema",
            "betId",
            "a-b",
            "a_b",
            "A9.x-y_z",
            &"a".repeat(32),
        ] {
            assert!(validate_name(n).is_ok(), "{n}");
        }
        for n in [
            "",
            "1a",
            "_a",
            "-a",
            ".a",
            "$key",
            "a b",
            "a--b",
            "é",
            "aé",
            "a/b",
            "a'b",
            &"a".repeat(33),
            "a\0",
        ] {
            assert!(validate_name(n).is_err(), "{n:?}");
        }
    }

    #[test]
    fn reserved_names_case_insensitive() {
        for n in RESERVED {
            assert!(validate_name(n).is_err(), "{n}");
            assert!(validate_name(&n.to_uppercase()).is_err(), "{n}");
        }
        assert!(validate_name("Keys").is_ok());
        assert!(validate_name("order_id").is_ok());
        assert!(validate_name("str.x").is_ok());
    }

    #[test]
    fn name_error_kind() {
        assert!(matches!(
            validate_name("1"),
            Err(Error::InvalidAttributeName { .. })
        ));
    }

    #[test]
    fn constructors_set_types() {
        let t = |a: Attribute, ty: AttrType| {
            assert_eq!(a.value.attr_type(), ty);
            assert!(!a.indexed);
            assert_eq!(a.type_byte(), ty.id());
        };
        t(Attribute::str("a", "x").unwrap(), AttrType::Str);
        t(Attribute::u64("a", 1).unwrap(), AttrType::U64);
        t(Attribute::dec("a", d("1")).unwrap(), AttrType::Dec);
        t(Attribute::addr("a", addr()).unwrap(), AttrType::Addr);
        t(Attribute::bool("a", true).unwrap(), AttrType::Bool);
        t(Attribute::i32("a", -1).unwrap(), AttrType::I32);
        t(Attribute::key("a", B256([1; 32])).unwrap(), AttrType::Key);
        t(Attribute::bytes("a", vec![1]).unwrap(), AttrType::Bytes);
    }

    #[test]
    fn indexed_bit() {
        let a = Attribute::u64("count", 42).unwrap().indexed().unwrap();
        assert!(a.indexed);
        assert_eq!(a.type_byte(), 0x83);
        assert_eq!(
            AttrType::from_type_byte(a.type_byte()).unwrap(),
            (AttrType::U64, true)
        );
        assert!(Attribute::bytes("b", vec![1]).unwrap().indexed().is_err());
        assert!(Attribute::new("b", Value::Bytes(vec![]), true).is_err());
        assert!(Attribute::new("b", Value::Bytes(vec![]), false).is_ok());
    }

    #[test]
    fn schema_attribute() {
        let a = Attribute::schema("demo.items").unwrap();
        assert_eq!(a.name, SCHEMA_ATTRIBUTE);
        assert_eq!(a.type_byte(), 0x88);
        assert_eq!(a.value.encode().unwrap(), b"demo.items");
    }

    #[test]
    fn constructors_validate() {
        assert!(Attribute::str("1bad", "x").is_err());
        assert!(Attribute::str("ok", "a\0").is_err());
        assert!(Attribute::bytes("ok", vec![0; MAX_BYTES_LEN + 1]).is_err());
    }

    #[test]
    fn name_word_padding() {
        let w = Attribute::str("arkiv.schema", "x").unwrap().name_word();
        assert_eq!(&w[..12], b"arkiv.schema");
        assert_eq!(w[12..], [0; 20]);
        let full = Attribute::str(&"z".repeat(32), "x").unwrap().name_word();
        assert_eq!(full, [b'z'; 32]);
    }

    #[test]
    fn normalize_sorts_by_name_word() {
        let attrs = vec![
            Attribute::str("b", "1").unwrap(),
            Attribute::str("a", "1").unwrap(),
            Attribute::str("B", "1").unwrap(),
            Attribute::str("a.b", "1").unwrap(),
            Attribute::str("ab", "1").unwrap(),
        ];
        let names: Vec<_> = normalize(attrs)
            .unwrap()
            .into_iter()
            .map(|a| a.name)
            .collect();
        assert_eq!(names, ["B", "a", "a.b", "ab", "b"]);
    }

    #[test]
    fn normalize_empty_and_single() {
        assert!(normalize(vec![]).unwrap().is_empty());
        assert_eq!(
            normalize(vec![Attribute::str("a", "1").unwrap()])
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn normalize_duplicates() {
        let attrs = vec![
            Attribute::str("a", "1").unwrap(),
            Attribute::u64("a", 1).unwrap(),
        ];
        assert!(matches!(normalize(attrs), Err(Error::DuplicateAttribute(n)) if n == "a"));
    }

    #[test]
    fn normalize_count_limit() {
        let mk = |n: usize| {
            (0..n)
                .map(|i| Attribute::u64(&format!("a{i}"), 1).unwrap())
                .collect::<Vec<_>>()
        };
        assert_eq!(normalize(mk(32)).unwrap().len(), 32);
        assert!(matches!(
            normalize(mk(33)),
            Err(Error::TooManyAttributes { got: 33, max: 32 })
        ));
    }

    #[test]
    fn normalize_bytes_total() {
        let half = || vec![0u8; MAX_ENTITY_BYTES / 2];
        let ok = vec![
            Attribute::bytes("a", half()).unwrap(),
            Attribute::bytes("b", half()).unwrap(),
        ];
        assert!(normalize(ok).is_ok());
        let over = vec![
            Attribute::bytes("a", half()).unwrap(),
            Attribute::bytes("b", half()).unwrap(),
            Attribute::bytes("c", vec![1]).unwrap(),
        ];
        assert!(matches!(normalize(over), Err(Error::EntityTooLarge { .. })));
    }

    #[test]
    fn golden_vectors_match_viem() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../tests/vectors/viem.json")).unwrap();
        let entries = v["attributes"].as_array().unwrap();
        let key = B256(
            hex_decode("59c5ddf06b5605e27833d0a02c8f6e96cebf9f334a6470b39e31eccb34895807")
                .unwrap()
                .try_into()
                .unwrap(),
        );
        let attrs = [
            Attribute::schema("demo.items").unwrap(),
            Attribute::u64("count", 42).unwrap().indexed().unwrap(),
            Attribute::bool("flag", true).unwrap(),
            Attribute::addr("owner", addr()).unwrap().indexed().unwrap(),
            Attribute::dec("price", d("1.5")).unwrap(),
            Attribute::i32("delta", -7).unwrap(),
            Attribute::key("ref", key).unwrap().indexed().unwrap(),
            Attribute::bytes("blob", vec![0xde, 0xad, 0xbe, 0xef]).unwrap(),
        ];
        assert_eq!(attrs.len(), entries.len());
        for (a, e) in attrs.iter().zip(entries) {
            assert_eq!(
                crate::types::hex_encode(&a.name_word()),
                e["name"].as_str().unwrap(),
                "{}",
                a.name
            );
            assert_eq!(
                a.type_byte() as u64,
                e["typeId"].as_u64().unwrap(),
                "{}",
                a.name
            );
            assert_eq!(
                crate::types::hex_encode(&a.value.encode().unwrap()),
                e["value"].as_str().unwrap(),
                "{}",
                a.name
            );
        }
    }
}
