//! Byte for byte checks against calldata produced by the official `@arkiv-network/sdk`
//! (see `tests/golden/generate.mjs`) and against a port of Strike's production encoder.

use arkiv::attributes::{Attribute, Decimal, Value};
use arkiv::ops::{execute_calldata, Create, Expiry, Op};
use arkiv::types::{hex_decode, hex_encode, Address, Key};
use serde_json::Value as Json;

fn h(s: &str) -> Vec<u8> {
    hex_decode(s).expect("hex")
}

fn u256_word(decimal: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for d in decimal.bytes() {
        let mut carry = u32::from(d - b'0');
        for b in out.iter_mut().rev() {
            let v = u32::from(*b) * 10 + carry;
            *b = (v & 0xff) as u8;
            carry = v >> 8;
        }
    }
    out
}

fn attr(a: &Json) -> Attribute {
    let name = a["name"].as_str().unwrap();
    let v = &a["value"];
    let value = match a["type"].as_str().unwrap() {
        "str" => Value::Str(v.as_str().unwrap().into()),
        "u64" => Value::U64(v.as_str().unwrap().parse().unwrap()),
        "u256" => Value::U256(u256_word(v.as_str().unwrap())),
        "i32" => Value::I32(i32::try_from(v.as_i64().unwrap()).unwrap()),
        "bool" => Value::Bool(v.as_bool().unwrap()),
        "dec" => Value::Dec(Decimal::parse(v.as_str().unwrap()).unwrap()),
        "addr" => Value::Addr(v.as_str().unwrap().parse::<Address>().unwrap()),
        "key" => Value::Key(v.as_str().unwrap().parse::<Key>().unwrap()),
        "bytes" => Value::Bytes(h(v.as_str().unwrap())),
        t => panic!("unknown type {t}"),
    };
    Attribute::new(name, value, a["indexed"].as_bool().unwrap()).unwrap()
}

fn create(e: &Json) -> Op {
    let mut attrs = vec![Attribute::schema(e["schema"].as_str().unwrap()).unwrap()];
    attrs.extend(e["attrs"].as_array().unwrap().iter().map(attr));
    let expiry = Expiry {
        expires_at: e["expiry"]["expiresAt"].as_u64().unwrap(),
        min_lifetime: e["expiry"]["minLifetime"].as_u64().unwrap(),
    };
    let salt =
        u128::from_str_radix(e["salt"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    let mut c = Create::new(attrs, expiry).unwrap().with_salt(salt);
    c.flags.readonly = e["readonly"].as_bool().unwrap();
    c.flags.permissionless_extension = e["permissionlessExtension"].as_bool().unwrap();
    Op::Create(c)
}

#[test]
fn matches_official_sdk_calldata() {
    let cases: Vec<Json> = serde_json::from_str(include_str!("golden/fixtures.json")).unwrap();
    assert!(cases.len() >= 8);
    for case in &cases {
        let ops: Vec<Op> = case["entities"]
            .as_array()
            .unwrap()
            .iter()
            .map(create)
            .collect();
        let got = hex_encode(&execute_calldata(&ops).unwrap());
        let want = case["calldata"].as_str().unwrap();
        assert_eq!(got, want, "case {}", case["id"]);
    }
}

#[test]
fn golden_cases_cover_every_type_and_flag() {
    let cases: Vec<Json> = serde_json::from_str(include_str!("golden/fixtures.json")).unwrap();
    let all = serde_json::to_string(&cases).unwrap();
    for t in [
        "str", "u64", "u256", "i32", "bool", "dec", "addr", "key", "bytes",
    ] {
        assert!(all.contains(&format!("\"type\":\"{t}\"")), "missing {t}");
    }
    assert!(all.contains("\"readonly\":true") && all.contains("\"readonly\":false"));
    assert!(all.contains("\"permissionlessExtension\":true"));
}

#[test]
fn calldata_len_matches_golden_length() {
    let cases: Vec<Json> = serde_json::from_str(include_str!("golden/fixtures.json")).unwrap();
    for case in &cases {
        let ops: Vec<Op> = case["entities"]
            .as_array()
            .unwrap()
            .iter()
            .map(create)
            .collect();
        let sum: usize = ops.iter().map(|o| o.calldata_len().unwrap()).sum();
        let want = (case["calldata"].as_str().unwrap().len() - 2) / 2;
        assert_eq!(4 + 64 + sum, want, "case {}", case["id"]);
    }
}

// ---- Strike parity: a verbatim port of backend/crates/core/src/arkiv.rs encoding ----

mod strike {
    pub enum Abi {
        Word([u8; 32]),
        Bytes(Vec<u8>),
        Array(Vec<Abi>),
        Tuple(Vec<Abi>),
    }
    impl Abi {
        fn dynamic(&self) -> bool {
            match self {
                Abi::Word(_) => false,
                Abi::Bytes(_) | Abi::Array(_) => true,
                Abi::Tuple(i) => i.iter().any(Abi::dynamic),
            }
        }
        fn encode(&self) -> Vec<u8> {
            match self {
                Abi::Word(w) => w.to_vec(),
                Abi::Bytes(b) => {
                    let mut out = uint(b.len() as u128).to_vec();
                    out.extend_from_slice(b);
                    out.resize(32 + b.len().div_ceil(32) * 32, 0);
                    out
                }
                Abi::Array(i) => [uint(i.len() as u128).to_vec(), sequence(i)].concat(),
                Abi::Tuple(i) => sequence(i),
            }
        }
    }
    pub fn sequence(items: &[Abi]) -> Vec<u8> {
        let (mut head, mut tail) = (Vec::new(), Vec::new());
        for item in items {
            if item.dynamic() {
                head.extend_from_slice(&uint((items.len() * 32 + tail.len()) as u128));
                tail.extend(item.encode());
            } else {
                head.extend(item.encode());
            }
        }
        [head, tail].concat()
    }
    pub fn uint(v: u128) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[16..].copy_from_slice(&v.to_be_bytes());
        w
    }
    fn int(v: i128) -> [u8; 32] {
        let mut w = [if v < 0 { 0xff } else { 0 }; 32];
        w[16..].copy_from_slice(&v.to_be_bytes());
        w
    }
    pub fn dec(value: i64, scale: u32) -> Vec<u8> {
        int(value as i128 * 10i128.pow(18 - scale)).to_vec()
    }
    pub const STR: u8 = 8;
    pub const DEC: u8 = 5;
    pub const U64: u8 = 3;
    pub const ADDR: u8 = 9;
    pub const INDEXED: u8 = 0x80;
    pub struct Attr(pub &'static str, pub u8, pub Vec<u8>);
    pub fn create_op(mut attrs: Vec<Attr>, salt: u128) -> Abi {
        attrs.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        let attributes = attrs
            .into_iter()
            .map(|a| {
                let mut name = [0u8; 32];
                name[..a.0.len()].copy_from_slice(a.0.as_bytes());
                Abi::Tuple(vec![
                    Abi::Word(name),
                    Abi::Word(uint(a.1 as u128)),
                    Abi::Bytes(a.2),
                ])
            })
            .collect();
        let data = sequence(&[Abi::Tuple(vec![
            Abi::Word(uint(salt)),
            Abi::Word(uint(0)),
            Abi::Word(uint(7_800_000)),
            Abi::Word(uint(1)),
            Abi::Array(attributes),
        ])]);
        Abi::Tuple(vec![Abi::Word(uint(1)), Abi::Bytes(data)])
    }
    pub fn calldata(ops: Vec<Abi>) -> Vec<u8> {
        [vec![0x49, 0x65, 0x00, 0x44], sequence(&[Abi::Array(ops)])].concat()
    }
}

/// One settled round, same field meaning as Strike's `Sealed`.
struct Round {
    bet_id: &'static str,
    wallet: &'static str,
    asset: &'static str,
    direction: &'static str,
    stake: i64,
    multiplier: i64,
    strike_price: i64,
    box_: Option<(i64, i64)>,
    end_price: Option<i64>,
    outcome: &'static str,
    payout: i64,
    settled_at_us: i64,
}

fn strike_attrs(r: &Round) -> Vec<strike::Attr> {
    use strike::*;
    let t = |s: &str| s.as_bytes().to_vec();
    let mut w = vec![0u8; 12];
    w.extend(h(r.wallet));
    let mut a = vec![
        Attr("arkiv.schema", STR | INDEXED, t("strike.rounds")),
        Attr("asset", STR | INDEXED, t(r.asset)),
        Attr("betId", STR | INDEXED, t(r.bet_id)),
        Attr("currency", STR | INDEXED, t("USDC")),
        Attr("direction", STR | INDEXED, t(r.direction)),
        Attr("mode", STR | INDEXED, t("up_down")),
        Attr("multiplier", DEC, dec(r.multiplier, 4)),
        Attr("outcome", STR | INDEXED, t(r.outcome)),
        Attr("payout", DEC, dec(r.payout, 10)),
        Attr(
            "settledAt",
            U64 | INDEXED,
            uint((r.settled_at_us / 1000) as u128).to_vec(),
        ),
        Attr("stake", DEC, dec(r.stake, 10)),
        Attr("strikePrice", DEC, dec(r.strike_price, 8)),
        Attr("wallet", ADDR | INDEXED, w),
    ];
    if let Some(e) = r.end_price {
        a.push(Attr("endPrice", DEC, dec(e, 8)));
    }
    if let Some((top, bottom)) = r.box_ {
        a.push(Attr("priceTop", DEC, dec(top, 8)));
        a.push(Attr("priceBottom", DEC, dec(bottom, 8)));
    }
    a
}

fn arkiv_round(r: &Round) -> Create {
    let s = |n: &str, v: &str| Attribute::str(n, v).unwrap().indexed().unwrap();
    let d = |n: &str, v: i64, scale: u32| {
        Attribute::dec(n, Decimal::from_scaled(v, scale).unwrap()).unwrap()
    };
    let mut a = vec![
        Attribute::schema("strike.rounds").unwrap(),
        s("asset", r.asset),
        s("betId", r.bet_id),
        s("currency", "USDC"),
        s("direction", r.direction),
        s("mode", "up_down"),
        d("multiplier", r.multiplier, 4),
        s("outcome", r.outcome),
        d("payout", r.payout, 10),
        Attribute::u64("settledAt", (r.settled_at_us / 1000) as u64)
            .unwrap()
            .indexed()
            .unwrap(),
        d("stake", r.stake, 10),
        d("strikePrice", r.strike_price, 8),
        Attribute::addr("wallet", r.wallet.parse().unwrap())
            .unwrap()
            .indexed()
            .unwrap(),
    ];
    if let Some(e) = r.end_price {
        a.push(d("endPrice", e, 8));
    }
    if let Some((top, bottom)) = r.box_ {
        a.push(d("priceTop", top, 8));
        a.push(d("priceBottom", bottom, 8));
    }
    Create::new(a, Expiry::blocks(7_800_000).unwrap())
        .unwrap()
        .readonly()
}

fn rounds() -> Vec<Round> {
    vec![
        Round {
            bet_id: "bet_0001",
            wallet: "0f05df479fcb23b2281e28813fb47e57e47d1bb7",
            asset: "BTC",
            direction: "up",
            stake: 25_0000000000,
            multiplier: 18_500,
            strike_price: 6_543_212_345_678,
            box_: None,
            end_price: Some(6_543_999_000_000),
            outcome: "win",
            payout: 46_2500000000,
            settled_at_us: 1_760_000_123_456_789,
        },
        Round {
            bet_id: "bet_0002",
            wallet: "00000000000000000000000000000000000000ab",
            asset: "ETH",
            direction: "box",
            stake: 1_0000000000,
            multiplier: 52_000,
            strike_price: 350_012_345_678,
            box_: Some((351_000_000_000, 349_000_000_000)),
            end_price: None,
            outcome: "loss",
            payout: 0,
            settled_at_us: 1_760_000_999_000_000,
        },
    ]
}

#[test]
fn strike_parity_single_and_batch() {
    let rs = rounds();
    for (n, r) in rs.iter().enumerate() {
        let salt = 0x1000 + n as u128;
        let want = strike::calldata(vec![strike::create_op(strike_attrs(r), salt)]);
        let got = execute_calldata(&[Op::Create(arkiv_round(r).with_salt(salt))]).unwrap();
        assert_eq!(hex_encode(&got), hex_encode(&want), "round {n}");
    }
    let want = strike::calldata(
        rs.iter()
            .enumerate()
            .map(|(n, r)| strike::create_op(strike_attrs(r), 7 + n as u128))
            .collect(),
    );
    let ops: Vec<Op> = rs
        .iter()
        .enumerate()
        .map(|(n, r)| Op::Create(arkiv_round(r).with_salt(7 + n as u128)))
        .collect();
    assert_eq!(
        hex_encode(&execute_calldata(&ops).unwrap()),
        hex_encode(&want)
    );
}
