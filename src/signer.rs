//! EIP-1559 transaction building and secp256k1 signing.
//!
//! Contains its own minimal RLP; nothing else in the crate encodes RLP.

use k256::ecdsa::{RecoveryId, Signature, SigningKey};

use crate::error::{Error, Result};
use crate::types::{hex_decode, hex_encode, keccak256, Address, TxHash, B256};

/// An EIP-1559 (type 2) transaction with an empty access list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tx1559 {
    /// Chain id.
    pub chain_id: u64,
    /// Account nonce.
    pub nonce: u64,
    /// Gas limit.
    pub gas_limit: u64,
    /// `maxFeePerGas` in wei.
    pub max_fee_per_gas: u128,
    /// `maxPriorityFeePerGas` in wei.
    pub max_priority_fee_per_gas: u128,
    /// Destination.
    pub to: Address,
    /// Value in wei.
    pub value: u128,
    /// Calldata.
    pub data: Vec<u8>,
}

/// A signed, serialized transaction ready for `eth_sendRawTransaction`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTx {
    /// `0x02 || rlp([... , yParity, r, s])`.
    pub raw: Vec<u8>,
    /// `keccak256(raw)`.
    pub hash: TxHash,
}

impl SignedTx {
    /// The raw bytes as `0x` hex.
    pub fn raw_hex(&self) -> String {
        hex_encode(&self.raw)
    }
}

/// A secp256k1 key that signs transactions. `Debug` never prints the key.
pub struct Signer {
    key: SigningKey,
    address: Address,
}

impl Signer {
    /// Parses a 32-byte private key from hex, with or without `0x`.
    ///
    /// ```
    /// use arkiv::Signer;
    ///
    /// // The public Hardhat test key. Never use it for real funds.
    /// let key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    /// let signer = Signer::from_hex(key).unwrap();
    /// assert_eq!(signer.address().to_string().to_lowercase(), "0xf39fd6e51aad88f6f4ce6ab8827279cffFb92266".to_lowercase());
    /// assert!(Signer::from_hex("nope").is_err());
    /// ```
    /// Errors with [`Error::InvalidKey`], without echoing the input.
    pub fn from_hex(private_key: &str) -> Result<Signer> {
        let bytes = hex_decode(private_key.trim()).map_err(|_| Error::InvalidKey)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| Error::InvalidKey)?;
        Signer::from_bytes(&arr)
    }

    /// Builds a signer from raw key bytes.
    pub fn from_bytes(private_key: &[u8; 32]) -> Result<Signer> {
        let key = SigningKey::from_bytes(private_key.into()).map_err(|_| Error::InvalidKey)?;
        let point = key.verifying_key().to_encoded_point(false);
        let xy = point.as_bytes().get(1..).ok_or(Error::InvalidKey)?;
        let hash = keccak256(xy);
        let mut a = [0u8; 20];
        a.copy_from_slice(&hash[12..]);
        Ok(Signer {
            key,
            address: Address(a),
        })
    }

    /// The Ethereum address: the last 20 bytes of `keccak256(uncompressed pubkey without the 0x04 prefix)`.
    pub fn address(&self) -> Address {
        self.address
    }

    /// Signs `tx`. Deterministic (RFC 6979) with a low-s signature, so equal input gives equal bytes.
    pub fn sign(&self, tx: &Tx1559) -> Result<SignedTx> {
        let digest = keccak256(&unsigned_payload(tx));
        let (sig, rid) = self
            .key
            .sign_prehash_recoverable(&digest)
            .map_err(|e| Error::Signing(e.to_string()))?;
        let (sig, rid) = low_s(sig, rid);
        let bytes = sig.to_bytes();
        let (r, s) = bytes.split_at(32);
        let mut items = fields(tx);
        items.push(rlp_bytes(&be_min(u128::from(rid.is_y_odd()))));
        items.push(rlp_bytes(&strip_zeros(r)));
        items.push(rlp_bytes(&strip_zeros(s)));
        let mut raw = vec![0x02u8];
        raw.extend(rlp_list(&items));
        let hash = B256(keccak256(&raw));
        Ok(SignedTx { raw, hash })
    }
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signer")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

/// The signing payload: `0x02 || rlp([chainId, nonce, maxPriorityFee, maxFee, gasLimit, to, value, data, []])`.
pub fn unsigned_payload(tx: &Tx1559) -> Vec<u8> {
    let mut out = vec![0x02u8];
    out.extend(rlp_list(&fields(tx)));
    out
}

/// Forces `s` into the lower half of the curve order, flipping the recovery parity when it changes.
fn low_s(sig: Signature, rid: RecoveryId) -> (Signature, RecoveryId) {
    match sig.normalize_s() {
        Some(n) => (n, RecoveryId::new(!rid.is_y_odd(), rid.is_x_reduced())),
        None => (sig, rid),
    }
}

/// The nine shared RLP items of the transaction, already encoded.
fn fields(tx: &Tx1559) -> Vec<Vec<u8>> {
    vec![
        rlp_bytes(&be_min(u128::from(tx.chain_id))),
        rlp_bytes(&be_min(u128::from(tx.nonce))),
        rlp_bytes(&be_min(tx.max_priority_fee_per_gas)),
        rlp_bytes(&be_min(tx.max_fee_per_gas)),
        rlp_bytes(&be_min(u128::from(tx.gas_limit))),
        rlp_bytes(tx.to.as_bytes()),
        rlp_bytes(&be_min(tx.value)),
        rlp_bytes(&tx.data),
        rlp_list(&[]),
    ]
}

/// Big-endian bytes with leading zeros removed (empty for 0).
fn be_min(n: u128) -> Vec<u8> {
    strip_zeros(&n.to_be_bytes())
}

fn strip_zeros(b: &[u8]) -> Vec<u8> {
    let start = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    b[start..].to_vec()
}

fn rlp_header(offset: u8, len: usize) -> Vec<u8> {
    if len < 56 {
        // len < 56 fits in a byte
        return vec![offset + len as u8];
    }
    let l = strip_zeros(&(len as u64).to_be_bytes());
    let mut out = vec![offset + 55 + l.len() as u8];
    out.extend(l);
    out
}

/// RLP string encoding.
fn rlp_bytes(b: &[u8]) -> Vec<u8> {
    if b.len() == 1 && b[0] < 0x80 {
        return b.to_vec();
    }
    let mut out = rlp_header(0x80, b.len());
    out.extend_from_slice(b);
    out
}

/// RLP list of already encoded items.
fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let body: Vec<u8> = items.concat();
    let mut out = rlp_header(0xc0, body.len());
    out.extend(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    use k256::elliptic_curve::scalar::IsHigh;

    const HARDHAT: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const VECTORS: &str = include_str!("../tests/vectors/viem.json");

    fn tx() -> Tx1559 {
        Tx1559 {
            chain_id: 7_794_095,
            nonce: 7,
            gas_limit: 210_000,
            max_fee_per_gas: 2_000_000_000,
            max_priority_fee_per_gas: 100_000_000,
            to: crate::types::ARKIV_ADDRESS,
            value: 0,
            data: vec![0x49, 0x65, 0x00, 0x44, 0x00],
        }
    }

    fn signer() -> Signer {
        Signer::from_hex(HARDHAT).unwrap()
    }

    fn addr_of(hex_key: &str) -> String {
        Signer::from_hex(hex_key).unwrap().address().to_string()
    }

    #[test]
    fn matches_viem_golden_vector() {
        let v: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
        let g = &v["signedTx"];
        let s = Signer::from_hex(g["privateKey"].as_str().unwrap()).unwrap();
        assert_eq!(s.address().to_string(), g["address"].as_str().unwrap());
        let t = Tx1559 {
            chain_id: g["chainId"].as_u64().unwrap(),
            nonce: g["nonce"].as_u64().unwrap(),
            gas_limit: g["gasLimit"].as_u64().unwrap(),
            max_fee_per_gas: g["maxFeePerGas"].as_str().unwrap().parse().unwrap(),
            max_priority_fee_per_gas: g["maxPriorityFeePerGas"].as_str().unwrap().parse().unwrap(),
            to: g["to"].as_str().unwrap().parse().unwrap(),
            value: g["value"].as_str().unwrap().parse().unwrap(),
            data: hex_decode(g["data"].as_str().unwrap()).unwrap(),
        };
        let signed = s.sign(&t).unwrap();
        assert_eq!(signed.raw_hex(), g["raw"].as_str().unwrap());
        assert_eq!(signed.hash.to_string(), g["hash"].as_str().unwrap());
    }

    #[test]
    fn hardhat_vector_in_file_uses_same_key() {
        let v: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
        assert_eq!(v["signedTx"]["privateKey"].as_str().unwrap(), HARDHAT);
    }

    #[test]
    fn hardhat_address() {
        assert_eq!(
            signer().address().to_string(),
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        );
    }

    #[test]
    fn known_addresses_for_small_keys() {
        let k1 = format!("{:0>64}", "1");
        let k2 = format!("{:0>64}", "2");
        assert_eq!(addr_of(&k1), "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf");
        assert_eq!(addr_of(&k2), "0x2b5ad5c4795c026514f8317c7a215e218dccd6cf");
    }

    #[test]
    fn other_hardhat_accounts() {
        assert_eq!(
            addr_of("59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"),
            "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"
        );
        assert_eq!(
            addr_of("5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"),
            "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc"
        );
    }

    #[test]
    fn from_hex_with_and_without_prefix_agree() {
        let a = Signer::from_hex(HARDHAT).unwrap();
        let b = Signer::from_hex(&HARDHAT[2..]).unwrap();
        assert_eq!(a.address(), b.address());
    }

    #[test]
    fn from_hex_accepts_uppercase_and_whitespace() {
        let s = Signer::from_hex(&format!(
            "  {}\n",
            HARDHAT.to_uppercase().replace("0X", "0x")
        ))
        .unwrap();
        assert_eq!(s.address(), signer().address());
    }

    #[test]
    fn from_bytes_matches_from_hex() {
        let mut b = [0u8; 32];
        b.copy_from_slice(&hex::decode(&HARDHAT[2..]).unwrap());
        assert_eq!(
            Signer::from_bytes(&b).unwrap().address(),
            signer().address()
        );
    }

    #[test]
    fn rejects_bad_keys() {
        for bad in [
            "",
            "0x",
            "zz",
            "0x1234",
            &"00".repeat(32),
            &"ff".repeat(32),
            &"ab".repeat(33),
            "not hex at all",
        ] {
            assert!(
                matches!(Signer::from_hex(bad), Err(Error::InvalidKey)),
                "{bad}"
            );
        }
    }

    #[test]
    fn rejects_zero_and_curve_order() {
        assert!(Signer::from_bytes(&[0u8; 32]).is_err());
        let n = hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
            .unwrap();
        let mut b = [0u8; 32];
        b.copy_from_slice(&n);
        assert!(Signer::from_bytes(&b).is_err());
    }

    #[test]
    fn accepts_order_minus_one() {
        let n = hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140")
            .unwrap();
        let mut b = [0u8; 32];
        b.copy_from_slice(&n);
        assert!(Signer::from_bytes(&b).is_ok());
    }

    #[test]
    fn error_does_not_echo_key() {
        let secret = "deadbeef-secret-key";
        let e = Signer::from_hex(secret).unwrap_err();
        assert!(!e.to_string().contains("deadbeef"));
        assert!(!format!("{e:?}").contains("deadbeef"));
    }

    #[test]
    fn debug_hides_key() {
        let d = format!("{:?}", signer());
        assert!(!d.contains(&HARDHAT[2..]));
        assert!(!d.contains("ac0974"));
        assert!(d.contains("Signer"));
        assert!(d.contains("f39fd6e51aad88f6f4ce6ab8827279cfffb92266"));
    }

    #[test]
    fn signing_is_deterministic() {
        let a = signer().sign(&tx()).unwrap();
        let b = signer().sign(&tx()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_nonce_changes_signature_and_hash() {
        let mut t = tx();
        let a = signer().sign(&t).unwrap();
        t.nonce += 1;
        let b = signer().sign(&t).unwrap();
        assert_ne!(a.raw, b.raw);
        assert_ne!(a.hash, b.hash);
    }

    #[test]
    fn hash_is_keccak_of_raw() {
        let s = signer().sign(&tx()).unwrap();
        assert_eq!(s.hash.0, keccak256(&s.raw));
    }

    #[test]
    fn raw_starts_with_type_byte_and_hex_is_prefixed() {
        let s = signer().sign(&tx()).unwrap();
        assert_eq!(s.raw[0], 0x02);
        assert!(s.raw_hex().starts_with("0x02"));
        assert_eq!(s.raw_hex().len(), 2 + s.raw.len() * 2);
    }

    #[test]
    fn unsigned_payload_prefix_and_prefix_of_raw() {
        let p = unsigned_payload(&tx());
        assert_eq!(p[0], 0x02);
        // first RLP item of both is the list header then the chain id 7794095 = 0x76edaf
        assert!(p.windows(4).any(|w| w == [0x83, 0x76, 0xed, 0xaf]));
    }

    #[test]
    fn unsigned_payload_known_bytes() {
        let tx = Tx1559 {
            chain_id: 1,
            nonce: 0,
            gas_limit: 21_000,
            max_fee_per_gas: 2,
            max_priority_fee_per_gas: 1,
            to: Address([0x11; 20]),
            value: 0,
            data: vec![],
        };
        // 02 | list(0x1c + ...) : 01 80 01 02 82 5208 94<20> 80 80 c0
        let mut want = vec![
            0x02u8,
            0xc0 + 31,
            0x01,
            0x80,
            0x01,
            0x02,
            0x82,
            0x52,
            0x08,
            0x94,
        ];
        want.extend([0x11u8; 20]);
        want.extend([0x80, 0x80, 0xc0]);
        assert_eq!(unsigned_payload(&tx), want);
    }

    #[test]
    fn signature_is_low_s_and_verifies() {
        let t = tx();
        let s = signer().sign(&t).unwrap();
        // decode r, s from the tail: ... a0<r32> a0<s32>
        let n = s.raw.len();
        let sb = &s.raw[n - 32..];
        let rb = &s.raw[n - 65..n - 33];
        assert_eq!(s.raw[n - 33], 0xa0);
        let mut rs = [0u8; 64];
        rs[..32].copy_from_slice(rb);
        rs[32..].copy_from_slice(sb);
        let sig = Signature::from_slice(&rs).unwrap();
        assert!(!bool::from(sig.s().is_high()));
        let digest = keccak256(&unsigned_payload(&t));
        signer()
            .key
            .verifying_key()
            .verify_prehash(&digest, &sig)
            .unwrap();
    }

    #[test]
    fn recovers_signer_address_for_many_txs() {
        use k256::ecdsa::VerifyingKey;
        for nonce in 0..40u64 {
            let t = Tx1559 {
                nonce,
                data: vec![nonce as u8; (nonce as usize) * 3],
                ..tx()
            };
            let s = signer().sign(&t).unwrap();
            let (r, ss, y) = parse_sig_tail(&s.raw);
            let mut rs = [0u8; 64];
            rs[32 - r.len()..32].copy_from_slice(&r);
            rs[64 - ss.len()..].copy_from_slice(&ss);
            let sig = Signature::from_slice(&rs).unwrap();
            assert!(!bool::from(sig.s().is_high()), "nonce {nonce}");
            let rid = RecoveryId::new(y == 1, false);
            let digest = keccak256(&unsigned_payload(&t));
            let vk = VerifyingKey::recover_from_prehash(&digest, &sig, rid).unwrap();
            let pt = vk.to_encoded_point(false);
            let h = keccak256(&pt.as_bytes()[1..]);
            assert_eq!(&h[12..], signer().address().as_bytes(), "nonce {nonce}");
        }
    }

    /// Parses `(r, s, yParity)` from the end of a signed tx, handling short r or s.
    fn parse_sig_tail(raw: &[u8]) -> (Vec<u8>, Vec<u8>, u8) {
        // Walk the list backwards is awkward; decode forward instead.
        let (items, _) = decode_list(&raw[1..]);
        let n = items.len();
        assert_eq!(n, 12);
        let y = items[9].first().copied().unwrap_or(0);
        (items[10].clone(), items[11].clone(), y)
    }

    /// Minimal RLP decoder for tests: returns the top-level items of a list as raw payload bytes
    /// (nested lists are returned as their body).
    fn decode_list(b: &[u8]) -> (Vec<Vec<u8>>, usize) {
        let (hdr, body_len) = header(b);
        let mut items = Vec::new();
        let mut pos = hdr;
        let end = hdr + body_len;
        while pos < end {
            let (h, l) = header(&b[pos..]);
            if b[pos] < 0x80 {
                items.push(vec![b[pos]]);
                pos += 1;
            } else {
                items.push(b[pos + h..pos + h + l].to_vec());
                pos += h + l;
            }
        }
        (items, end)
    }

    fn header(b: &[u8]) -> (usize, usize) {
        let t = b[0];
        match t {
            0..=0x7f => (0, 1),
            0x80..=0xb7 => (1, (t - 0x80) as usize),
            0xb8..=0xbf => {
                let ll = (t - 0xb7) as usize;
                (
                    1 + ll,
                    b[1..1 + ll]
                        .iter()
                        .fold(0usize, |a, &x| (a << 8) | x as usize),
                )
            }
            0xc0..=0xf7 => (1, (t - 0xc0) as usize),
            _ => {
                let ll = (t - 0xf7) as usize;
                (
                    1 + ll,
                    b[1..1 + ll]
                        .iter()
                        .fold(0usize, |a, &x| (a << 8) | x as usize),
                )
            }
        }
    }

    #[test]
    fn signed_tx_decodes_back_to_fields() {
        let t = Tx1559 {
            value: 1_000_000_000_000_000_000,
            data: vec![0xab; 300],
            ..tx()
        };
        let s = signer().sign(&t).unwrap();
        let (items, end) = decode_list(&s.raw[1..]);
        assert_eq!(end, s.raw.len() - 1);
        assert_eq!(items[0], be_min(t.chain_id as u128));
        assert_eq!(items[1], be_min(t.nonce as u128));
        assert_eq!(items[2], be_min(t.max_priority_fee_per_gas));
        assert_eq!(items[3], be_min(t.max_fee_per_gas));
        assert_eq!(items[4], be_min(t.gas_limit as u128));
        assert_eq!(items[5], t.to.as_bytes().to_vec());
        assert_eq!(items[6], be_min(t.value));
        assert_eq!(items[7], t.data);
        assert!(items[8].is_empty());
    }

    #[test]
    fn works_for_any_chain_id() {
        for id in [1u64, 5, 137, 255, 256, 65_535, 7_794_095, u64::MAX] {
            let t = Tx1559 {
                chain_id: id,
                ..tx()
            };
            let s = signer().sign(&t).unwrap();
            let (items, _) = decode_list(&s.raw[1..]);
            assert_eq!(items[0], be_min(id as u128));
        }
    }

    #[test]
    fn chain_id_changes_signature() {
        let a = signer().sign(&tx()).unwrap();
        let b = signer()
            .sign(&Tx1559 {
                chain_id: 1,
                ..tx()
            })
            .unwrap();
        assert_ne!(a.raw, b.raw);
    }

    #[test]
    fn zero_fields_encode_as_empty_strings() {
        let t = Tx1559 {
            nonce: 0,
            value: 0,
            max_priority_fee_per_gas: 0,
            data: vec![],
            ..tx()
        };
        let f = fields(&t);
        assert_eq!(f[1], vec![0x80]);
        assert_eq!(f[2], vec![0x80]);
        assert_eq!(f[6], vec![0x80]);
        assert_eq!(f[7], vec![0x80]);
        assert_eq!(f[8], vec![0xc0]);
    }

    #[test]
    fn max_values_encode() {
        let t = Tx1559 {
            max_fee_per_gas: u128::MAX,
            value: u128::MAX,
            gas_limit: u64::MAX,
            nonce: u64::MAX,
            ..tx()
        };
        let s = signer().sign(&t).unwrap();
        let (items, _) = decode_list(&s.raw[1..]);
        assert_eq!(items[3], vec![0xff; 16]);
        assert_eq!(items[6], vec![0xff; 16]);
        assert_eq!(items[4], vec![0xff; 8]);
        assert_eq!(items[1], vec![0xff; 8]);
    }

    // ---- RLP vectors from the Ethereum wiki ----

    #[test]
    fn rlp_wiki_strings() {
        assert_eq!(rlp_bytes(b"dog"), vec![0x83, b'd', b'o', b'g']);
        assert_eq!(rlp_bytes(b""), vec![0x80]);
        assert_eq!(rlp_bytes(&[0x00]), vec![0x00]);
        assert_eq!(rlp_bytes(&[0x0f]), vec![0x0f]);
        assert_eq!(rlp_bytes(&[0x7f]), vec![0x7f]);
        assert_eq!(rlp_bytes(&[0x80]), vec![0x81, 0x80]);
        assert_eq!(rlp_bytes(&[0x04, 0x00]), vec![0x82, 0x04, 0x00]);
    }

    #[test]
    fn rlp_wiki_lists() {
        assert_eq!(rlp_list(&[]), vec![0xc0]);
        assert_eq!(
            rlp_list(&[rlp_bytes(b"cat"), rlp_bytes(b"dog")]),
            vec![0xc8, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g']
        );
        // [ [], [[]], [ [], [[]] ] ]
        let e = rlp_list(&[]);
        let a = rlp_list(std::slice::from_ref(&e));
        let c = rlp_list(&[e.clone(), a.clone()]);
        assert_eq!(
            rlp_list(&[e, a, c]),
            vec![0xc7, 0xc0, 0xc1, 0xc0, 0xc3, 0xc0, 0xc1, 0xc0]
        );
    }

    #[test]
    fn rlp_long_string_wiki() {
        let s = b"Lorem ipsum dolor sit amet, consectetur adipisicing elit";
        assert_eq!(s.len(), 56);
        let out = rlp_bytes(s);
        assert_eq!(&out[..2], &[0xb8, 0x38]);
        assert_eq!(&out[2..], s);
    }

    #[test]
    fn rlp_length_boundaries() {
        assert_eq!(rlp_bytes(&[1u8; 55])[0], 0x80 + 55);
        assert_eq!(&rlp_bytes(&[1u8; 56])[..2], &[0xb8, 56]);
        assert_eq!(&rlp_bytes(&[1u8; 255])[..2], &[0xb8, 255]);
        assert_eq!(&rlp_bytes(&[1u8; 256])[..3], &[0xb9, 1, 0]);
        assert_eq!(&rlp_bytes(&vec![1u8; 70_000])[..4], &[0xba, 1, 0x11, 0x70]);
        let l55 = rlp_list(&[vec![0x01u8; 55]]);
        assert_eq!(l55[0], 0xc0 + 55);
        let l56 = rlp_list(&[vec![0x01u8; 56]]);
        assert_eq!(&l56[..2], &[0xf8, 56]);
        let l256 = rlp_list(&[vec![0x01u8; 256]]);
        assert_eq!(&l256[..3], &[0xf9, 1, 0]);
    }

    #[test]
    fn rlp_integers() {
        assert_eq!(rlp_bytes(&be_min(0)), vec![0x80]);
        assert_eq!(rlp_bytes(&be_min(1)), vec![0x01]);
        assert_eq!(rlp_bytes(&be_min(127)), vec![0x7f]);
        assert_eq!(rlp_bytes(&be_min(128)), vec![0x81, 0x80]);
        assert_eq!(rlp_bytes(&be_min(1024)), vec![0x82, 0x04, 0x00]);
    }

    #[test]
    fn be_min_strips_leading_zeros() {
        assert!(be_min(0).is_empty());
        assert_eq!(be_min(0x0100), vec![1, 0]);
        assert_eq!(be_min(u128::MAX).len(), 16);
        assert_eq!(strip_zeros(&[0, 0, 5, 0]), vec![5, 0]);
        assert!(strip_zeros(&[0, 0]).is_empty());
    }

    // ---- cross-check against Strike eth.rs logic (same field order, same low-s step) ----

    #[test]
    fn matches_strike_field_order_by_construction() {
        // Strike eth.rs build_eip1559_raw: [chain, nonce, priority, maxFee, gas, to, value, data, []]
        // then [.., yParity, r, s]. Rebuild the unsigned list that way and compare.
        let t = tx();
        let strike = rlp_list(&[
            rlp_bytes(&be_min(t.chain_id as u128)),
            rlp_bytes(&be_min(t.nonce as u128)),
            rlp_bytes(&be_min(t.max_priority_fee_per_gas)),
            rlp_bytes(&be_min(t.max_fee_per_gas)),
            rlp_bytes(&be_min(t.gas_limit as u128)),
            rlp_bytes(t.to.as_bytes()),
            rlp_bytes(&be_min(t.value)),
            rlp_bytes(&t.data),
            rlp_list(&[]),
        ]);
        let mut want = vec![0x02];
        want.extend(strike);
        assert_eq!(unsigned_payload(&t), want);
    }

    #[test]
    fn low_s_flips_parity() {
        // Build a high-s signature from a real one and check low_s restores it with flipped parity.
        let digest = keccak256(&unsigned_payload(&tx()));
        let (sig, rid) = signer().key.sign_prehash_recoverable(&digest).unwrap();
        let (low, low_rid) = low_s(sig, rid);
        assert!(!bool::from(low.s().is_high()));
        // high form: s' = n - s
        let high = Signature::from_scalars(low.r().to_bytes(), (-*low.s()).to_bytes()).unwrap();
        assert!(bool::from(high.s().is_high()));
        let flipped = RecoveryId::new(!low_rid.is_y_odd(), low_rid.is_x_reduced());
        let (fixed, fixed_rid) = low_s(high, flipped);
        assert_eq!(fixed, low);
        assert_eq!(fixed_rid.is_y_odd(), low_rid.is_y_odd());
    }

    #[test]
    fn many_signatures_are_unique_per_payload() {
        let mut seen = std::collections::HashSet::new();
        for n in 0..50u64 {
            let s = signer().sign(&Tx1559 { nonce: n, ..tx() }).unwrap();
            assert!(seen.insert(s.hash));
        }
    }
}
