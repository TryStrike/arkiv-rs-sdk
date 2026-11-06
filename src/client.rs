//! JSON-RPC client: reads, nonces, receipts, sending, and the signed `execute` pipeline.
//!
//! Uses `ops`, `signer`, `query` and `attributes` through their public APIs only.

use std::time::{Duration, Instant};

use serde_json::{json, Value as Json};

use crate::attributes::Value;
use crate::error::{Error, QueryErrorKind, Result};
use crate::ops::{self, CreationFlags, Op};
use crate::query::Query;
use crate::signer::{SignedTx, Signer, Tx1559};
use crate::types::{
    entity_created_topic, hex_decode, hex_encode, parse_quantity, quantity, Address, Key, TxHash,
    ARKIV_ADDRESS, B256, ENTITY_NONCE_SELECTOR, RABDI_CHAIN_ID, RABDI_RPC,
};

/// Node limit on `arkiv_query` page size.
pub const MAX_QUERY_LIMIT: u32 = 100;

/// Longest response body kept inside an [`Error::Status`].
const MAX_BODY_IN_ERROR: usize = 512;

/// Connection and retry settings.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// JSON-RPC endpoint.
    pub rpc_url: String,
    /// Chain id used for signing.
    pub chain_id: u64,
    /// Per-request timeout.
    pub timeout: Duration,
    /// Retries after the first attempt, for reads only.
    pub max_retries: u32,
    /// First backoff delay; doubles each retry, with jitter.
    pub base_delay: Duration,
    /// Backoff ceiling. A `Retry-After` header is honoured up to this.
    pub max_delay: Duration,
}

impl Default for ClientConfig {
    /// The Rabdi testnet, 20 s timeout, 5 retries, 300 ms base delay, 8 s ceiling.
    fn default() -> Self {
        ClientConfig {
            rpc_url: RABDI_RPC.to_string(),
            chain_id: RABDI_CHAIN_ID,
            timeout: Duration::from_secs(20),
            max_retries: 5,
            base_delay: Duration::from_millis(300),
            max_delay: Duration::from_secs(8),
        }
    }
}

/// Which fields `arkiv_query` returns. [`Select::all`] is the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Select {
    /// Entity key.
    pub key: bool,
    /// Current owner.
    pub owner: bool,
    /// Creator.
    pub creator: bool,
    /// Block of creation.
    pub created_at: bool,
    /// Block of last update.
    pub updated_at: bool,
    /// Expiry block.
    pub expires_at: bool,
    /// Creation flags.
    pub creation_flags: bool,
    /// All attributes.
    pub attributes: bool,
}

impl Select {
    /// Everything.
    pub fn all() -> Select {
        Select {
            key: true,
            owner: true,
            creator: true,
            created_at: true,
            updated_at: true,
            expires_at: true,
            creation_flags: true,
            attributes: true,
        }
    }
    /// Only the key.
    pub fn key_only() -> Select {
        Select {
            key: true,
            owner: false,
            creator: false,
            created_at: false,
            updated_at: false,
            expires_at: false,
            creation_flags: false,
            attributes: false,
        }
    }

    fn to_json(self) -> Json {
        json!({
            "key": self.key,
            "owner": self.owner,
            "creator": self.creator,
            "createdAt": self.created_at,
            "updatedAt": self.updated_at,
            "expiresAt": self.expires_at,
            "creationFlags": self.creation_flags,
            "attributes": self.attributes,
        })
    }
}

/// Options for [`Client::query`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryOptions {
    /// Fields to return.
    pub select: Select,
    /// Page size, 1 to [`MAX_QUERY_LIMIT`]. Default 100.
    pub limit: u32,
    /// Rows to skip. Offset paging works on the public node; `cursor` does not across blocks.
    pub offset: Option<u64>,
    /// Opaque cursor from a previous page. Only valid at the block it was issued for.
    pub cursor: Option<String>,
    /// Read state at this block. The public node keeps only the latest.
    pub at_block: Option<u64>,
}

impl Default for QueryOptions {
    /// `Select::all()`, limit 100, no offset, no cursor, latest block.
    fn default() -> Self {
        QueryOptions {
            select: Select::all(),
            limit: MAX_QUERY_LIMIT,
            offset: None,
            cursor: None,
            at_block: None,
        }
    }
}

/// An entity as read back from the node. Fields not selected are `None`; attributes empty.
#[derive(Debug, Clone, PartialEq)]
pub struct Entity {
    /// Entity key.
    pub key: Option<Key>,
    /// Current owner.
    pub owner: Option<Address>,
    /// Creator.
    pub creator: Option<Address>,
    /// Block of creation.
    pub created_at: Option<u64>,
    /// Block of last update.
    pub updated_at: Option<u64>,
    /// Expiry block.
    pub expires_at: Option<u64>,
    /// Creation flags.
    pub creation_flags: Option<CreationFlags>,
    /// Attributes in node order, decoded by declared type.
    pub attributes: Vec<(String, Value)>,
}

impl Entity {
    /// First attribute named `name`.
    pub fn attr(&self, name: &str) -> Option<&Value> {
        self.attributes
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v)
    }
    /// The `arkiv.schema` tag, when present and a string.
    pub fn schema(&self) -> Option<&str> {
        match self.attr(crate::attributes::SCHEMA_ATTRIBUTE) {
            Some(Value::Str(s)) => Some(s),
            _ => None,
        }
    }

    fn from_json(j: &Json) -> Result<Entity> {
        let obj = j
            .as_object()
            .ok_or_else(|| decode("entity is not an object"))?;
        let flags = match obj.get("creationFlags") {
            None | Some(Json::Null) => None,
            Some(f) => Some(parse_flags(f)?),
        };
        let mut attributes = Vec::new();
        if let Some(list) = obj.get("attributes").filter(|a| !a.is_null()) {
            let list = list
                .as_array()
                .ok_or_else(|| decode("attributes is not an array"))?;
            for a in list {
                let name = a
                    .get("name")
                    .and_then(Json::as_str)
                    .ok_or_else(|| decode("attribute without name"))?;
                let ty = a
                    .get("type")
                    .and_then(Json::as_str)
                    .ok_or_else(|| decode("attribute without type"))?;
                let raw = a
                    .get("value")
                    .ok_or_else(|| decode("attribute without value"))?;
                attributes.push((name.to_string(), Value::from_rpc(ty, raw)?));
            }
        }
        Ok(Entity {
            key: opt_hex(obj.get("key"))?,
            owner: opt_hex(obj.get("owner"))?,
            creator: opt_hex(obj.get("creator"))?,
            created_at: opt_num(obj.get("createdAt"))?,
            updated_at: opt_num(obj.get("updatedAt"))?,
            expires_at: opt_num(obj.get("expiresAt"))?,
            creation_flags: flags,
            attributes,
        })
    }
}

fn decode(msg: impl Into<String>) -> Error {
    Error::Decode(msg.into())
}

fn parse_flags(f: &Json) -> Result<CreationFlags> {
    if let Some(raw) = f.get("raw") {
        return Ok(CreationFlags::from_byte(
            u8::try_from(num(raw)?).map_err(|_| decode("creation flags above 255"))?,
        ));
    }
    let b = |k: &str| f.get(k).and_then(Json::as_bool).unwrap_or(false);
    Ok(CreationFlags {
        readonly: b("readonly"),
        permissionless_extension: b("permissionlessExtension"),
    })
}

/// A number given as a QUANTITY string or a JSON number.
fn num(j: &Json) -> Result<u64> {
    match j {
        Json::String(s) => parse_quantity(s),
        Json::Number(n) => n
            .as_u64()
            .ok_or_else(|| decode(format!("not an unsigned integer: {n}"))),
        other => Err(decode(format!("not a number: {other}"))),
    }
}

fn opt_num(j: Option<&Json>) -> Result<Option<u64>> {
    match j {
        None | Some(Json::Null) => Ok(None),
        Some(v) => num(v).map(Some),
    }
}

fn opt_hex<T: std::str::FromStr<Err = Error>>(j: Option<&Json>) -> Result<Option<T>> {
    match j {
        None | Some(Json::Null) => Ok(None),
        Some(v) => {
            let s = v.as_str().ok_or_else(|| decode("expected a hex string"))?;
            s.parse().map(Some)
        }
    }
}

fn req_hex<T: std::str::FromStr<Err = Error>>(j: &Json, field: &str) -> Result<T> {
    opt_hex(j.get(field))?.ok_or_else(|| decode(format!("missing {field}")))
}

/// One page of query results.
#[derive(Debug, Clone, PartialEq)]
pub struct Page {
    /// Rows.
    pub entities: Vec<Entity>,
    /// Block the page was read at.
    pub block_number: u64,
    /// Cursor for the next page, when the node returned one.
    pub cursor: Option<String>,
}

/// A decoded log from a receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Log {
    /// Emitting contract.
    pub address: Address,
    /// Topics, topic 0 first.
    pub topics: Vec<crate::types::B256>,
    /// Log data.
    pub data: Vec<u8>,
}

/// A mined transaction receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    /// Transaction hash.
    pub tx_hash: TxHash,
    /// Block number.
    pub block_number: u64,
    /// True when status is `0x1`.
    pub success: bool,
    /// Gas used.
    pub gas_used: u64,
    /// Logs.
    pub logs: Vec<Log>,
}

impl Receipt {
    /// Keys of entities created in this transaction, in order: topic 1 of each `EntityCreated`
    /// log emitted by the Arkiv engine contract.
    pub fn created_keys(&self) -> Vec<Key> {
        let topic = entity_created_topic();
        self.logs
            .iter()
            .filter(|l| l.address == ARKIV_ADDRESS && l.topics.first() == Some(&topic))
            .filter_map(|l| l.topics.get(1).copied())
            .collect()
    }

    fn from_json(j: &Json) -> Result<Receipt> {
        let status = j
            .get("status")
            .ok_or_else(|| decode("receipt without status"))?;
        let logs = match j.get("logs").filter(|l| !l.is_null()) {
            None => Vec::new(),
            Some(l) => l
                .as_array()
                .ok_or_else(|| decode("logs is not an array"))?
                .iter()
                .map(Log::from_json)
                .collect::<Result<Vec<_>>>()?,
        };
        Ok(Receipt {
            tx_hash: req_hex(j, "transactionHash")?,
            block_number: num(j
                .get("blockNumber")
                .ok_or_else(|| decode("receipt without blockNumber"))?)?,
            success: num(status)? == 1,
            gas_used: num(j
                .get("gasUsed")
                .ok_or_else(|| decode("receipt without gasUsed"))?)?,
            logs,
        })
    }
}

impl Log {
    fn from_json(j: &Json) -> Result<Log> {
        let topics = j
            .get("topics")
            .and_then(Json::as_array)
            .ok_or_else(|| decode("log without topics"))?
            .iter()
            .map(|t| {
                t.as_str()
                    .ok_or_else(|| decode("topic is not a string"))?
                    .parse::<B256>()
            })
            .collect::<Result<Vec<_>>>()?;
        let data = match j.get("data").and_then(Json::as_str) {
            Some(d) => hex_decode(d)?,
            None => Vec::new(),
        };
        Ok(Log {
            address: req_hex(j, "address")?,
            topics,
            data,
        })
    }
}

/// Knobs for [`Client::execute`].
#[derive(Debug, Clone)]
pub struct ExecOptions {
    /// Percent added to the gas estimate. Default 20.
    pub gas_headroom_percent: u64,
    /// Multiplier on `eth_gasPrice` for `maxFeePerGas`. Default 2.
    pub max_fee_multiplier: u128,
    /// Divisor on `eth_gasPrice` for `maxPriorityFeePerGas`. Default 10.
    pub priority_fee_divisor: u128,
    /// How long to wait for a receipt. Default 60 s.
    pub receipt_timeout: Duration,
    /// Receipt polling interval. Default 500 ms.
    pub poll_interval: Duration,
    /// Calldata cap per transaction for [`Client::execute_all`]. Default [`DEFAULT_MAX_CALLDATA`](crate::ops::DEFAULT_MAX_CALLDATA).
    pub max_calldata: usize,
}

impl Default for ExecOptions {
    /// The defaults listed on each field.
    fn default() -> Self {
        ExecOptions {
            gas_headroom_percent: 20,
            max_fee_multiplier: 2,
            priority_fee_divisor: 10,
            receipt_timeout: Duration::from_secs(60),
            poll_interval: Duration::from_millis(500),
            max_calldata: ops::DEFAULT_MAX_CALLDATA,
        }
    }
}

/// EIP-7825 per-transaction gas cap enforced by the node.
const MAX_TX_GAS: u64 = 1 << 24;

impl ExecOptions {
    /// Rejects values that would build a transaction that cannot be mined or that spins.
    fn validate(&self) -> Result<()> {
        let bad = |m: &str| Err(Error::InvalidOptions(m.into()));
        if self.max_fee_multiplier == 0 {
            return bad("max_fee_multiplier must be at least 1");
        }
        if self.priority_fee_divisor == 0 {
            return bad("priority_fee_divisor must be at least 1");
        }
        if self.poll_interval.is_zero() {
            return bad("poll_interval must be above zero");
        }
        if self.gas_headroom_percent > 100 {
            return bad("gas_headroom_percent must be at most 100");
        }
        Ok(())
    }
}

/// The outcome of one confirmed `execute` transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Executed {
    /// Transaction hash.
    pub tx_hash: TxHash,
    /// Block it landed in.
    pub block_number: u64,
    /// Keys of the entities created, in the order of the creates in the batch.
    pub keys: Vec<Key>,
    /// Gas used.
    pub gas_used: u64,
}

/// The Arkiv JSON-RPC client. Cheap to clone.
#[derive(Debug, Clone)]
pub struct Client {
    http: reqwest::Client,
    config: ClientConfig,
}

impl Client {
    /// Builds a client.
    pub fn new(config: ClientConfig) -> Result<Client> {
        let http = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|e| Error::Transport(e.to_string()))?;
        Ok(Client { http, config })
    }
    /// A client for the Rabdi testnet with default settings.
    pub fn rabdi() -> Result<Client> {
        Client::new(ClientConfig::default())
    }
    /// The config in force.
    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    /// One HTTP round trip, no retry. Maps HTTP and JSON-RPC failures to [`Error`].
    async fn post(&self, method: &str, params: &Json) -> Result<Json> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let resp = self
            .http
            .post(&self.config.rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;
        let status = resp.status();
        let retry_after = resp
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(Duration::from_secs);
        let text = resp
            .text()
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;
        if !status.is_success() {
            let body = text.chars().take(MAX_BODY_IN_ERROR).collect();
            return Err(Error::Status {
                status: status.as_u16(),
                body,
                retry_after,
            });
        }
        let mut reply: Json =
            serde_json::from_str(&text).map_err(|e| decode(format!("invalid JSON: {e}")))?;
        if let Some(err) = reply.get("error").filter(|e| !e.is_null()) {
            return Err(rpc_error(err));
        }
        match reply.get_mut("result") {
            Some(r) => Ok(r.take()),
            None => Err(decode("response has neither result nor error")),
        }
    }

    /// Delay before retry number `attempt` (0 based): `base * 2^attempt` capped, plus up to 25 %
    /// jitter, with `retry_after` winning when larger, all under `max_delay`.
    fn backoff(&self, attempt: u32, retry_after: Option<Duration>) -> Duration {
        let cfg = &self.config;
        let exp = cfg
            .base_delay
            .saturating_mul(1u32.checked_shl(attempt).unwrap_or(u32::MAX))
            .min(cfg.max_delay);
        let mut r = [0u8; 2];
        let _ = getrandom::getrandom(&mut r);
        let jitter = exp.mul_f64(f64::from(u16::from_be_bytes(r)) / f64::from(u16::MAX) * 0.25);
        let own = exp.saturating_add(jitter).min(cfg.max_delay);
        match retry_after {
            Some(ra) => own.max(ra.min(cfg.max_delay)),
            None => own,
        }
    }

    /// Raw JSON-RPC call with retry and backoff on [`Error::is_retryable`].
    /// Used for reads. Maps `error` objects to [`Error::Rpc`], or to
    /// [`Error::Query`] for codes -32001 to -32004.
    pub async fn call(&self, method: &str, params: Json) -> Result<Json> {
        let mut attempt = 0;
        loop {
            match self.post(method, &params).await {
                Err(e) if e.is_retryable() && attempt < self.config.max_retries => {
                    let hint = match &e {
                        Error::Status { retry_after, .. } => *retry_after,
                        _ => None,
                    };
                    tokio::time::sleep(self.backoff(attempt, hint)).await;
                    attempt += 1;
                }
                other => return other,
            }
        }
    }

    async fn call_quantity(&self, method: &str, params: Json) -> Result<u64> {
        num(&self.call(method, params).await?)
    }

    /// `eth_blockNumber`.
    pub async fn block_number(&self) -> Result<u64> {
        self.call_quantity("eth_blockNumber", json!([])).await
    }
    /// `eth_getTransactionCount(address, "pending")`.
    pub async fn nonce(&self, address: Address) -> Result<u64> {
        self.call_quantity(
            "eth_getTransactionCount",
            json!([address.to_string(), "pending"]),
        )
        .await
    }
    /// `eth_gasPrice` in wei.
    pub async fn gas_price(&self) -> Result<u128> {
        let v = self.call("eth_gasPrice", json!([])).await?;
        let s = v
            .as_str()
            .and_then(|s| s.strip_prefix("0x"))
            .ok_or_else(|| decode("gas price is not a quantity"))?;
        u128::from_str_radix(s, 16).map_err(|_| decode(format!("gas price out of range: {s}")))
    }
    /// `eth_estimateGas` for a call from `from` to `to` with `data`.
    pub async fn estimate_gas(&self, from: Address, to: Address, data: &[u8]) -> Result<u64> {
        let call =
            json!({ "from": from.to_string(), "to": to.to_string(), "data": hex_encode(data) });
        self.call_quantity("eth_estimateGas", json!([call])).await
    }
    /// The owner's entity-minting nonce, via `eth_call` of `entityNonce(address)` on the engine.
    /// Not the account's transaction nonce.
    pub async fn entity_nonce(&self, owner: Address) -> Result<u64> {
        let mut data = ENTITY_NONCE_SELECTOR.to_vec();
        data.extend_from_slice(&owner.to_word());
        let call = json!({ "to": ARKIV_ADDRESS.to_string(), "data": hex_encode(&data) });
        let v = self.call("eth_call", json!([call, "latest"])).await?;
        let bytes = hex_decode(
            v.as_str()
                .ok_or_else(|| decode("eth_call result is not a string"))?,
        )?;
        let word: [u8; 32] = bytes
            .try_into()
            .map_err(|_| decode("entityNonce result is not one word"))?;
        if word[..24].iter().any(|b| *b != 0) {
            return Err(decode("entityNonce does not fit in u64"));
        }
        let mut low = [0u8; 8];
        low.copy_from_slice(&word[24..]);
        Ok(u64::from_be_bytes(low))
    }
    /// `eth_getTransactionReceipt`; `None` while pending or unknown.
    pub async fn receipt(&self, hash: TxHash) -> Result<Option<Receipt>> {
        let v = self
            .call("eth_getTransactionReceipt", json!([hash.to_string()]))
            .await?;
        if v.is_null() {
            return Ok(None);
        }
        Receipt::from_json(&v).map(Some)
    }
    /// Polls [`receipt`](Client::receipt) every `poll` until it appears.
    /// Errors with [`Error::ReceiptTimeout`] after `timeout`.
    pub async fn wait_for_receipt(
        &self,
        hash: TxHash,
        timeout: Duration,
        poll: Duration,
    ) -> Result<Receipt> {
        let start = Instant::now();
        loop {
            if let Some(r) = self.receipt(hash).await? {
                return Ok(r);
            }
            let waited = start.elapsed();
            if waited >= timeout {
                return Err(Error::ReceiptTimeout { hash, waited });
            }
            tokio::time::sleep(poll.min(timeout - waited)).await;
        }
    }
    /// `eth_sendRawTransaction`. Never retried. An `nonce too low`, `insufficient funds`,
    /// `underpriced`, `gas too low`, `intrinsic gas`, `gas limit` or `exceeds` RPC error is [`Error::SendRefused`]
    /// (the nonce is free); every other failure, a transport error included, is
    /// [`Error::SendUnknown`] carrying the tx hash.
    pub async fn send_raw(&self, tx: &SignedTx) -> Result<TxHash> {
        match self
            .post("eth_sendRawTransaction", &json!([tx.raw_hex()]))
            .await
        {
            Ok(_) => Ok(tx.hash),
            Err(Error::Rpc { message, .. }) if is_refusal(&message) => {
                Err(Error::SendRefused(message))
            }
            Err(e) => Err(Error::SendUnknown {
                hash: tx.hash,
                reason: e.to_string(),
            }),
        }
    }
    /// Builds, signs, sends and confirms one `execute` transaction for `ops`:
    /// calldata, pending nonce, gas price, gas estimate plus headroom, sign, send, wait.
    /// Errors with [`Error::Reverted`] on status 0 and
    /// [`Error::KeyCountMismatch`] when the number of created
    /// keys differs from the number of `Op::Create` in `ops`. Does not split; the caller owns the cap
    /// (use [`execute_all`](Client::execute_all) for that).
    pub async fn execute(
        &self,
        signer: &Signer,
        ops: &[Op],
        options: &ExecOptions,
    ) -> Result<Executed> {
        options.validate()?;
        let data = ops::execute_calldata(ops)?;
        let from = signer.address();
        let nonce = self.nonce(from).await?;
        let gas_price = self.gas_price().await?;
        let estimate = self.estimate_gas(from, ARKIV_ADDRESS, &data).await?;
        if estimate > MAX_TX_GAS {
            return Err(Error::InvalidOptions(format!("gas estimate {estimate} is above the {MAX_TX_GAS} per-transaction cap; use smaller batches")));
        }
        let headroom =
            (u128::from(estimate) * u128::from(options.gas_headroom_percent) / 100) as u64;
        let max_fee = gas_price.saturating_mul(options.max_fee_multiplier);
        let tip = (gas_price / options.priority_fee_divisor).min(max_fee);
        let tx = Tx1559 {
            chain_id: self.config.chain_id,
            nonce,
            gas_limit: estimate.saturating_add(headroom).min(MAX_TX_GAS),
            max_fee_per_gas: max_fee,
            max_priority_fee_per_gas: tip,
            to: ARKIV_ADDRESS,
            value: 0,
            data,
        };
        let signed = signer.sign(&tx)?;
        let hash = self.send_raw(&signed).await?;
        let unconfirmed = |e: Error| match e {
            e @ Error::ReceiptTimeout { .. } => e,
            e => Error::Unconfirmed {
                hash,
                source: Box::new(e),
            },
        };
        let receipt = self
            .wait_for_receipt(hash, options.receipt_timeout, options.poll_interval)
            .await
            .map_err(unconfirmed)?;
        if !receipt.success {
            return Err(Error::Reverted(hash));
        }
        let keys = receipt.created_keys();
        let expected = ops.iter().filter(|o| matches!(o, Op::Create(_))).count();
        if keys.len() != expected {
            return Err(Error::KeyCountMismatch {
                hash,
                got: keys.len(),
                expected,
                keys,
            });
        }
        Ok(Executed {
            tx_hash: hash,
            block_number: receipt.block_number,
            keys,
            gas_used: receipt.gas_used,
        })
    }
    /// Splits `ops` with [`ops::split`] at `options.max_calldata` and runs
    /// [`execute`](Client::execute) for each part in order, one at a time (they share a nonce sequence).
    /// Stops at the first error. Batches are atomic per transaction, not across them: a failure
    /// after at least one confirmed batch is [`Error::PartialBatch`], carrying the confirmed
    /// [`Executed`] values so the caller never re-creates them. `max_calldata` bounds calldata
    /// only, not gas.
    pub async fn execute_all(
        &self,
        signer: &Signer,
        ops: Vec<Op>,
        options: &ExecOptions,
    ) -> Result<Vec<Executed>> {
        options.validate()?;
        let mut done = Vec::new();
        for (failed_at, part) in ops::split(ops, options.max_calldata)?
            .into_iter()
            .enumerate()
        {
            match self.execute(signer, &part, options).await {
                Ok(e) => done.push(e),
                Err(e) if done.is_empty() => return Err(e),
                Err(e) => {
                    return Err(Error::PartialBatch {
                        done,
                        failed_at,
                        source: Box::new(e),
                    })
                }
            }
        }
        Ok(done)
    }
    /// `arkiv_getEntity`. `None` when the node has no such entity.
    pub async fn get_entity(&self, key: Key) -> Result<Option<Entity>> {
        let v = self
            .call("arkiv_getEntity", json!([key.to_string()]))
            .await?;
        if v.is_null() {
            return Ok(None);
        }
        Entity::from_json(&v).map(Some)
    }
    /// `arkiv_query` with a query string. `limit` must be 1 to [`MAX_QUERY_LIMIT`]; it is sent as hex.
    pub async fn query_str(&self, query: &str, options: &QueryOptions) -> Result<Page> {
        if options.limit == 0 || options.limit > MAX_QUERY_LIMIT {
            return Err(Error::InvalidQuery(format!(
                "limit must be 1 to {MAX_QUERY_LIMIT}, got {}",
                options.limit
            )));
        }
        let mut opts = json!({ "select": options.select.to_json(), "limit": quantity(u64::from(options.limit)) });
        if let Some(o) = options.offset {
            opts["offset"] = quantity(o).into();
        }
        if let Some(c) = &options.cursor {
            opts["cursor"] = c.clone().into();
        }
        if let Some(b) = options.at_block {
            opts["atBlock"] = quantity(b).into();
        }
        let v = self.call("arkiv_query", json!([query, opts])).await?;
        let rows = v
            .get("data")
            .and_then(Json::as_array)
            .ok_or_else(|| decode("query result without data"))?;
        Ok(Page {
            entities: rows
                .iter()
                .map(Entity::from_json)
                .collect::<Result<Vec<_>>>()?,
            block_number: opt_num(v.get("blockNumber"))?.unwrap_or(0),
            cursor: v.get("cursor").and_then(Json::as_str).map(str::to_string),
        })
    }
    /// [`query_str`](Client::query_str) with a built [`Query`].
    pub async fn query(&self, query: &Query, options: &QueryOptions) -> Result<Page> {
        self.query_str(&query.build()?, options).await
    }
    /// Reads up to `max_rows` rows by paging with `offset`, `QueryOptions::limit` per page,
    /// stopping on a short page. Retries per the config on 429. Offsets are not tied to a block
    /// and a query has no stable order, so concurrent writes can duplicate or skip rows; use it
    /// on data that is not being written, or dedupe by key.
    pub async fn query_all(
        &self,
        query: &Query,
        options: &QueryOptions,
        max_rows: usize,
    ) -> Result<Vec<Entity>> {
        let text = query.build()?;
        let mut out: Vec<Entity> = Vec::new();
        let mut opts = QueryOptions {
            cursor: None,
            ..options.clone()
        };
        let mut offset = options.offset.unwrap_or(0);
        while out.len() < max_rows {
            let want = (max_rows - out.len()).min(options.limit as usize);
            opts.limit = want as u32;
            opts.offset = Some(offset);
            let page = self.query_str(&text, &opts).await?;
            let got = page.entities.len();
            out.extend(page.entities);
            if got < want {
                break;
            }
            offset += got as u64;
        }
        out.truncate(max_rows);
        Ok(out)
    }
}

fn rpc_error(err: &Json) -> Error {
    let code = err.get("code").and_then(Json::as_i64).unwrap_or(0);
    let message = err
        .get("message")
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_string();
    let kind = match code {
        -32001 => Some(QueryErrorKind::Parse),
        -32002 => Some(QueryErrorKind::Type),
        -32003 => Some(QueryErrorKind::Literal),
        -32004 => Some(QueryErrorKind::Limits),
        _ => None,
    };
    match kind {
        Some(kind) => Error::Query {
            kind,
            code,
            message,
        },
        None => {
            let data = err.get("data").filter(|d| !d.is_null()).map(|d| match d {
                Json::String(s) => s.clone(),
                other => other.to_string(),
            });
            Error::Rpc {
                code,
                message,
                data,
            }
        }
    }
}

fn is_refusal(message: &str) -> bool {
    let m = message.to_lowercase();
    [
        "nonce too low",
        "insufficient funds",
        "underpriced",
        "gas too low",
        "intrinsic gas",
        "gas limit",
        "exceeds",
    ]
    .iter()
    .any(|p| m.contains(p))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attributes::{Attribute, Decimal};
    use crate::ops::{Create, Expiry};
    use crate::query::{eq, Query};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    struct Reply {
        status: u16,
        headers: Vec<(&'static str, String)>,
        body: String,
    }
    impl Reply {
        fn ok(result: Json) -> Reply {
            Reply {
                status: 200,
                headers: vec![],
                body: json!({"jsonrpc":"2.0","id":1,"result":result}).to_string(),
            }
        }
        fn rpc_err(code: i64, message: &str) -> Reply {
            let b = json!({"jsonrpc":"2.0","id":1,"error":{"code":code,"message":message}});
            Reply {
                status: 200,
                headers: vec![],
                body: b.to_string(),
            }
        }
        fn status(status: u16, body: &str) -> Reply {
            Reply {
                status,
                headers: vec![],
                body: body.into(),
            }
        }
        fn header(mut self, k: &'static str, v: &str) -> Reply {
            self.headers.push((k, v.into()));
            self
        }
    }

    struct Mock {
        url: String,
        seen: Arc<Mutex<Vec<Json>>>,
    }
    impl Mock {
        /// Serves each request with `handler(method, params, nth_request)`. One thread per connection.
        fn start(handler: impl Fn(&str, &Json, usize) -> Reply + Send + Sync + 'static) -> Mock {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let seen = Arc::new(Mutex::new(Vec::<Json>::new()));
            let handler = Arc::new(handler);
            let seen2 = seen.clone();
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { continue };
                    let (handler, seen) = (handler.clone(), seen2.clone());
                    std::thread::spawn(move || {
                        let req = read_request(&mut stream);
                        let n = {
                            let mut s = seen.lock().unwrap();
                            s.push(req.clone());
                            s.len() - 1
                        };
                        let method = req["method"].as_str().unwrap_or("").to_string();
                        let r = handler(&method, &req["params"], n);
                        let mut out = format!(
                            "HTTP/1.1 {} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n",
                            r.status,
                            r.body.len()
                        );
                        for (k, v) in &r.headers {
                            out.push_str(&format!("{k}: {v}\r\n"));
                        }
                        out.push_str("\r\n");
                        out.push_str(&r.body);
                        let _ = stream.write_all(out.as_bytes());
                    });
                }
            });
            Mock { url, seen }
        }
        fn count(&self) -> usize {
            self.seen.lock().unwrap().len()
        }
        fn req(&self, i: usize) -> Json {
            self.seen.lock().unwrap()[i].clone()
        }
        fn methods(&self) -> Vec<String> {
            self.seen
                .lock()
                .unwrap()
                .iter()
                .map(|r| r["method"].as_str().unwrap().to_string())
                .collect()
        }
        fn client(&self) -> Client {
            Client::new(ClientConfig {
                rpc_url: self.url.clone(),
                chain_id: 7_794_095,
                timeout: Duration::from_secs(5),
                max_retries: 3,
                base_delay: Duration::from_millis(5),
                max_delay: Duration::from_millis(50),
            })
            .unwrap()
        }
    }

    fn read_request(stream: &mut std::net::TcpStream) -> Json {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = stream.read(&mut chunk).unwrap_or(0);
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&buf[..pos]).to_lowercase();
                let len = head
                    .lines()
                    .find_map(|l| {
                        l.strip_prefix("content-length:")
                            .map(|v| v.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                if buf.len() >= pos + 4 + len {
                    return serde_json::from_slice(&buf[pos + 4..pos + 4 + len])
                        .unwrap_or(Json::Null);
                }
            }
        }
        Json::Null
    }

    const KEY: &str = "0x59c5ddf06b5605e27833d0a02c8f6e96cebf9f334a6470b39e31eccb34895807";
    const CREATOR: &str = "0x0f05df479fcb23b2281e28813fb47e57e47d1bb7";
    const HARDHAT_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    fn entity_json(i: u64) -> Json {
        json!({
            "key": KEY, "owner": CREATOR, "creator": CREATOR,
            "createdAt": "0x10", "updatedAt": "0x11", "expiresAt": format!("{:#x}", 1000 + i),
            "creationFlags": {"readonly": true, "permissionlessExtension": false, "raw": 1},
            "attributes": [
                {"name": "arkiv.schema", "type": "str", "value": "strike.epochs"},
                {"name": "n", "type": "u64", "value": format!("{i:#x}")},
                {"name": "ok", "type": "bool", "value": true},
            ]
        })
    }

    fn key_n(n: u8) -> Key {
        B256([n; 32])
    }

    fn created_log(n: u8) -> Json {
        json!({"address": ARKIV_ADDRESS.to_string(),
               "topics": [entity_created_topic().to_string(), key_n(n).to_string(), Address([1; 20]).to_word().iter().fold(String::from("0x"), |a, b| a + &format!("{b:02x}"))],
               "data": "0x"})
    }

    fn receipt_json(status: &str, logs: Vec<Json>) -> Json {
        json!({"transactionHash": B256([9; 32]).to_string(), "blockNumber": "0x2a", "status": status,
               "gasUsed": "0x5208", "logs": logs})
    }

    // ---- config and small types ----

    #[test]
    fn default_config() {
        let c = ClientConfig::default();
        assert_eq!(c.rpc_url, RABDI_RPC);
        assert_eq!(c.chain_id, 7_794_095);
        assert_eq!(c.timeout, Duration::from_secs(20));
        assert_eq!(c.max_retries, 5);
        assert_eq!(c.base_delay, Duration::from_millis(300));
        assert_eq!(c.max_delay, Duration::from_secs(8));
    }

    #[test]
    fn rabdi_client_uses_defaults() {
        assert_eq!(Client::rabdi().unwrap().config().rpc_url, RABDI_RPC);
    }

    #[test]
    fn default_options() {
        let o = QueryOptions::default();
        assert_eq!(o.limit, 100);
        assert_eq!(o.select, Select::all());
        assert!(o.offset.is_none() && o.cursor.is_none() && o.at_block.is_none());
        let e = ExecOptions::default();
        assert_eq!(
            (
                e.gas_headroom_percent,
                e.max_fee_multiplier,
                e.priority_fee_divisor
            ),
            (20, 2, 10)
        );
        assert_eq!(e.receipt_timeout, Duration::from_secs(60));
        assert_eq!(e.poll_interval, Duration::from_millis(500));
        assert_eq!(e.max_calldata, crate::ops::DEFAULT_MAX_CALLDATA);
    }

    #[test]
    fn select_key_only() {
        let s = Select::key_only();
        assert!(s.key && !s.owner && !s.attributes && !s.creation_flags);
        assert_eq!(s.to_json()["key"], true);
        assert_eq!(s.to_json()["attributes"], false);
    }

    // ---- entity decoding ----

    #[test]
    fn entity_full_decode() {
        let e = Entity::from_json(&entity_json(7)).unwrap();
        assert_eq!(e.key.unwrap().to_string(), KEY);
        assert_eq!(e.owner.unwrap().to_string(), CREATOR);
        assert_eq!(e.created_at, Some(16));
        assert_eq!(e.updated_at, Some(17));
        assert_eq!(e.expires_at, Some(1007));
        assert_eq!(
            e.creation_flags,
            Some(CreationFlags {
                readonly: true,
                permissionless_extension: false
            })
        );
        assert_eq!(e.schema(), Some("strike.epochs"));
        assert_eq!(e.attr("n"), Some(&Value::U64(7)));
        assert_eq!(e.attr("ok"), Some(&Value::Bool(true)));
        assert_eq!(e.attr("missing"), None);
    }

    #[test]
    fn entity_partial_select() {
        let e = Entity::from_json(&json!({"key": KEY})).unwrap();
        assert!(
            e.key.is_some()
                && e.owner.is_none()
                && e.created_at.is_none()
                && e.creation_flags.is_none()
        );
        assert!(e.attributes.is_empty());
        let e = Entity::from_json(&json!({"key": KEY, "attributes": null})).unwrap();
        assert!(e.attributes.is_empty());
    }

    #[test]
    fn entity_numbers_as_json_numbers() {
        let e = Entity::from_json(&json!({"createdAt": 5, "expiresAt": "0xa"})).unwrap();
        assert_eq!((e.created_at, e.expires_at), (Some(5), Some(10)));
    }

    #[test]
    fn entity_flags_without_raw() {
        let e = Entity::from_json(
            &json!({"creationFlags": {"readonly": false, "permissionlessExtension": true}}),
        )
        .unwrap();
        assert_eq!(
            e.creation_flags,
            Some(CreationFlags {
                readonly: false,
                permissionless_extension: true
            })
        );
    }

    #[test]
    fn entity_decode_errors() {
        assert!(matches!(
            Entity::from_json(&json!("x")),
            Err(Error::Decode(_))
        ));
        assert!(Entity::from_json(&json!({"key": "0x12"})).is_err());
        assert!(Entity::from_json(&json!({"createdAt": "12"})).is_err());
        assert!(Entity::from_json(&json!({"createdAt": true})).is_err());
        assert!(Entity::from_json(&json!({"attributes": [{"name": "a"}]})).is_err());
        assert!(Entity::from_json(
            &json!({"attributes": [{"name": "a", "type": "nope", "value": 1}]})
        )
        .is_err());
        assert!(Entity::from_json(&json!({"attributes": {}})).is_err());
    }

    #[test]
    fn schema_ignores_non_string() {
        let e = Entity {
            key: None,
            owner: None,
            creator: None,
            created_at: None,
            updated_at: None,
            expires_at: None,
            creation_flags: None,
            attributes: vec![("arkiv.schema".into(), Value::U64(1))],
        };
        assert_eq!(e.schema(), None);
    }

    #[test]
    fn attr_returns_first_match() {
        let e = Entity {
            key: None,
            owner: None,
            creator: None,
            created_at: None,
            updated_at: None,
            expires_at: None,
            creation_flags: None,
            attributes: vec![("a".into(), Value::U64(1)), ("a".into(), Value::U64(2))],
        };
        assert_eq!(e.attr("a"), Some(&Value::U64(1)));
    }

    // ---- receipts ----

    #[test]
    fn receipt_decode_and_created_keys() {
        let other = json!({"address": Address([7; 20]).to_string(), "topics": [entity_created_topic().to_string(), key_n(5).to_string()], "data": "0x"});
        let wrong_topic = json!({"address": ARKIV_ADDRESS.to_string(), "topics": [B256([1; 32]).to_string(), key_n(6).to_string()], "data": "0x"});
        let no_topic1 = json!({"address": ARKIV_ADDRESS.to_string(), "topics": [entity_created_topic().to_string()], "data": "0x"});
        let r = Receipt::from_json(&receipt_json(
            "0x1",
            vec![
                created_log(1),
                other,
                wrong_topic,
                no_topic1,
                created_log(2),
            ],
        ))
        .unwrap();
        assert!(r.success);
        assert_eq!((r.block_number, r.gas_used), (42, 21000));
        assert_eq!(r.logs.len(), 5);
        assert_eq!(r.created_keys(), vec![key_n(1), key_n(2)]);
    }

    #[test]
    fn receipt_failed_status() {
        let r = Receipt::from_json(&receipt_json("0x0", vec![])).unwrap();
        assert!(!r.success);
        assert!(r.created_keys().is_empty());
    }

    #[test]
    fn receipt_missing_fields() {
        assert!(Receipt::from_json(&json!({})).is_err());
        let mut j = receipt_json("0x1", vec![]);
        j.as_object_mut().unwrap().remove("gasUsed");
        assert!(Receipt::from_json(&j).is_err());
        let mut j = receipt_json("0x1", vec![]);
        j["logs"] = json!(null);
        assert!(Receipt::from_json(&j).unwrap().logs.is_empty());
        let mut j = receipt_json("0x1", vec![]);
        j["logs"] = json!([{"address": ARKIV_ADDRESS.to_string()}]);
        assert!(Receipt::from_json(&j).is_err());
    }

    // ---- rpc error mapping ----

    #[test]
    fn rpc_error_codes() {
        for (code, kind) in [
            (-32001, QueryErrorKind::Parse),
            (-32002, QueryErrorKind::Type),
            (-32003, QueryErrorKind::Literal),
            (-32004, QueryErrorKind::Limits),
        ] {
            match rpc_error(&json!({"code": code, "message": "m"})) {
                Error::Query {
                    kind: k,
                    code: c,
                    message,
                } => assert_eq!((k, c, message.as_str()), (kind, code, "m")),
                other => panic!("{other:?}"),
            }
        }
        match rpc_error(&json!({"code": -32000, "message": "boom", "data": "0xdead"})) {
            Error::Rpc {
                code,
                message,
                data,
            } => {
                assert_eq!(
                    (code, message.as_str(), data.as_deref()),
                    (-32000, "boom", Some("0xdead"))
                )
            }
            other => panic!("{other:?}"),
        }
        match rpc_error(&json!({"code": 3, "message": "x", "data": {"a": 1}})) {
            Error::Rpc { data, .. } => assert_eq!(data.as_deref(), Some("{\"a\":1}")),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn refusal_matching() {
        for m in [
            "Nonce too low",
            "insufficient funds for gas",
            "transaction underpriced",
            "gas too low",
            "intrinsic gas too low",
        ] {
            assert!(is_refusal(m), "{m}");
        }
        assert!(!is_refusal("already known"));
        assert!(!is_refusal("execution reverted"));
    }

    // ---- backoff ----

    #[test]
    fn backoff_grows_and_caps() {
        let c = Client::new(ClientConfig {
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(1),
            ..ClientConfig::default()
        })
        .unwrap();
        for _ in 0..50 {
            let d0 = c.backoff(0, None);
            assert!(
                d0 >= Duration::from_millis(100) && d0 <= Duration::from_millis(125),
                "{d0:?}"
            );
            let d2 = c.backoff(2, None);
            assert!(
                d2 >= Duration::from_millis(400) && d2 <= Duration::from_millis(500),
                "{d2:?}"
            );
            assert!(c.backoff(10, None) <= Duration::from_secs(1));
            assert!(c.backoff(200, None) <= Duration::from_secs(1));
        }
    }

    #[test]
    fn backoff_honours_retry_after() {
        let c = Client::new(ClientConfig {
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(5),
            ..ClientConfig::default()
        })
        .unwrap();
        assert_eq!(
            c.backoff(0, Some(Duration::from_secs(3))),
            Duration::from_secs(3)
        );
        assert_eq!(
            c.backoff(0, Some(Duration::from_secs(60))),
            Duration::from_secs(5)
        );
        assert!(c.backoff(0, Some(Duration::from_millis(1))) >= Duration::from_millis(100));
    }

    // ---- call over HTTP ----

    #[tokio::test]
    async fn call_sends_jsonrpc_envelope() {
        let m = Mock::start(|_, _, _| Reply::ok(json!("0x1")));
        let v = m.client().call("eth_chainId", json!([])).await.unwrap();
        assert_eq!(v, json!("0x1"));
        let r = m.req(0);
        assert_eq!(r["jsonrpc"], "2.0");
        assert_eq!(r["method"], "eth_chainId");
        assert_eq!(r["params"], json!([]));
    }

    #[tokio::test]
    async fn call_returns_null_result() {
        let m = Mock::start(|_, _, _| Reply::ok(Json::Null));
        assert_eq!(m.client().call("x", json!([])).await.unwrap(), Json::Null);
    }

    #[tokio::test]
    async fn retries_429_then_succeeds() {
        let m = Mock::start(|_, _, n| {
            if n < 2 {
                Reply::status(429, "slow down")
            } else {
                Reply::ok(json!("0x5"))
            }
        });
        assert_eq!(m.client().block_number().await.unwrap(), 5);
        assert_eq!(m.count(), 3);
    }

    #[tokio::test]
    async fn retries_5xx() {
        let m = Mock::start(|_, _, n| {
            if n == 0 {
                Reply::status(503, "down")
            } else {
                Reply::ok(json!("0x5"))
            }
        });
        assert_eq!(m.client().block_number().await.unwrap(), 5);
        assert_eq!(m.count(), 2);
    }

    #[tokio::test]
    async fn gives_up_after_max_retries() {
        let m = Mock::start(|_, _, _| Reply::status(429, "no"));
        let err = m.client().block_number().await.unwrap_err();
        assert!(matches!(err, Error::Status { status: 429, .. }), "{err:?}");
        assert_eq!(m.count(), 4); // first try plus 3 retries
    }

    #[tokio::test]
    async fn zero_retries_means_one_attempt() {
        let m = Mock::start(|_, _, _| Reply::status(500, "no"));
        let mut cfg = m.client().config().clone();
        cfg.max_retries = 0;
        assert!(Client::new(cfg).unwrap().block_number().await.is_err());
        assert_eq!(m.count(), 1);
    }

    #[tokio::test]
    async fn does_not_retry_413_or_400() {
        for status in [413u16, 400, 404] {
            let m = Mock::start(move |_, _, _| Reply::status(status, "bad"));
            let err = m.client().block_number().await.unwrap_err();
            assert!(matches!(err, Error::Status { status: s, .. } if s == status));
            assert_eq!(m.count(), 1, "status {status}");
        }
    }

    #[tokio::test]
    async fn does_not_retry_rpc_errors() {
        let m = Mock::start(|_, _, _| Reply::rpc_err(-32000, "nope"));
        let err = m.client().block_number().await.unwrap_err();
        assert!(matches!(err, Error::Rpc { code: -32000, .. }));
        assert_eq!(m.count(), 1);
    }

    #[tokio::test]
    async fn status_error_carries_retry_after_and_truncated_body() {
        let big = "x".repeat(5000);
        let m = Mock::start(move |_, _, _| Reply::status(429, &big).header("retry-after", "7"));
        let mut cfg = m.client().config().clone();
        cfg.max_retries = 0;
        match Client::new(cfg).unwrap().block_number().await.unwrap_err() {
            Error::Status {
                status,
                body,
                retry_after,
            } => {
                assert_eq!(status, 429);
                assert_eq!(body.len(), MAX_BODY_IN_ERROR);
                assert_eq!(retry_after, Some(Duration::from_secs(7)));
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn retry_after_header_delays_the_retry() {
        let m = Mock::start(|_, _, n| {
            if n == 0 {
                Reply::status(429, "wait").header("retry-after", "1")
            } else {
                Reply::ok(json!("0x1"))
            }
        });
        let mut cfg = m.client().config().clone();
        cfg.max_delay = Duration::from_millis(300);
        let t = Instant::now();
        Client::new(cfg).unwrap().block_number().await.unwrap();
        let el = t.elapsed();
        assert!(el >= Duration::from_millis(290), "{el:?}"); // capped at max_delay, not 1 s
        assert!(el < Duration::from_millis(900), "{el:?}");
    }

    #[tokio::test]
    async fn transport_error_is_retried_then_reported() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        drop(l); // nothing listens: connection refused
        let c = Client::new(ClientConfig {
            rpc_url: url,
            max_retries: 2,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(5),
            ..ClientConfig::default()
        })
        .unwrap();
        assert!(matches!(
            c.block_number().await.unwrap_err(),
            Error::Transport(_)
        ));
    }

    #[tokio::test]
    async fn garbage_body_is_decode_error() {
        let m = Mock::start(|_, _, _| Reply::status(200, "<html>"));
        assert!(matches!(
            m.client().block_number().await.unwrap_err(),
            Error::Decode(_)
        ));
        let m = Mock::start(|_, _, _| Reply::status(200, "{\"jsonrpc\":\"2.0\",\"id\":1}"));
        assert!(matches!(
            m.client().block_number().await.unwrap_err(),
            Error::Decode(_)
        ));
    }

    // ---- simple methods ----

    #[tokio::test]
    async fn nonce_uses_pending() {
        let m = Mock::start(|_, _, _| Reply::ok(json!("0x1f")));
        let a: Address = CREATOR.parse().unwrap();
        assert_eq!(m.client().nonce(a).await.unwrap(), 31);
        assert_eq!(m.req(0)["method"], "eth_getTransactionCount");
        assert_eq!(m.req(0)["params"], json!([CREATOR, "pending"]));
    }

    #[tokio::test]
    async fn gas_price_parses_u128() {
        let m = Mock::start(|_, _, _| Reply::ok(json!("0xffffffffffffffffffff")));
        assert_eq!(m.client().gas_price().await.unwrap(), (1u128 << 80) - 1);
        let m = Mock::start(|_, _, _| Reply::ok(json!("12")));
        assert!(matches!(
            m.client().gas_price().await.unwrap_err(),
            Error::Decode(_)
        ));
    }

    #[tokio::test]
    async fn estimate_gas_params() {
        let m = Mock::start(|_, _, _| Reply::ok(json!("0x30d40")));
        let from: Address = CREATOR.parse().unwrap();
        let g = m
            .client()
            .estimate_gas(from, ARKIV_ADDRESS, &[0x49, 0x65, 0, 0x44])
            .await
            .unwrap();
        assert_eq!(g, 200_000);
        assert_eq!(
            m.req(0)["params"],
            json!([{"from": CREATOR, "to": ARKIV_ADDRESS.to_string(), "data": "0x49650044"}])
        );
    }

    #[tokio::test]
    async fn entity_nonce_calls_engine() {
        let m = Mock::start(|_, _, _| Reply::ok(json!(format!("0x{:064x}", 9))));
        let owner: Address = CREATOR.parse().unwrap();
        assert_eq!(m.client().entity_nonce(owner).await.unwrap(), 9);
        let r = m.req(0);
        assert_eq!(r["method"], "eth_call");
        assert_eq!(r["params"][0]["to"], ARKIV_ADDRESS.to_string());
        assert_eq!(
            r["params"][0]["data"],
            format!("0x36917bfd{}", "0".repeat(24) + &CREATOR[2..])
        );
        assert_eq!(r["params"][1], "latest");
    }

    #[tokio::test]
    async fn entity_nonce_rejects_bad_results() {
        let owner = Address([1; 20]);
        for bad in [
            json!("0x01"),
            json!(format!("0x01{}", "00".repeat(31))),
            json!(5),
        ] {
            let m = Mock::start(move |_, _, _| Reply::ok(bad.clone()));
            assert!(matches!(
                m.client().entity_nonce(owner).await.unwrap_err(),
                Error::Decode(_)
            ));
        }
    }

    // ---- receipts over HTTP ----

    #[tokio::test]
    async fn receipt_none_when_pending() {
        let m = Mock::start(|_, _, _| Reply::ok(Json::Null));
        assert!(m.client().receipt(B256([9; 32])).await.unwrap().is_none());
        assert_eq!(m.req(0)["params"], json!([B256([9; 32]).to_string()]));
    }

    #[tokio::test]
    async fn wait_for_receipt_polls_until_mined() {
        let m = Mock::start(|_, _, n| {
            if n < 3 {
                Reply::ok(Json::Null)
            } else {
                Reply::ok(receipt_json("0x1", vec![]))
            }
        });
        let r = m
            .client()
            .wait_for_receipt(
                B256([9; 32]),
                Duration::from_secs(5),
                Duration::from_millis(5),
            )
            .await
            .unwrap();
        assert_eq!(r.block_number, 42);
        assert_eq!(m.count(), 4);
    }

    #[tokio::test]
    async fn wait_for_receipt_times_out() {
        let m = Mock::start(|_, _, _| Reply::ok(Json::Null));
        let err = m
            .client()
            .wait_for_receipt(
                B256([9; 32]),
                Duration::from_millis(60),
                Duration::from_millis(10),
            )
            .await
            .unwrap_err();
        match err {
            Error::ReceiptTimeout { hash, waited } => {
                assert_eq!(hash, B256([9; 32]));
                assert!(waited >= Duration::from_millis(60));
            }
            other => panic!("{other:?}"),
        }
        assert!(m.count() >= 2);
    }

    #[tokio::test]
    async fn wait_for_receipt_zero_timeout_checks_once() {
        let m = Mock::start(|_, _, _| Reply::ok(Json::Null));
        let err = m
            .client()
            .wait_for_receipt(B256([9; 32]), Duration::ZERO, Duration::from_millis(10))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::ReceiptTimeout { .. }));
        assert_eq!(m.count(), 1);
    }

    // ---- send_raw ----

    fn signed() -> SignedTx {
        let s = Signer::from_hex(HARDHAT_KEY).unwrap();
        s.sign(&Tx1559 {
            chain_id: 7_794_095,
            nonce: 0,
            gas_limit: 21_000,
            max_fee_per_gas: 10,
            max_priority_fee_per_gas: 1,
            to: ARKIV_ADDRESS,
            value: 0,
            data: vec![],
        })
        .unwrap()
    }

    #[tokio::test]
    async fn send_raw_ok_sends_raw_hex_once() {
        let tx = signed();
        let m = Mock::start(|_, _, _| Reply::ok(json!("0xabc")));
        assert_eq!(m.client().send_raw(&tx).await.unwrap(), tx.hash);
        assert_eq!(m.req(0)["method"], "eth_sendRawTransaction");
        assert_eq!(m.req(0)["params"], json!([tx.raw_hex()]));
    }

    #[tokio::test]
    async fn send_raw_refusals() {
        for msg in [
            "nonce too low: next nonce 5",
            "insufficient funds for gas * price + value",
            "replacement transaction underpriced",
            "intrinsic gas too low",
        ] {
            let m = Mock::start(move |_, _, _| Reply::rpc_err(-32000, msg));
            let err = m.client().send_raw(&signed()).await.unwrap_err();
            assert!(
                matches!(err, Error::SendRefused(ref s) if s == msg),
                "{err:?}"
            );
            assert_eq!(m.count(), 1);
        }
    }

    #[tokio::test]
    async fn send_raw_unknown_rpc_error() {
        let tx = signed();
        let m = Mock::start(|_, _, _| Reply::rpc_err(-32000, "already known"));
        match m.client().send_raw(&tx).await.unwrap_err() {
            Error::SendUnknown { hash, reason } => {
                assert_eq!(hash, tx.hash);
                assert!(reason.contains("already known"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn send_raw_never_retries_429_or_5xx() {
        for status in [429u16, 502] {
            let tx = signed();
            let m = Mock::start(move |_, _, _| Reply::status(status, "x"));
            let err = m.client().send_raw(&tx).await.unwrap_err();
            assert!(matches!(err, Error::SendUnknown { hash, .. } if hash == tx.hash));
            assert_eq!(m.count(), 1);
        }
    }

    #[tokio::test]
    async fn send_raw_transport_failure_is_unknown() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        drop(l);
        let c = Client::new(ClientConfig {
            rpc_url: url,
            ..ClientConfig::default()
        })
        .unwrap();
        let tx = signed();
        assert!(
            matches!(c.send_raw(&tx).await.unwrap_err(), Error::SendUnknown { hash, .. } if hash == tx.hash)
        );
    }

    // ---- execute ----

    fn create_op() -> Op {
        Op::Create(
            Create::new(
                vec![Attribute::schema("demo.items").unwrap()],
                Expiry::blocks(100).unwrap(),
            )
            .unwrap(),
        )
    }

    /// A node that answers the whole write pipeline. `logs` and `status` shape the receipt.
    fn node(status: &'static str, logs: Vec<Json>) -> Mock {
        Mock::start(move |method, _, _| match method {
            "eth_getTransactionCount" => Reply::ok(json!("0x7")),
            "eth_gasPrice" => Reply::ok(json!("0x3e8")),
            "eth_estimateGas" => Reply::ok(json!("0x186a0")),
            "eth_sendRawTransaction" => Reply::ok(json!("0x00")),
            "eth_getTransactionReceipt" => Reply::ok(receipt_json(status, logs.clone())),
            other => Reply::rpc_err(-32601, other),
        })
    }

    fn fast() -> ExecOptions {
        ExecOptions {
            poll_interval: Duration::from_millis(5),
            receipt_timeout: Duration::from_secs(2),
            ..ExecOptions::default()
        }
    }

    #[tokio::test]
    async fn execute_pipeline_happy_path() {
        let m = node("0x1", vec![created_log(1), created_log(2)]);
        let signer = Signer::from_hex(HARDHAT_KEY).unwrap();
        let ops = vec![create_op(), create_op()];
        let done = m.client().execute(&signer, &ops, &fast()).await.unwrap();
        assert_eq!(done.keys, vec![key_n(1), key_n(2)]);
        assert_eq!((done.block_number, done.gas_used), (42, 21000));
        assert_eq!(
            m.methods(),
            [
                "eth_getTransactionCount",
                "eth_gasPrice",
                "eth_estimateGas",
                "eth_sendRawTransaction",
                "eth_getTransactionReceipt"
            ]
        );
        // the raw tx is what we would sign ourselves: nonce 7, gas 100000 + 20 %, fee 2x and 1/10 of 1000
        let calldata = crate::ops::execute_calldata(&ops).unwrap();
        let expected = signer
            .sign(&Tx1559 {
                chain_id: 7_794_095,
                nonce: 7,
                gas_limit: 120_000,
                max_fee_per_gas: 2000,
                max_priority_fee_per_gas: 100,
                to: ARKIV_ADDRESS,
                value: 0,
                data: calldata.clone(),
            })
            .unwrap();
        assert_eq!(m.req(3)["params"], json!([expected.raw_hex()]));
        assert_eq!(done.tx_hash, expected.hash);
        let est = m.req(2);
        assert_eq!(est["params"][0]["to"], ARKIV_ADDRESS.to_string());
        assert_eq!(est["params"][0]["from"], signer.address().to_string());
        assert_eq!(est["params"][0]["data"], hex_encode(&calldata));
        assert_eq!(m.req(0)["params"][1], "pending");
    }

    #[tokio::test]
    async fn execute_custom_fee_options() {
        let m = node("0x1", vec![created_log(1)]);
        let signer = Signer::from_hex(HARDHAT_KEY).unwrap();
        let opts = ExecOptions {
            gas_headroom_percent: 0,
            max_fee_multiplier: 3,
            priority_fee_divisor: 4,
            ..fast()
        };
        let ops = vec![create_op()];
        m.client().execute(&signer, &ops, &opts).await.unwrap();
        let expected = signer
            .sign(&Tx1559 {
                chain_id: 7_794_095,
                nonce: 7,
                gas_limit: 100_000,
                max_fee_per_gas: 3000,
                max_priority_fee_per_gas: 250,
                to: ARKIV_ADDRESS,
                value: 0,
                data: crate::ops::execute_calldata(&ops).unwrap(),
            })
            .unwrap();
        assert_eq!(m.req(3)["params"], json!([expected.raw_hex()]));
    }

    #[tokio::test]
    async fn execute_rejects_unworkable_options() {
        let m = node("0x1", vec![created_log(1)]);
        let signer = Signer::from_hex(HARDHAT_KEY).unwrap();
        for opts in [
            ExecOptions {
                max_fee_multiplier: 0,
                ..fast()
            },
            ExecOptions {
                priority_fee_divisor: 0,
                ..fast()
            },
            ExecOptions {
                poll_interval: Duration::ZERO,
                ..fast()
            },
            ExecOptions {
                gas_headroom_percent: u64::MAX,
                ..fast()
            },
        ] {
            let err = m
                .client()
                .execute(&signer, &[create_op()], &opts)
                .await
                .unwrap_err();
            assert!(matches!(err, Error::InvalidOptions(_)), "{err:?}");
        }
        assert_eq!(m.count(), 0);
    }

    #[tokio::test]
    async fn execute_clamps_gas_to_cap() {
        let m = Mock::start(|method, _, _| match method {
            "eth_getTransactionCount" => Reply::ok(json!("0x7")),
            "eth_gasPrice" => Reply::ok(json!("0x3e8")),
            "eth_estimateGas" => Reply::ok(json!(format!("{:#x}", (1u64 << 24) - 10))),
            "eth_sendRawTransaction" => Reply::ok(json!("0x00")),
            _ => Reply::ok(Json::Null),
        });
        let signer = Signer::from_hex(HARDHAT_KEY).unwrap();
        let ops = vec![create_op()];
        let _ = m
            .client()
            .execute(
                &signer,
                &ops,
                &ExecOptions {
                    receipt_timeout: Duration::ZERO,
                    ..fast()
                },
            )
            .await;
        let expected = signer
            .sign(&Tx1559 {
                chain_id: 7_794_095,
                nonce: 7,
                gas_limit: 1 << 24,
                max_fee_per_gas: 2000,
                max_priority_fee_per_gas: 100,
                to: ARKIV_ADDRESS,
                value: 0,
                data: crate::ops::execute_calldata(&ops).unwrap(),
            })
            .unwrap();
        assert_eq!(m.req(3)["params"], json!([expected.raw_hex()]));
    }

    #[tokio::test]
    async fn execute_estimate_above_cap_fails_before_send() {
        let m = Mock::start(|method, _, _| match method {
            "eth_getTransactionCount" => Reply::ok(json!("0x7")),
            "eth_gasPrice" => Reply::ok(json!("0x3e8")),
            _ => Reply::ok(json!(format!("{:#x}", (1u64 << 24) + 1))),
        });
        let signer = Signer::from_hex(HARDHAT_KEY).unwrap();
        let err = m
            .client()
            .execute(&signer, &[create_op()], &fast())
            .await
            .unwrap_err();
        assert!(matches!(err, Error::InvalidOptions(_)), "{err:?}");
        assert!(!m.methods().contains(&"eth_sendRawTransaction".to_string()));
    }

    fn sent_then(receipt: fn() -> Reply) -> Mock {
        Mock::start(move |method, _, _| match method {
            "eth_getTransactionCount" => Reply::ok(json!("0x7")),
            "eth_gasPrice" => Reply::ok(json!("0x3e8")),
            "eth_estimateGas" => Reply::ok(json!("0x186a0")),
            "eth_sendRawTransaction" => Reply::ok(json!("0x00")),
            _ => receipt(),
        })
    }

    #[tokio::test]
    async fn execute_receipt_429_keeps_hash() {
        let m = sent_then(|| Reply::status(429, "slow down"));
        let signer = Signer::from_hex(HARDHAT_KEY).unwrap();
        let err = m
            .client()
            .execute(&signer, &[create_op()], &fast())
            .await
            .unwrap_err();
        let Error::Unconfirmed { hash, source } = err else {
            panic!("{err:?}")
        };
        assert!(matches!(*source, Error::Status { status: 429, .. }));
        assert_ne!(hash, B256([0; 32]));
    }

    #[tokio::test]
    async fn execute_garbage_receipt_keeps_hash() {
        let m = sent_then(|| Reply::ok(json!({"nonsense": true})));
        let signer = Signer::from_hex(HARDHAT_KEY).unwrap();
        let err = m
            .client()
            .execute(&signer, &[create_op()], &fast())
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Unconfirmed { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn execute_empty_batch_fails_before_network() {
        let m = node("0x1", vec![]);
        let signer = Signer::from_hex(HARDHAT_KEY).unwrap();
        let err = m.client().execute(&signer, &[], &fast()).await.unwrap_err();
        assert!(matches!(err, Error::EmptyBatch));
        assert_eq!(m.count(), 0);
    }

    #[tokio::test]
    async fn execute_reverted() {
        let m = node("0x0", vec![]);
        let signer = Signer::from_hex(HARDHAT_KEY).unwrap();
        let err = m
            .client()
            .execute(&signer, &[create_op()], &fast())
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Reverted(_)), "{err:?}");
    }

    #[tokio::test]
    async fn execute_key_count_mismatch() {
        let m = node("0x1", vec![created_log(1)]);
        let signer = Signer::from_hex(HARDHAT_KEY).unwrap();
        let err = m
            .client()
            .execute(&signer, &[create_op(), create_op()], &fast())
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::KeyCountMismatch { got: 1, expected: 2, keys, .. } if keys.len() == 1),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn execute_non_create_ops_expect_no_keys() {
        let m = node("0x1", vec![]);
        let signer = Signer::from_hex(HARDHAT_KEY).unwrap();
        let ops = vec![Op::Delete { key: key_n(3) }];
        let done = m.client().execute(&signer, &ops, &fast()).await.unwrap();
        assert!(done.keys.is_empty());
    }

    #[tokio::test]
    async fn execute_send_refused_propagates() {
        let m = Mock::start(|method, _, _| match method {
            "eth_getTransactionCount" => Reply::ok(json!("0x7")),
            "eth_gasPrice" => Reply::ok(json!("0x3e8")),
            "eth_estimateGas" => Reply::ok(json!("0x186a0")),
            _ => Reply::rpc_err(-32000, "nonce too low"),
        });
        let signer = Signer::from_hex(HARDHAT_KEY).unwrap();
        let err = m
            .client()
            .execute(&signer, &[create_op()], &fast())
            .await
            .unwrap_err();
        assert!(matches!(err, Error::SendRefused(_)));
        assert_eq!(m.count(), 4);
    }

    #[tokio::test]
    async fn execute_estimate_failure_stops_before_send() {
        let m = Mock::start(|method, _, _| match method {
            "eth_getTransactionCount" => Reply::ok(json!("0x7")),
            "eth_gasPrice" => Reply::ok(json!("0x3e8")),
            _ => Reply::rpc_err(3, "execution reverted"),
        });
        let signer = Signer::from_hex(HARDHAT_KEY).unwrap();
        let err = m
            .client()
            .execute(&signer, &[create_op()], &fast())
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Rpc { code: 3, .. }));
        assert!(!m.methods().contains(&"eth_sendRawTransaction".to_string()));
    }

    #[tokio::test]
    async fn execute_receipt_timeout() {
        let m = Mock::start(|method, _, _| match method {
            "eth_getTransactionCount" => Reply::ok(json!("0x7")),
            "eth_gasPrice" => Reply::ok(json!("0x3e8")),
            "eth_estimateGas" => Reply::ok(json!("0x186a0")),
            "eth_sendRawTransaction" => Reply::ok(json!("0x00")),
            _ => Reply::ok(Json::Null),
        });
        let signer = Signer::from_hex(HARDHAT_KEY).unwrap();
        let opts = ExecOptions {
            receipt_timeout: Duration::from_millis(40),
            poll_interval: Duration::from_millis(5),
            ..ExecOptions::default()
        };
        let err = m
            .client()
            .execute(&signer, &[create_op()], &opts)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::ReceiptTimeout { .. }));
    }

    #[tokio::test]
    async fn execute_all_splits_and_runs_in_order() {
        let m = node("0x1", vec![created_log(1)]);
        let signer = Signer::from_hex(HARDHAT_KEY).unwrap();
        let one = create_op().calldata_len().unwrap();
        // room for exactly one create per transaction
        let opts = ExecOptions {
            max_calldata: 4 + 64 + one,
            ..fast()
        };
        let done = m
            .client()
            .execute_all(&signer, vec![create_op(), create_op(), create_op()], &opts)
            .await
            .unwrap();
        assert_eq!(done.len(), 3);
        let sends = m
            .methods()
            .iter()
            .filter(|x| *x == "eth_sendRawTransaction")
            .count();
        assert_eq!(sends, 3);
    }

    #[tokio::test]
    async fn execute_all_single_batch_when_small() {
        let m = node("0x1", vec![created_log(1), created_log(2)]);
        let signer = Signer::from_hex(HARDHAT_KEY).unwrap();
        let done = m
            .client()
            .execute_all(&signer, vec![create_op(), create_op()], &fast())
            .await
            .unwrap();
        assert_eq!(done.len(), 1);
        assert_eq!(done[0].keys.len(), 2);
    }

    #[tokio::test]
    async fn execute_all_stops_at_first_error() {
        let m = node("0x0", vec![]);
        let signer = Signer::from_hex(HARDHAT_KEY).unwrap();
        let one = create_op().calldata_len().unwrap();
        let opts = ExecOptions {
            max_calldata: 4 + 64 + one,
            ..fast()
        };
        let err = m
            .client()
            .execute_all(&signer, vec![create_op(), create_op()], &opts)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Reverted(_)), "{err:?}");
        let sends = m
            .methods()
            .iter()
            .filter(|x| *x == "eth_sendRawTransaction")
            .count();
        assert_eq!(sends, 1);
    }

    #[tokio::test]
    async fn execute_all_empty_is_ok_and_idle() {
        let m = node("0x1", vec![]);
        let signer = Signer::from_hex(HARDHAT_KEY).unwrap();
        let r = m.client().execute_all(&signer, vec![], &fast()).await;
        assert_eq!(r.unwrap(), Vec::<Executed>::new());
        assert_eq!(m.count(), 0);
    }

    #[tokio::test]
    async fn execute_all_keeps_progress_on_later_failure() {
        // first receipt succeeds, every later one reverts
        let m = Mock::start(|method, _, n| match method {
            "eth_getTransactionCount" => Reply::ok(json!("0x7")),
            "eth_gasPrice" => Reply::ok(json!("0x3e8")),
            "eth_estimateGas" => Reply::ok(json!("0x186a0")),
            "eth_sendRawTransaction" => Reply::ok(json!("0x00")),
            _ => Reply::ok(receipt_json(
                if n < 6 { "0x1" } else { "0x0" },
                vec![created_log(1)],
            )),
        });
        let signer = Signer::from_hex(HARDHAT_KEY).unwrap();
        let one = create_op().calldata_len().unwrap();
        let opts = ExecOptions {
            max_calldata: 4 + 64 + one,
            ..fast()
        };
        let err = m
            .client()
            .execute_all(&signer, vec![create_op(), create_op(), create_op()], &opts)
            .await
            .unwrap_err();
        match err {
            Error::PartialBatch {
                done,
                failed_at,
                source,
            } => {
                assert_eq!((done.len(), failed_at), (1, 1));
                assert_eq!(done[0].keys.len(), 1);
                assert!(matches!(*source, Error::Reverted(_)));
            }
            other => panic!("{other:?}"),
        }
    }

    // ---- get_entity ----

    #[tokio::test]
    async fn get_entity_found() {
        let m = Mock::start(|_, _, _| Reply::ok(entity_json(3)));
        let k: Key = KEY.parse().unwrap();
        let e = m.client().get_entity(k).await.unwrap().unwrap();
        assert_eq!(e.attr("n"), Some(&Value::U64(3)));
        assert_eq!(m.req(0)["method"], "arkiv_getEntity");
        assert_eq!(m.req(0)["params"], json!([KEY]));
    }

    #[tokio::test]
    async fn get_entity_absent_is_none() {
        let m = Mock::start(|_, _, _| Reply::ok(Json::Null));
        assert!(m
            .client()
            .get_entity(B256([1; 32]))
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn get_entity_retries_429() {
        let m = Mock::start(|_, _, n| {
            if n == 0 {
                Reply::status(429, "x")
            } else {
                Reply::ok(entity_json(1))
            }
        });
        assert!(m
            .client()
            .get_entity(B256([1; 32]))
            .await
            .unwrap()
            .is_some());
        assert_eq!(m.count(), 2);
    }

    // ---- query ----

    fn paged(total: usize) -> Mock {
        Mock::start(move |_, params, _| {
            let off = u64::from_str_radix(
                params[1]["offset"]
                    .as_str()
                    .unwrap()
                    .trim_start_matches("0x"),
                16,
            )
            .unwrap() as usize;
            let lim = u64::from_str_radix(
                params[1]["limit"]
                    .as_str()
                    .unwrap()
                    .trim_start_matches("0x"),
                16,
            )
            .unwrap() as usize;
            let rows = (off..total.min(off + lim))
                .map(|i| entity_json(i as u64))
                .collect();
            Reply::ok(page_json(rows, None))
        })
    }

    #[tokio::test]
    async fn query_all_stops_on_short_page() {
        let m = paged(5);
        let o = QueryOptions {
            limit: 2,
            ..Default::default()
        };
        let rows = m
            .client()
            .query_all(&Query::new().schema("x"), &o, 100)
            .await
            .unwrap();
        assert_eq!(rows.len(), 5);
        assert_eq!(m.count(), 3);
        let offs: Vec<_> = (0..3)
            .map(|i| m.req(i)["params"][1]["offset"].clone())
            .collect();
        assert_eq!(offs, vec![json!("0x0"), json!("0x2"), json!("0x4")]);
    }

    #[tokio::test]
    async fn query_all_respects_max_rows() {
        let m = paged(50);
        let o = QueryOptions {
            limit: 4,
            ..Default::default()
        };
        let rows = m
            .client()
            .query_all(&Query::new().schema("x"), &o, 6)
            .await
            .unwrap();
        assert_eq!(rows.len(), 6);
        assert_eq!(m.count(), 2);
        assert_eq!(m.req(1)["params"][1]["limit"], json!("0x2"));
    }

    #[test]
    fn flags_above_255_are_a_decode_error() {
        assert!(parse_flags(&json!({"raw": 256})).is_err());
        assert!(parse_flags(&json!({"raw": 1})).is_ok());
    }

    fn page_json(rows: Vec<Json>, cursor: Option<&str>) -> Json {
        let mut p = json!({"data": rows, "blockNumber": "0x99"});
        if let Some(c) = cursor {
            p["cursor"] = c.into();
        }
        p
    }

    #[tokio::test]
    async fn query_str_params_and_page() {
        let m = Mock::start(|_, _, _| {
            Reply::ok(page_json(
                vec![entity_json(1), entity_json(2)],
                Some("0xc0ffee"),
            ))
        });
        let opts = QueryOptions {
            limit: 25,
            offset: Some(50),
            cursor: Some("0xabc".into()),
            at_block: Some(255),
            ..Default::default()
        };
        let page = m
            .client()
            .query_str("arkiv.schema = str('x')", &opts)
            .await
            .unwrap();
        assert_eq!(page.entities.len(), 2);
        assert_eq!(page.block_number, 0x99);
        assert_eq!(page.cursor.as_deref(), Some("0xc0ffee"));
        let r = m.req(0);
        assert_eq!(r["method"], "arkiv_query");
        assert_eq!(r["params"][0], "arkiv.schema = str('x')");
        let o = &r["params"][1];
        assert_eq!(o["limit"], "0x19");
        assert_eq!(o["offset"], "0x32");
        assert_eq!(o["cursor"], "0xabc");
        assert_eq!(o["atBlock"], "0xff");
        assert_eq!(o["select"]["attributes"], true);
        assert_eq!(o["select"]["createdAt"], true);
    }

    #[tokio::test]
    async fn query_str_omits_unset_options() {
        let m = Mock::start(|_, _, _| Reply::ok(page_json(vec![], None)));
        let page = m
            .client()
            .query_str("a = u64(1)", &QueryOptions::default())
            .await
            .unwrap();
        assert!(page.entities.is_empty() && page.cursor.is_none());
        let o = m.req(0)["params"][1].clone();
        assert_eq!(o["limit"], "0x64");
        for k in ["offset", "cursor", "atBlock"] {
            assert!(o.get(k).is_none(), "{k}");
        }
    }

    #[tokio::test]
    async fn query_limit_validated_before_network() {
        let m = Mock::start(|_, _, _| Reply::ok(page_json(vec![], None)));
        for limit in [0u32, 101, 1000] {
            let opts = QueryOptions {
                limit,
                ..Default::default()
            };
            let err = m.client().query_str("a = u64(1)", &opts).await.unwrap_err();
            assert!(matches!(err, Error::InvalidQuery(_)), "{limit}");
        }
        assert_eq!(m.count(), 0);
        for limit in [1u32, 100] {
            let opts = QueryOptions {
                limit,
                ..Default::default()
            };
            m.client().query_str("a = u64(1)", &opts).await.unwrap();
        }
    }

    #[tokio::test]
    async fn query_key_only_select() {
        let m = Mock::start(|_, _, _| Reply::ok(page_json(vec![json!({"key": KEY})], None)));
        let opts = QueryOptions {
            select: Select::key_only(),
            ..Default::default()
        };
        let page = m.client().query_str("a = u64(1)", &opts).await.unwrap();
        assert!(page.entities[0].key.is_some());
        assert_eq!(m.req(0)["params"][1]["select"]["owner"], false);
    }

    #[tokio::test]
    async fn query_builds_string_from_builder() {
        let m = Mock::start(|_, _, _| Reply::ok(page_json(vec![], None)));
        let creator: Address = CREATOR.parse().unwrap();
        let q = Query::new()
            .schema("strike.epochs")
            .creator(creator)
            .filter(eq("asset", Value::Str("BTC".into())));
        m.client()
            .query(&q, &QueryOptions::default())
            .await
            .unwrap();
        assert_eq!(
            m.req(0)["params"][0],
            format!("arkiv.schema = str('strike.epochs') AND $creator = addr({CREATOR}) AND asset = str('BTC')")
        );
    }

    #[tokio::test]
    async fn query_invalid_builder_never_hits_network() {
        let m = Mock::start(|_, _, _| Reply::ok(page_json(vec![], None)));
        let err = m
            .client()
            .query(&Query::new(), &QueryOptions::default())
            .await
            .unwrap_err();
        assert!(matches!(err, Error::InvalidQuery(_)));
        assert_eq!(m.count(), 0);
    }

    #[tokio::test]
    async fn query_error_codes_surface() {
        let m = Mock::start(|_, _, _| Reply::rpc_err(-32001, "parse error at 3"));
        let err = m
            .client()
            .query_str("???", &QueryOptions::default())
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Query {
                kind: QueryErrorKind::Parse,
                code: -32001,
                ..
            }
        ));
        assert_eq!(m.count(), 1);
    }

    #[tokio::test]
    async fn query_missing_data_is_decode_error() {
        let m = Mock::start(|_, _, _| Reply::ok(json!({"blockNumber": "0x1"})));
        assert!(matches!(
            m.client()
                .query_str("a = u64(1)", &QueryOptions::default())
                .await
                .unwrap_err(),
            Error::Decode(_)
        ));
    }

    #[tokio::test]
    async fn query_missing_block_number_defaults_to_zero() {
        let m = Mock::start(|_, _, _| Reply::ok(json!({"data": []})));
        assert_eq!(
            m.client()
                .query_str("a = u64(1)", &QueryOptions::default())
                .await
                .unwrap()
                .block_number,
            0
        );
    }

    #[tokio::test]
    async fn query_retries_429() {
        let m = Mock::start(|_, _, n| {
            if n < 2 {
                Reply::status(429, "x")
            } else {
                Reply::ok(page_json(vec![entity_json(1)], None))
            }
        });
        let page = m
            .client()
            .query_str("a = u64(1)", &QueryOptions::default())
            .await
            .unwrap();
        assert_eq!(page.entities.len(), 1);
        assert_eq!(m.count(), 3);
    }

    // ---- query_all ----

    /// A node with `total` rows; honours limit and offset.
    fn table(total: u64) -> Mock {
        Mock::start(move |_, params, _| {
            let o = &params[1];
            let limit = parse_quantity(o["limit"].as_str().unwrap()).unwrap();
            let offset = o
                .get("offset")
                .and_then(Json::as_str)
                .map(|s| parse_quantity(s).unwrap())
                .unwrap_or(0);
            let rows = (offset..total.min(offset + limit))
                .map(entity_json)
                .collect();
            Reply::ok(page_json(rows, None))
        })
    }

    fn q() -> Query {
        Query::new().schema("x")
    }

    #[tokio::test]
    async fn query_all_pages_until_short_page() {
        let m = table(250);
        let rows = m
            .client()
            .query_all(&q(), &QueryOptions::default(), 10_000)
            .await
            .unwrap();
        assert_eq!(rows.len(), 250);
        assert_eq!(rows[249].attr("n"), Some(&Value::U64(249)));
        assert_eq!(m.count(), 3); // 100, 100, 50
        assert_eq!(m.req(1)["params"][1]["offset"], "0x64");
        assert_eq!(m.req(2)["params"][1]["offset"], "0xc8");
    }

    #[tokio::test]
    async fn query_all_exact_multiple_costs_one_extra_empty_page() {
        let m = table(200);
        let rows = m
            .client()
            .query_all(&q(), &QueryOptions::default(), 10_000)
            .await
            .unwrap();
        assert_eq!(rows.len(), 200);
        assert_eq!(m.count(), 3);
    }

    #[tokio::test]
    async fn query_all_truncates_last_page_limit() {
        let m = table(1000);
        let rows = m
            .client()
            .query_all(&q(), &QueryOptions::default(), 150)
            .await
            .unwrap();
        assert_eq!(rows.len(), 150);
        assert_eq!(m.count(), 2);
        assert_eq!(m.req(1)["params"][1]["limit"], "0x32"); // asks only for the 50 still needed
    }

    #[tokio::test]
    async fn query_all_max_rows_zero_is_free() {
        let m = table(10);
        assert!(m
            .client()
            .query_all(&q(), &QueryOptions::default(), 0)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(m.count(), 0);
    }

    #[tokio::test]
    async fn query_all_small_page_size() {
        let m = table(7);
        let opts = QueryOptions {
            limit: 3,
            ..Default::default()
        };
        let rows = m.client().query_all(&q(), &opts, 100).await.unwrap();
        assert_eq!(rows.len(), 7);
        assert_eq!(m.count(), 3);
    }

    #[tokio::test]
    async fn query_all_starts_at_given_offset_and_drops_cursor() {
        let m = table(10);
        let opts = QueryOptions {
            offset: Some(4),
            cursor: Some("0xdead".into()),
            ..Default::default()
        };
        let rows = m.client().query_all(&q(), &opts, 100).await.unwrap();
        assert_eq!(rows.len(), 6);
        assert_eq!(rows[0].attr("n"), Some(&Value::U64(4)));
        assert!(m.req(0)["params"][1].get("cursor").is_none());
    }

    #[tokio::test]
    async fn query_all_empty_table() {
        let m = table(0);
        assert!(m
            .client()
            .query_all(&q(), &QueryOptions::default(), 100)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(m.count(), 1);
    }

    #[tokio::test]
    async fn query_all_rides_through_429() {
        let m = Mock::start(|_, params, n| {
            if n == 1 {
                return Reply::status(429, "burst");
            }
            let offset = params[1]
                .get("offset")
                .and_then(Json::as_str)
                .map(|s| parse_quantity(s).unwrap())
                .unwrap_or(0);
            let rows = if offset == 0 {
                (0..2).map(entity_json).collect()
            } else {
                vec![]
            };
            Reply::ok(page_json(rows, None))
        });
        let opts = QueryOptions {
            limit: 2,
            ..Default::default()
        };
        let rows = m.client().query_all(&q(), &opts, 100).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(m.count(), 3);
    }

    #[tokio::test]
    async fn query_all_error_aborts() {
        let m = Mock::start(|_, _, _| Reply::rpc_err(-32004, "too many"));
        let err = m
            .client()
            .query_all(&q(), &QueryOptions::default(), 100)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Query {
                kind: QueryErrorKind::Limits,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn query_all_bad_limit_rejected() {
        let m = table(10);
        let opts = QueryOptions {
            limit: 0,
            ..Default::default()
        };
        assert!(m.client().query_all(&q(), &opts, 5).await.is_err());
        assert_eq!(m.count(), 0);
    }

    #[tokio::test]
    async fn clone_shares_config() {
        let m = Mock::start(|_, _, _| Reply::ok(json!("0x3")));
        let c = m.client();
        let d = c.clone();
        assert_eq!(d.block_number().await.unwrap(), 3);
        assert_eq!(c.config().rpc_url, d.config().rpc_url);
    }

    #[test]
    fn decimal_attr_decodes_via_entity() {
        let e = Entity::from_json(
            &json!({"attributes": [{"name": "p", "type": "dec", "value": "1.5"}]}),
        )
        .unwrap();
        assert_eq!(
            e.attr("p"),
            Some(&Value::Dec(Decimal::parse("1.5").unwrap()))
        );
    }
}
