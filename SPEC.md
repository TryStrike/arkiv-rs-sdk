# arkiv-rs-sdk specification

Rust SDK for Arkiv. Package `arkiv-rs-sdk`, library `arkiv`, MIT. Sources compared: the official
`@arkiv-network/sdk` 1.0.1 (TypeScript, viem based), Strike's production encoder
(`backend/crates/core/src/arkiv.rs`, `eth.rs`) and the live Rabdi RPC.

## 1. Findings

Strike's hand-rolled Rust encoder and the official SDK agree byte for byte on everything Strike uses
(create, attributes, execute). Differences and facts worth keeping:

| topic | official SDK | Strike | arkiv-rs-sdk |
|---|---|---|---|
| expiry on create | `expiresAt` (absolute) and `minLifetime` (blocks); engine takes the later | `expiresAt = 0`, `minLifetime = 7_800_000` | both fields exposed via `Expiry` |
| creation flags | bit0 readonly, bit1 permissionless extension | readonly only | both bits |
| attribute order | strictly ascending by 32-byte name word; engine requires it | sorted by raw name bytes (same order) | sort by name word |
| attribute count | 32 max, the schema tag counts | not checked | checked |
| name grammar | `^[A-Za-z][A-Za-z0-9._-]*$`, max 32 bytes, no `--`, not a query keyword | not checked | checked |
| salt | random `uint128` per create | random (uuid) | random `uint128`, fixed at `Create::new` |
| key | `keccak256(chainId ++ registry ++ owner ++ nonce ++ salt)`, predictable via `entityNonce(owner)` | read back from `EntityCreated` log topic 1 | both |
| other ops | patch, extend, transfer, delete have full ABIs | create only | all five, see 3.4 |
| paging | `offset` (hex) and `limit` (max 100) | no paging (cursor fails across blocks) | `offset`; verified live that offset paging works where `cursor` does not |
| gas | estimate + 25 % | estimate + 20 %, `maxFee = 2 * gasPrice`, `tip = gasPrice / 10` | estimate + 20 %, same fees, configurable |
| 413 | not handled | cap calldata at 60 000 bytes via `fit()` | `ops::fit` / `ops::split` by exact byte arithmetic |
| rate limits | none | retry twice | exponential backoff with jitter, `Retry-After` honoured |

Everything else is identical: engine `0x4400000000000000000000000000000000000044`, selector
`0x49650044` for `execute((uint8,bytes)[])`, `entityNonce(address)` selector `0x36917bfd`, op tag 1 for create.

## 2. Wire format

All integers are big-endian 32-byte ABI words unless stated. "Dynamic" follows Solidity ABI rules.

### 2.1 Attribute

ABI tuple `(bytes32 name, uint8 typeId, bytes value)`.

* `name`: UTF-8, left aligned, zero padded on the right.
* `typeId`: low 7 bits the type, bit 7 (`0x80`) set when indexed. `0` is a tombstone (patch only).
* `value`: depends on the type.

| type | id | value bytes | query literal |
|---|---|---|---|
| `bool` | 1 | 32-byte word, 0 or 1 | `true` |
| `i32` | 2 | 32-byte two's complement | `i32(5)` |
| `u64` | 3 | 32-byte word | `u64(123)` |
| `u256` | 4 | 32-byte word | `u256(123)` |
| `dec` | 5 | 32-byte two's complement of `value * 10^18` | `dec(1.5)` |
| `bytes` | 7 | raw bytes, never indexed | not queryable |
| `str` | 8 | raw UTF-8 (no padding inside the cell) | `str('it''s')` |
| `addr` | 9 | 20 bytes left padded to 32, lowercase source | `addr(0x..)` |
| `key` | 10 | 32 bytes (the node reports id 6 `bytes32` as `key`) | `key(0x..)` |

Example, indexed string `arkiv.schema = "demo.items"`: name word
`61726b69762e736368656d61` then 20 zero bytes, `typeId = 0x88`, value `64656d6f2e6974656d73` (10 bytes).
In the enclosing array the tuple is dynamic, so it sits behind an offset, and the `bytes` cell is
`len word ++ data padded to 32`.

### 2.2 Create payload (`operationData`, tag 1)

`abi.encode((uint128 salt, uint64 expiresAt, uint64 minLifetime, uint8 creationFlags, Attribute[] attributes))`.
One struct with a dynamic last member, so the encoding starts with an offset word `0x20`.
Golden head (salt `0x0102..0f10`, `expiresAt 0`, `minLifetime 7_800_000`, readonly):

```
word 0  0000..0020   offset of the struct
word 1  0000..0102030405060708090a0b0c0d0e0f10   salt
word 2  0000..0000   expiresAt
word 3  0000..7704c0 minLifetime (7_800_000)
word 4  0000..0001   creationFlags (readonly)
word 5  0000..00a0   offset of attributes within the struct
word 6  0000..0008   attribute count
word 7+ offsets, then each attribute tuple
```

### 2.3 Other payloads

| tag | op | `abi.encode` of |
|---|---|---|
| 2 | patch | `(bytes32 entityKey, Attribute[] mutations)`; unset = tombstone `typeId 0`, empty value; mutations sorted like creates |
| 3 | extend expiry | `(bytes32 entityKey, uint64 expiresAt, uint64 minLifetime)` |
| 4 | transfer ownership | `(bytes32 entityKey, address newOwner)` |
| 5 | delete | `(bytes32 entityKey)` |

### 2.4 Execute calldata

`0x49650044 ++ abi.encode((uint8 operation, bytes operationData)[] ops)`.
Layout: `0x20` offset word, array length word, one offset word per op, then per op
`[tag word, 0x40 offset word, len word, data padded to 32]`.
Bytes one op adds: `32 (its offset) + 96 (tag, offset, len) + pad32(data) = 128 + pad32(data)`.
Total: `4 + 64 + sum(op.calldata_len())`. An empty `ops` encodes (`...0020 ...0000`) but the SDK refuses it with `EmptyBatch`.

### 2.5 Entity key

`keccak256(uint256 chainId ++ address(0x44..44) ++ address owner ++ uint64 nonce ++ uint128 salt)`, packed
(32 + 20 + 20 + 8 + 16 = 96 bytes). `nonce` is the owner's `entityNonce`, plus the create's index in the batch.
Prediction holds only while nothing else from that owner is in flight; the receipt is authoritative.

### 2.6 Receipt

A confirmed execute emits one `EntityCreated(bytes32 indexed entityKey, address indexed owner, uint64 expiresAt, uint8 creationFlags)`
per create, from the engine address. Topic 0 is `keccak256("EntityCreated(bytes32,address,uint64,uint8)")`, topic 1 the key.

### 2.7 EIP-1559 transaction

Signing payload `0x02 ++ rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, []])`.
Signature over `keccak256(payload)`, low-s normalised, then
`0x02 ++ rlp([..same.., yParity, r, s])`. `r` and `s` are RLP integers (leading zeros stripped).
Hash is `keccak256(raw)`. Golden vector in `tests/vectors/viem.json` (`signedTx`).

### 2.8 JSON-RPC

* `arkiv_query(queryString, {select, limit, offset, cursor, atBlock})` where `limit`, `offset`, `atBlock` are hex
  QUANTITYs, `select` is `{key, owner, creator, createdAt, updatedAt, expiresAt, creationFlags, attributes}` booleans.
  Result `{data: [...], blockNumber, cursor?}`. `limit` max 100 (0x64).
* `arkiv_getEntity(key)` returns the entity, or `null` when absent (verified live).
* Entity JSON: `key, owner, creator` hex; `createdAt, updatedAt, expiresAt` QUANTITY; `creationFlags {readonly, permissionlessExtension, raw}`;
  `attributes [{name, type, value}]` with `value` by type: `str` string, `u64`/`u256` `0x` QUANTITY, `dec` decimal string,
  `i32` number, `bool` boolean, `addr`/`key` hex string, `bytes` hex.
* Query error codes: -32001 parse, -32002 type, -32003 literal, -32004 limits.
* HTTP: 413 on request bodies past about 200 KB, 429 on bursts, cursors are tied to a block and the public node keeps only the latest.

## 3. Public API

All fallible functions return `arkiv::Result<T>` = `Result<T, arkiv::Error>`. The signatures are the stubs in `src/`;
this section says what each module owns.

### 3.1 `types.rs` (final, no owner)

`Address`, `B256`, `Key`, `TxHash`, constants (`ARKIV_ADDRESS`, `RABDI_CHAIN_ID`, `RABDI_RPC`, `MAX_LIFETIME_BLOCKS`,
`EXECUTE_SELECTOR`, `ENTITY_NONCE_SELECTOR`), `keccak256`, `entity_created_topic`, `hex_decode`, `hex_encode`,
`parse_quantity`, `quantity`. Implemented and tested.

### 3.2 `error.rs` (final, no owner)

One enum `Error` (thiserror), grouped by raising module, plus `Error::is_retryable`. No module adds variants.

### 3.3 `attributes.rs`

`AttrType`, `Decimal`, `Value`, `Attribute` with typed constructors and `.indexed()`, `validate_name`, `normalize`,
`Value::from_rpc`, `Value::encode`. Owns: type ids, indexed bit, name grammar, limits, sort order, decimal parsing.
Rules: `Decimal::parse` rejects exponents and more than 18 fraction digits; `from_scaled(value, scale)` needs `scale <= 18`;
`str` values may not contain NUL; `bytes` over 128 KiB are rejected.

### 3.4 `ops.rs`

`Expiry`, `CreationFlags`, `Create`, `Patch`, `Op`, `execute_calldata`, `fit`, `split`, `predict_entity_key`, `DEFAULT_MAX_CALLDATA`.
Owns all ABI encoding (a private minimal encoder for words, bytes, arrays, tuples) and batching.
`fit` and `split` use `Op::calldata_len`, which must equal the real encoded length (tested).
Patch, extend, transfer and delete are encoded exactly as the official SDK's ABI strings and checked against
viem-generated golden vectors (`tests/vectors/viem.json`).
`Expiry::seconds` requires a multiple of 2. `Expiry` rejects a zero pair and `min_lifetime > 7_884_000`.

### 3.5 `signer.rs`

`Tx1559`, `SignedTx`, `Signer`. Owns RLP, key parsing, address derivation, low-s signing. A key never appears in `Debug`
or in error text.

### 3.6 `query.rs`

`Query`, `Expr`, `Cmp`, `Dir`, the expression functions, `literal`. Owns the query grammar. Operators: `=`, `>`, `>=`, `<`, `<=`,
`BETWEEN`, `STARTSWITH`, `EXISTS`, `AND`, `OR`. System names: `$key`, `$owner`, `$creator`, `$expiresAt`, with fixed types
`key`, `addr`, `addr`, `u64`. `AND` binds tighter than `OR`; an `Or` inside an `And` is parenthesised. Example:

```
arkiv.schema = str('strike.rounds') AND $creator = addr(0x0f05df479fcb23b2281e28813fb47e57e47d1bb7) AND asset = str('BTC') AND settledAt > u64(123) ORDER BY settledAt:u64 DESC
```

### 3.7 `client.rs`

`ClientConfig`, `Client`, `QueryOptions`, `Select`, `Entity`, `Page`, `Receipt`, `Log`, `ExecOptions`, `Executed`.
Owns HTTP, retries, JSON shapes, and the pipeline `execute` (nonce, fees, estimate, sign, send, wait, keys).
Retry policy: reads retry on transport errors, 429 and 5xx up to `max_retries`, delay `base * 2^n` capped at `max_delay`,
plus up to 25 % jitter; a `Retry-After` header wins when larger. Writes (`send_raw`) never retry. A refused send
(`nonce too low`, `insufficient funds`, `underpriced`, `gas too low`, `intrinsic gas`) is `SendRefused`; anything
ambiguous is `SendUnknown` with the hash, and callers resolve it with `receipt(hash)` instead of resending.

## 4. Error handling summary

* Validation errors (attributes, ops, query) are raised before any network call.
* `is_retryable()` is true for `Transport`, HTTP 429 and 5xx only.
* No `unwrap`/`expect`/`panic` in library code; indexing is bounds-checked or replaced with `get`.
* Secrets: private keys are read from the caller, never logged, never in `Debug` or `Error` text.

## 5. Ownership map

| file | owner | may edit |
|---|---|---|
| `src/types.rs`, `src/error.rs`, `src/lib.rs` | nobody (final) | no |
| `src/attributes.rs` | attributes agent | itself |
| `src/ops.rs` | ops agent | itself |
| `src/signer.rs` | signer agent | itself |
| `src/query.rs` | query agent | itself |
| `src/client.rs` | client agent | itself |
| `tests/*.rs`, `tests/vectors/` | each agent adds its own `tests/<module>.rs` | own test file only |
| `README.md`, `examples/` | docs agent | itself |

Dependency direction: `types`, `error` at the bottom; `attributes` on those; `ops`, `query` on `attributes`;
`signer` on `types`; `client` on all. `query` never imports `client`.

## 6. Tests

Offline: golden vectors from `tests/vectors/viem.json`, generated with viem 2 using the official SDK's ABI strings.
Keys: `selector`, `entityNonceSelector`, `attributes` (typeId and value per attribute), `createOpData`,
`executeCreate`, `executeTwoCreates`, `executeEmpty`, `executeMixed`, `patchOpData`, `extendOpData`, `transferOpData`,
`deleteOpData`, `predictKey`, `signedTx` (uses the public Hardhat test key, never a real one).
Live (marked `#[ignore]`, run with `cargo test -- --ignored`): read entity
`0x59c5ddf06b5605e27833d0a02c8f6e96cebf9f334a6470b39e31eccb34895807`, query `strike.epochs` by creator, paging by offset.
No test sends a transaction unless `ARKIV_TEST_KEY` is set to a throwaway funded Rabdi key.
