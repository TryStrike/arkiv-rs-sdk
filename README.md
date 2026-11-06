# arkiv-rs-sdk

A Rust SDK for [Arkiv](https://docs.arkiv.network), the Web3 database. MIT licensed.

Arkiv is an Ethereum-aligned database chain. You write entities with typed attributes, and you read them back with a query language. The official SDK is TypeScript. There was no Rust SDK.

This one grew out of [Strike](https://github.com/TryStrike/strike), built at ETHGlobal Mumbai 2026. Strike's backend hand-rolled the Arkiv encoding in Rust and wrote to the chain every few seconds. arkiv-rs-sdk is that code, cleaned up, tested against golden vectors from the official SDK, and made reusable.

Package `arkiv-rs-sdk`, library `arkiv`. The wire format is in [SPEC.md](SPEC.md).

## Install

```toml
[dependencies]
arkiv-rs-sdk = { git = "https://github.com/TryStrike/arkiv-rs-sdk" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

Adjust the source to wherever you got the crate. It is not published to crates.io yet.

## Quickstart

Write an entity, then query it back. Use a throwaway testnet key.

```rust,no_run
use arkiv::{Attribute, Client, Create, ExecOptions, Expiry, Op, Query, QueryOptions, Signer};

#[tokio::main]
async fn main() -> arkiv::Result<()> {
    let signer = Signer::from_hex(&std::env::var("ARKIV_PRIVATE_KEY").unwrap_or_default())?;
    let client = Client::rabdi()?;

    // Write: a readonly entity that lives for 600 blocks (about 20 minutes).
    let attributes = vec![
        Attribute::schema("demo.notes")?,
        Attribute::str("text", "hello arkiv")?,
        Attribute::u64("n", 1)?.indexed()?,
    ];
    let create = Create::new(attributes, Expiry::blocks(600)?)?.readonly();
    let done = client.execute(&signer, &[Op::Create(create)], &ExecOptions::default()).await?;
    println!("created {}", done.keys[0]);

    // Read: by key, then by query.
    let entity = client.get_entity(done.keys[0]).await?;
    println!("{:?}", entity.map(|e| e.attributes));

    let query = Query::new().schema("demo.notes").creator(signer.address());
    let page = client.query(&query, &QueryOptions::default()).await?;
    println!("{} entities", page.entities.len());
    Ok(())
}
```

Runnable versions are in [examples/](examples):

```sh
ARKIV_PRIVATE_KEY=0x... cargo run --example write_entity
cargo run --example query        # read only, no key
```

Keys are read from the environment. Nothing in this crate prints or stores a key.

## What it handles for you

The public Rabdi node has sharp edges. The client deals with them.

| Node behaviour | What arkiv-rs-sdk does |
|---|---|
| Query `limit` is capped at 100 | Rejects a limit of 0 or above 100 before the request. `query_all` pages for you. |
| 429 on bursts, 5xx under load | Reads retry with exponential backoff and jitter. A `Retry-After` header is honoured. |
| 413 on large request bodies | `ops::fit` and `ops::split` cap calldata (60,000 bytes by default) using exact byte counts. `execute_all` sends one transaction per batch. |
| Cursors are tied to a block, and the node keeps only the latest block | `query_all` pages with `offset`, which works across blocks. `cursor` and `at_block` are there if you need them. |
| Attributes must be sorted, named correctly, and at most 32 | Checked and sorted before anything is sent. |
| Send errors can be ambiguous | Writes are never retried. A refused send is `SendRefused`. An unclear one is `SendUnknown` with the hash, so you can look up the receipt instead of sending twice. |

## Features

| Feature | Status |
|---|---|
| Create entities, writable or readonly | Yes, tested on chain |
| Expiry by blocks, seconds or `Duration` | Yes |
| Typed attributes: `bool`, `i32`, `u64`, `u256`, `dec`, `bytes`, `str`, `addr`, `key` | Yes |
| Indexed attributes | Yes |
| Batched `execute` with automatic size cap | Yes |
| Predict an entity key before sending | Yes |
| EIP-1559 signing, nonce, gas estimate with headroom | Yes |
| Receipt waiting, created keys from logs | Yes |
| Query builder (`=`, `>`, `>=`, `<`, `<=`, `BETWEEN`, `STARTSWITH`, `EXISTS`, `AND`, `OR`, `ORDER BY`) | Yes |
| `get_entity`, `query`, `query_all`, field selection | Yes |
| Retries with backoff | Yes, reads only |
| Typed errors with `is_retryable` | Yes |

## Not yet

- Patch, extend, transfer and delete. They are encoded to match the official SDK and checked against golden vectors, but this crate has not run them on chain. Treat them as unverified. Create is the only write that is verified end to end.
- Event subscriptions and websockets.
- A derive macro for schemas.
- Sponsored writes.
- Receipt waiting by block subscription. Receipts are polled.

## Testing

```sh
cargo test                       # unit tests and golden vectors, offline
cargo test --doc                 # doctests
ARKIV_LIVE=1 cargo test --test live          # read-only tests against Rabdi
ARKIV_TEST_KEY=0x... cargo test --test funded -- --ignored   # sends transactions
```

- Golden tests compare our bytes with output from viem using the official SDK's ABI strings. The vectors are in `tests/vectors/viem.json`, generated by `tests/golden/generate.mjs`.
- Live tests read real Strike entities on Rabdi. They are skipped unless `ARKIV_LIVE=1`.
- Funded tests spend gas. Use a throwaway key. The suite never touches a key you did not pass in.

## Network

Rabdi testnet. Chain id 7794095. RPC `https://rpc.rabdi.db-chain.testnet.arkiv.network`. Explorer `https://rabdi.explorer.arkiv.network`. Block time 2 s. Maximum lifetime 7,884,000 blocks.

## License

MIT. See [LICENSE](LICENSE).
