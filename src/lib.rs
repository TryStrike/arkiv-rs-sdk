//! # arkiv
//!
//! A Rust SDK for Arkiv, the Web3 database. Write typed entities in size-capped batches, sign
//! and send them, then read them back with a query builder and a retrying client.
//!
//! ```no_run
//! use arkiv::{Attribute, Client, Create, Expiry, ExecOptions, Op, Query, QueryOptions, Signer};
//!
//! # async fn run() -> arkiv::Result<()> {
//! let client = Client::rabdi()?;
//! let signer = Signer::from_hex(&std::env::var("ARKIV_TEST_KEY").unwrap_or_default())?;
//!
//! let attrs = vec![
//!     Attribute::schema("demo.notes")?,
//!     Attribute::str("text", "hello arkiv")?,
//! ];
//! let create = Create::new(attrs, Expiry::blocks(600)?)?.readonly();
//! let done = client.execute(&signer, &[Op::Create(create)], &ExecOptions::default()).await?;
//!
//! let query = Query::new().schema("demo.notes").creator(signer.address());
//! let page = client.query(&query, &QueryOptions::default()).await?;
//! println!("{} written, {} found", done.keys.len(), page.entities.len());
//! # Ok(())
//! # }
//! ```
//!
//! Module map: [`attributes`] (typed values), [`ops`] (operations and calldata), [`signer`]
//! (EIP-1559), [`client`] (JSON-RPC), [`query`] (query strings), [`error`], [`types`].

#![warn(missing_docs)]

pub mod attributes;
pub mod client;
pub mod error;
pub mod ops;
pub mod query;
pub mod signer;
pub mod types;

pub use attributes::{AttrType, Attribute, Decimal, Value};
pub use client::{
    Client, ClientConfig, Entity, ExecOptions, Executed, Page, QueryOptions, Receipt, Select,
};
pub use error::{Error, Result};
pub use ops::{Create, CreationFlags, Expiry, Op, Patch};
pub use query::{Dir, Expr, Query};
pub use signer::{SignedTx, Signer, Tx1559};
pub use types::{Address, Key, TxHash, B256};
