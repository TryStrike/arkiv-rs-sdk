//! The single error type of the crate.
//!
//! This module is final. Variants are grouped by the module that raises them, but every module
//! returns [`Error`] so callers match on one enum.

use std::time::Duration;

use crate::types::TxHash;

/// Result alias used across the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Which part of an `arkiv_query` the node rejected, from JSON-RPC codes -32001 to -32004.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryErrorKind {
    /// -32001: the query string did not parse.
    Parse,
    /// -32002: a type mismatch in the query.
    Type,
    /// -32003: a malformed literal.
    Literal,
    /// -32004: a node limit was exceeded.
    Limits,
}

/// Every failure the SDK can report.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    // ---- attributes.rs ----
    /// An attribute name breaks the `Ident32` grammar or collides with a reserved word.
    #[error("invalid attribute name {name:?}: {reason}")]
    InvalidAttributeName {
        /// The offending name.
        name: String,
        /// Why it was rejected.
        reason: String,
    },
    /// A value does not fit its type (out of range, bad decimal literal, too long).
    #[error("invalid {kind} value: {reason}")]
    InvalidValue {
        /// The type tag, such as `u64` or `dec`.
        kind: &'static str,
        /// Why it was rejected.
        reason: String,
    },
    /// More than 32 attributes on one entity (the schema tag counts).
    #[error("too many attributes: {got}, the maximum is {max}")]
    TooManyAttributes {
        /// How many were given.
        got: usize,
        /// The limit.
        max: usize,
    },
    /// Two attributes share a name.
    #[error("duplicate attribute {0:?}")]
    DuplicateAttribute(String),
    /// The `bytes` values of one create or patch exceed 128 KiB in total.
    #[error("entity too large: {got} bytes of bytes values, the maximum is {max}")]
    EntityTooLarge {
        /// Total bytes given.
        got: usize,
        /// The limit.
        max: usize,
    },

    // ---- ops.rs ----
    /// An expiry that is zero, too long, or not a whole number of blocks.
    #[error("invalid expiry: {0}")]
    InvalidExpiry(String),
    /// The OS random source failed while drawing a salt.
    #[error("no random source: {0}")]
    Random(String),
    /// An empty list of operations.
    #[error("no operations to execute")]
    EmptyBatch,
    /// One operation alone encodes larger than the calldata cap.
    #[error("operation {index} needs {size} bytes of calldata, over the cap of {cap}")]
    OpTooLarge {
        /// Position of the operation in the input.
        index: usize,
        /// Calldata bytes it would need on its own.
        size: usize,
        /// The cap in force.
        cap: usize,
    },

    // ---- types.rs / signer.rs ----
    /// Bad hex input, or the wrong number of bytes for a fixed-size type.
    #[error("invalid hex: {0}")]
    InvalidHex(String),
    /// A private key that is not a valid secp256k1 scalar.
    #[error("invalid private key")]
    InvalidKey,
    /// The signing backend failed.
    #[error("signing failed: {0}")]
    Signing(String),

    // ---- client.rs ----
    /// The HTTP request failed before a response (DNS, TLS, timeout, reset).
    #[error("transport error: {0}")]
    Transport(String),
    /// A non-2xx HTTP status. 413 means the body was too large, 429 means rate limited.
    #[error("http status {status}: {body}")]
    Status {
        /// The status code.
        status: u16,
        /// The response body, truncated.
        body: String,
        /// The `Retry-After` header, when the node sent one.
        retry_after: Option<Duration>,
    },
    /// A JSON-RPC error object from the node.
    #[error("rpc error {code}: {message}")]
    Rpc {
        /// JSON-RPC error code.
        code: i64,
        /// Error message.
        message: String,
        /// Raw `data` field, when present.
        data: Option<String>,
    },
    /// An `arkiv_query` rejection with a recognised code.
    #[error("query rejected ({kind:?}, {code}): {message}")]
    Query {
        /// Which kind of rejection.
        kind: QueryErrorKind,
        /// JSON-RPC error code.
        code: i64,
        /// Error message.
        message: String,
    },
    /// A response that does not have the expected shape.
    #[error("could not decode response: {0}")]
    Decode(String),
    /// The node refused the raw transaction and the nonce is unused (nonce too low, underpriced, and so on).
    #[error("transaction refused: {0}")]
    SendRefused(String),
    /// The transaction may or may not have reached the mempool. Never resend blindly; resolve the hash first.
    #[error("transaction {hash} may have been sent: {reason}")]
    SendUnknown {
        /// Hash of the signed transaction.
        hash: TxHash,
        /// What the node or transport said.
        reason: String,
    },
    /// The transaction was mined and reverted.
    #[error("transaction {0} reverted")]
    Reverted(TxHash),
    /// No receipt appeared within the wait budget.
    #[error("no receipt for {hash} after {waited:?}")]
    ReceiptTimeout {
        /// Hash that was awaited.
        hash: TxHash,
        /// How long we waited.
        waited: Duration,
    },
    /// A batch confirmed with a different number of created entities than creates sent.
    #[error("batch created {got} entities, expected {expected}")]
    KeyCountMismatch {
        /// Hash of the confirmed transaction.
        hash: TxHash,
        /// Entities found in the receipt.
        got: usize,
        /// Creates in the batch.
        expected: usize,
        /// The keys the receipt did report.
        keys: Vec<crate::types::Key>,
    },
    /// The transaction was accepted by the node but confirmation failed (rate limit, transport,
    /// bad receipt). It may well be mined: look up `hash` before resending.
    #[error("transaction {hash} was sent but not confirmed: {source}")]
    Unconfirmed {
        /// Hash of the sent transaction.
        hash: TxHash,
        /// What went wrong while waiting.
        source: Box<Error>,
    },
    /// A multi-batch send failed part way. Batches are atomic per transaction, not across them:
    /// the `done` batches are confirmed on chain and cannot be rolled back.
    #[error("batch {failed_at} failed after {} confirmed: {source}", done.len())]
    PartialBatch {
        /// Batches confirmed before the failure, in order.
        done: Vec<crate::client::Executed>,
        /// Index of the batch that failed.
        failed_at: usize,
        /// Why it failed. May itself be [`Error::Unconfirmed`], so batch `failed_at` could have landed.
        source: Box<Error>,
    },
    /// An [`ExecOptions`](crate::client::ExecOptions) value that cannot work.
    #[error("invalid options: {0}")]
    InvalidOptions(String),

    // ---- query.rs ----
    /// A query that cannot be built: bad name, unindexable type, empty `IN`, and so on.
    #[error("invalid query: {0}")]
    InvalidQuery(String),
}

impl Error {
    /// True when retrying the same read is reasonable: transport failures, 429, 5xx, and the
    /// RPC codes a busy node uses. Never true for [`Error::SendUnknown`] or any write outcome.
    pub fn is_retryable(&self) -> bool {
        match self {
            Error::Transport(_) => true,
            Error::Status { status, .. } => *status == 429 || *status >= 500,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retryable_classification() {
        assert!(Error::Transport("x".into()).is_retryable());
        let s = |status| Error::Status {
            status,
            body: String::new(),
            retry_after: None,
        };
        assert!(s(429).is_retryable() && s(503).is_retryable());
        assert!(!s(413).is_retryable() && !s(400).is_retryable());
        assert!(!Error::EmptyBatch.is_retryable());
    }
}
