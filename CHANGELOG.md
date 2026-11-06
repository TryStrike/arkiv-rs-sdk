# Changelog

## 0.1.0

First release.

- Typed attributes with indexed flags and name checks.
- Create operations, writable or readonly, with expiry by blocks, seconds or `Duration`.
- Batched `execute` calldata, with `fit` and `split` to stay under the node's request size limit.
- Entity key prediction.
- EIP-1559 signing with low-s signatures.
- Client with nonce, gas estimate, send, receipt wait and created keys.
- Query builder and typed reads: `get_entity`, `query`, `query_all`.
- Read retries with exponential backoff, jitter and `Retry-After`.
- Golden vectors generated with viem, and read-only live tests.
- Not yet: patch, extend, transfer and delete are encoded but not verified on chain.
