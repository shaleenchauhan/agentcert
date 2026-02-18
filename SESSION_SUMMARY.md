# AgentCert — Merkle Batching Session Summary

## Overview

Added Merkle tree batching and batch anchoring to AgentCert (Phase 3a). Multiple audit entries can now be batched into a Merkle tree, with the root anchored to Bitcoin in a single transaction. Any individual entry is independently provable against the on-chain root via its O(log n) Merkle proof.

Without batching: 1,000 entries = 1,000 Bitcoin transactions (~$5,000 in fees).
With batching: 1,000 entries = 1 Bitcoin transaction (~$5 in fees).

## Build Steps

| Step | Description | Status |
|------|-------------|--------|
| 1 | New types — `MerkleProof`, `Batch`, `BatchVerificationResult`, `BatchVerificationCheck` in types.py; `BatchError` in exceptions.py | Done |
| 2 | Merkle tree — `MerkleTree` class with construction, root, proof generation, static proof verification | Done |
| 3 | Batch operations — `create_batch`, `create_batch_from_entries`, `create_batch_from_trail`, `anchor_batch`, proof retrieval, verification, save/load | Done |
| 4 | Tests — 79 new tests (258 → 337 total), all passing | Done |
| 5 | CLI — `batch` subcommand group with create, anchor, proof, verify, inspect | Done |
| 6 | Public API — updated `__init__.py` (51 → 69 exports) | Done |
| 7 | Example — `examples/batch_anchor_demo.py` | Done |
| 8 | README — Merkle batching section, updated project structure | Done |

## Files Created

| File | Description |
|------|-------------|
| `src/agentcert/merkle.py` | `MerkleTree` class — SHA-256 binary Merkle tree (~130 lines) |
| `src/agentcert/batch.py` | Batch creation, anchoring, proof retrieval, verification, save/load (~370 lines) |
| `tests/test_merkle.py` | 34 tests across 6 test classes |
| `tests/test_batch.py` | 45 tests across 13 test classes |
| `examples/batch_anchor_demo.py` | Full lifecycle demo: create → batch → proofs → verify → save/reload |

## Files Modified

| File | Changes |
|------|---------|
| `src/agentcert/types.py` | Added `MerkleProof`, `Batch`, `BatchVerificationCheck`, `BatchVerificationResult` frozen dataclasses |
| `src/agentcert/exceptions.py` | Added `BatchError(AgentCertError)` |
| `src/agentcert/__init__.py` | 18 new exports (51 → 69): `MerkleTree`, batch functions, new types, `BatchError` |
| `src/agentcert/cli.py` | Added `batch` subcommand group with 5 commands: create, anchor, proof, verify, inspect |
| `README.md` | Added Merkle batching section with SDK + CLI examples, updated project structure (69 exports, 337 tests) |

## Architecture

### MerkleTree (merkle.py)

Standard binary SHA-256 Merkle tree:

- Leaves are 32-byte SHA-256 hashes passed in directly
- Internal nodes: `SHA-256(left_child + right_child)`
- Odd levels: last node is duplicated
- All levels stored for O(1) proof generation
- `get_proof(index)` returns a `MerkleProof` with sibling hashes and directions
- `verify_proof(leaf, proof, root)` recomputes root from leaf+siblings, compares to expected

### Batch Operations (batch.py)

**Batch creation:**
- `create_batch(items)` — items can be hex strings, bytes, or dicts (dicts are serialized to canonical JSON and hashed)
- `create_batch_from_entries(entries)` — uses each entry's `entry_id` as the leaf hash
- `create_batch_from_trail(trail)` — batches all entries in a trail

**Anchoring:**
- `anchor_batch(batch, creator_keys=..., network=...)` — builds OP_RETURN payload with type `0x01` (MERKLE_ROOT), reuses the existing Bitcoin transaction infrastructure from `anchor.py`
- Returns updated `Batch` with `anchor_receipt` set

**Proof retrieval:**
- `get_proof_for_entry(entry, tree, batch)` — Merkle proof for an audit entry
- `get_proof_for_item(item_hash, tree, batch)` — Merkle proof for any item hash

**Verification:**
- `verify_batch_proof(item_hash, proof, batch)` — 3 checks: Merkle proof validity, root match, anchor validity
- `verify_entry_in_batch(entry, proof, batch, certificate=None)` — same + optional cert_id binding check
- Returns `BatchVerificationResult` with status: `VALID`, `INVALID`, or `NOT_ANCHORED`

**Persistence:**
- `save_batch / load_batch` — batch metadata as JSON
- `save_proofs / load_proofs` — dict of `item_hash → MerkleProof` as JSON

### OP_RETURN Payload

```
[AIT\0]   protocol tag     (4 bytes)
[0x01]    version           (1 byte)
[0x01]    MERKLE_ROOT       (1 byte)  ← distinct from 0x02 IDENTITY_CERT
[...]     Merkle root hash  (32 bytes)
Total: 38 bytes
```

## Test Count

| | Before | After | Delta |
|-|--------|-------|-------|
| Tests | 258 | 337 | +79 |

### test_merkle.py (34 tests)

| Test class | Count | Covers |
|------------|-------|--------|
| `TestMerkleTreeConstruction` | 12 | 1, 2, 3, 4, 7, 8, 16, 100, 1000 leaves; empty, invalid leaf errors |
| `TestMerkleRoot` | 4 | root_hex, determinism, different leaves, order matters |
| `TestHashPair` | 2 | Basic hash, non-commutativity |
| `TestProofGeneration` | 6 | 1/2/4/100 leaf proofs, depth for powers of two, out-of-range error |
| `TestProofVerification` | 8 | All 16 leaves, single leaf, odd leaves, 1000 leaves, tampered leaf/root/sibling/direction |
| `TestMerkleProofSerialization` | 2 | Roundtrip, dict structure |

### test_batch.py (45 tests)

| Test class | Count | Covers |
|------------|-------|--------|
| `TestNormalizeItem` | 7 | hex, bytes, dict, invalid hex, wrong length, unsupported type |
| `TestCreateBatch` | 7 | hex, bytes, dicts, mixed, single, empty, batch_id |
| `TestCreateBatchFromEntries` | 2 | From entries, empty raises |
| `TestCreateBatchFromTrail` | 2 | From trail, empty raises |
| `TestProofRetrieval` | 4 | For entry, for item, missing entry, missing item |
| `TestVerifyBatchProof` | 6 | Valid not-anchored, valid anchored, tampered item, mismatched anchor, all entries, checks structure |
| `TestVerifyEntryInBatch` | 3 | Matching cert, wrong cert, no cert |
| `TestBatchPayload` | 2 | Payload format, type is MERKLE_ROOT |
| `TestAnchorBatch` | 2 | Mocked success, no UTXOs |
| `TestBatchSaveLoad` | 4 | Roundtrip, with receipt, JSON valid, nonexistent |
| `TestProofsSaveLoad` | 3 | Roundtrip, JSON valid, nonexistent |
| `TestBatchSerialization` | 2 | Roundtrip, with receipt |
| `TestBatchLifecycle` | 1 | Full lifecycle: create → batch → proofs → verify → save → reload → re-verify |

## API Exports (69 total, +18 new)

### New exports

**Functions (12):**
- `create_batch` — Batch from hex strings, bytes, or dicts
- `create_batch_from_entries` — Batch from audit entries
- `create_batch_from_trail` — Batch from an audit trail
- `anchor_batch` — Anchor batch root to Bitcoin
- `get_proof_for_entry` — Merkle proof for an audit entry
- `get_proof_for_item` — Merkle proof for an item hash
- `verify_batch_proof` — Verify item against a batch
- `verify_entry_in_batch` — Verify entry against a batch + optional cert binding
- `save_batch` / `load_batch` — Batch persistence
- `save_proofs` / `load_proofs` — Proof persistence

**Classes (1):**
- `MerkleTree` — Binary SHA-256 Merkle tree

**Types (4):**
- `MerkleProof` — Proof of inclusion (leaf_hash, siblings, directions, root)
- `Batch` — Batch metadata (batch_id, merkle_root, item_hashes, anchor_receipt)
- `BatchVerificationCheck` — Single batch verification check
- `BatchVerificationResult` — Aggregate batch verification result

**Exceptions (1):**
- `BatchError` — Raised on Merkle/batch operation failures

## CLI Commands (5 new, 17 total)

```bash
agentcert batch create trail.json -o batch.json
agentcert batch anchor batch.json --creator-keys ck.json --network testnet
agentcert batch proof batch.json --entry-id <hash> -o proof.json
agentcert batch verify batch.json --entry-id <hash>
agentcert batch inspect batch.json
```

## Coverage

```
Name                                      Stmts   Miss  Cover
-----------------------------------------------------------------------
src/agentcert/__init__.py                    17      2    88%
src/agentcert/anchor.py                     200     17    92%
src/agentcert/audit.py                       83      4    95%
src/agentcert/audit_verify.py               122      2    98%
src/agentcert/batch.py                      148     12    92%
src/agentcert/certificate.py                 46      6    87%
src/agentcert/chain.py                       82      2    98%
src/agentcert/cli.py                        368    139    62%
src/agentcert/exceptions.py                  11      0   100%
src/agentcert/integrations/__init__.py        0      0   100%
src/agentcert/integrations/langchain.py     183      6    97%
src/agentcert/keys.py                        37      2    95%
src/agentcert/merkle.py                      64      0   100%
src/agentcert/types.py                      204      1    99%
src/agentcert/verify.py                      62      2    97%
-----------------------------------------------------------------------
TOTAL                                      1627    195    88%
```

New modules: `merkle.py` at 100%, `batch.py` at 92%. Overall project coverage 88%.

## Open Items

- **PyPI re-publish**: Package on PyPI is v0.2.0 and does not include Merkle batching. A version bump to v0.3.0 and re-publish is needed.
- **Real Bitcoin anchor test**: The demo runs offline. A test anchoring a real batch to Bitcoin testnet would confirm end-to-end.
- **Cross-agent batching**: The current API batches entries from a single trail. A future phase could batch entries from multiple agents/trails into a single tree.
- **Incremental batching**: Currently the entire trail is batched at once. Support for appending new entries to an existing batch (re-batching) would be useful.
- **Merkle root anchoring for audit trails**: The trail itself could store a reference to the batch that anchored it, closing the loop between trail verification and batch verification.
- **GitHub Actions CI**: No CI pipeline yet.
