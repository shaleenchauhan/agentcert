# AgentCert — Phase 3b: Anchoring Service + SDK Client Session Summary

## Overview

Added a FastAPI anchoring service and httpx-based SDK client to AgentCert. The service receives signed audit entries, batches them into Merkle trees, anchors roots to Bitcoin, and serves proofs. The SDK client provides a Python interface for developers to interact with the service instead of managing Bitcoin transactions themselves.

**Trust model:** Private keys stay on the developer's machine. Entries are signed before being sent. The service cannot forge entries. Even if compromised, all entries are independently verifiable.

## Build Steps

| Step | Description | Status |
|------|-------------|--------|
| 1 | Setup — `fastapi`, `uvicorn`, `httpx` as optional deps; `service/` package; `ServiceError`, `ClientError` exceptions | Done |
| 2 | Database layer — SQLite via `sqlite3`, 4 tables, CRUD for certs/entries/batches/proofs | Done |
| 3 | Service config — `ServiceConfig` dataclass, `from_env()`, `from_file()` | Done |
| 4 | Background scheduler — `BatchScheduler` with batching loop using existing `create_batch` + anchor infrastructure | Done |
| 5 | FastAPI app — 12 endpoints: certificates, entries, trails, proofs, verify, batches, admin, health, stats | Done |
| 6 | SDK client — `AgentCertClient` class, 14 methods, httpx-based, context manager | Done |
| 7 | Tests — 59 new tests (337 → 396 total), all passing | Done |
| 8 | CLI — `service` subcommand group with start, health, stats, force-batch | Done |
| 9 | Public API — updated `__init__.py` (69 → 72 exports), conditional client import | Done |
| 10 | Example — `examples/service_demo.py` full flow demo | Done |
| 11 | README — added anchoring service and SDK client sections, updated project structure | Done |

## Files Created

| File | Description |
|------|-------------|
| `src/agentcert/service/__init__.py` | Service package init |
| `src/agentcert/service/app.py` | FastAPI application with 12 endpoints (~280 lines) |
| `src/agentcert/service/models.py` | SQLite database layer with CRUD operations (~280 lines) |
| `src/agentcert/service/scheduler.py` | Background batching + anchoring scheduler (~120 lines) |
| `src/agentcert/service/config.py` | `ServiceConfig` dataclass (~100 lines) |
| `src/agentcert/client.py` | `AgentCertClient` SDK client (~260 lines) |
| `tests/test_service.py` | 40 tests across 9 test classes |
| `tests/test_client.py` | 19 tests across 11 test classes |
| `examples/service_demo.py` | Full flow demo: start service, register, submit, batch, proof, verify |

## Files Modified

| File | Changes |
|------|---------|
| `pyproject.toml` | Added `service`, `client` optional dependency groups; updated `dev` group |
| `src/agentcert/exceptions.py` | Added `ServiceError`, `ClientError` |
| `src/agentcert/__init__.py` | Added conditional `AgentCertClient` import, `ServiceError`, `ClientError` exports (69 → 72) |
| `src/agentcert/cli.py` | Added `service` subcommand group with 4 commands: start, health, stats, force-batch |
| `README.md` | Added anchoring service + SDK client sections, updated install options, project structure (396 tests, 21 CLI commands) |

## Architecture

### Database (models.py)

SQLite via `sqlite3` standard library. No ORM. 4 tables:

- **certificates** — registered certificates (cert_id PK, certificate_json, registered_at)
- **entries** — audit entries (entry_id PK, trail_id, cert_id, agent_id, sequence, entry_json, batch_id FK)
- **batches** — Merkle batches (batch_id PK, merkle_root, item_count, item_hashes_json, anchor_receipt_json)
- **proofs** — Merkle proofs (entry_id + batch_id composite PK, proof_json)

Indexes on trail_id, cert_id, batch_id for entries.

### Service (app.py)

FastAPI application with 12 endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/certificates` | POST | Register certificate (validates cert_id + creator signature) |
| `/api/v1/certificates/{id}` | GET | Get certificate |
| `/api/v1/entries` | POST | Submit entries (validates entry_id + agent signature + cert binding) |
| `/api/v1/entries/{id}` | GET | Get entry |
| `/api/v1/trails/{id}` | GET | Get trail entries |
| `/api/v1/proofs/{id}` | GET | Get Merkle proof (or "pending" status) |
| `/api/v1/verify/{id}` | GET | Full verification (5 checks: integrity, signature, cert binding, proof, anchor) |
| `/api/v1/batches/{id}` | GET | Get batch |
| `/api/v1/batches/latest` | GET | Latest batch |
| `/api/v1/admin/force-batch` | POST | Force immediate batch cycle |
| `/api/v1/health` | GET | Health check |
| `/api/v1/stats` | GET | Statistics |

Entry validation on submission:
1. Parse entry dict to `AuditEntry`
2. Verify `entry_id` integrity (SHA-256 of body)
3. Verify agent signature (ECDSA)
4. Check `cert_id` references a registered certificate
5. Check `agent_id` matches the certificate

### Scheduler (scheduler.py)

`BatchScheduler` runs as an asyncio background task:
1. Queries unbatched entries
2. If count >= `batch_min_entries`: builds Merkle tree, stores batch + proofs, marks entries batched
3. If wallet key configured: anchors to Bitcoin
4. Logs the result

### Client (client.py)

`AgentCertClient` — httpx-based sync client with 14 methods:

- `register_certificate(cert)`, `get_certificate(cert_id)`
- `submit_entries(entries)`, `submit_trail(trail)`, `get_entry(entry_id)`
- `get_trail(trail_id)`
- `get_proof(entry_id)` → `MerkleProof | None`, `get_proof_raw(entry_id)`
- `verify_entry(entry_id)`
- `get_batch(batch_id)`, `get_latest_batch()`, `force_batch()`
- `health()`, `stats()`

Context manager support (`with AgentCertClient(...) as client:`).

### Config (config.py)

`ServiceConfig` dataclass with defaults:
- `db_path`: `"./agentcert-service/agentcert.db"`
- `batch_interval_seconds`: 600 (10 minutes)
- `batch_min_entries`: 1
- `batch_max_entries`: 10000
- `network`: `"testnet"`
- `anchor_wallet_key`: None (skip anchoring)
- `host`: `"0.0.0.0"`, `port`: 8932

Loadable from environment variables (`AGENTCERT_*`) or JSON file.

## Test Count

| | Before | After | Delta |
|-|--------|-------|-------|
| Tests | 337 | 396 | +59 |

### test_service.py (40 tests)

| Test class | Count | Covers |
|------------|-------|--------|
| `TestHealth` | 2 | Health endpoint, empty stats |
| `TestCertificates` | 7 | Register, duplicate (409), invalid cert_id, invalid sig, missing field, get, not found |
| `TestEntries` | 8 | Submit, duplicate, invalid sig, unregistered cert, wrong agent, missing field, get, not found |
| `TestTrails` | 2 | Get trail, not found |
| `TestProofs` | 3 | Pending, after batch, not found |
| `TestVerify` | 3 | Pending, after batch, not found |
| `TestBatches` | 6 | Force batch (empty, with entries), get batch, not found, latest, latest empty |
| `TestFullFlow` | 1 | Register → submit → batch → proof → verify (full integration) |
| `TestConfig` | 3 | Default, from_env, from_file |
| `TestDatabase` | 5 | Register+get cert, get not found, store+get entries, unbatched entries, stats |

### test_client.py (19 tests)

| Test class | Count | Covers |
|------------|-------|--------|
| `TestRegisterCertificate` | 2 | Success, conflict (409) |
| `TestSubmitEntries` | 2 | Submit entries, submit trail |
| `TestGetProof` | 3 | Pending, available (returns MerkleProof), raw |
| `TestVerifyEntry` | 1 | Full verification response |
| `TestGetBatch` | 2 | Get batch, get latest |
| `TestForceBatch` | 1 | Force batch |
| `TestHealthAndStats` | 2 | Health, stats |
| `TestErrorHandling` | 2 | 404 → ClientError, connection error → ClientError |
| `TestContextManager` | 1 | With-statement |
| `TestGetCertificate` | 1 | Get certificate |
| `TestGetEntry` | 1 | Get entry |
| `TestGetTrail` | 1 | Get trail |

## API Exports (72 total, +3 new)

### New exports

**Classes (1):**
- `AgentCertClient` — SDK client for the anchoring service (conditional on httpx)

**Exceptions (2):**
- `ServiceError` — raised by the service on internal errors
- `ClientError` — raised by the SDK client on communication errors

## CLI Commands (4 new, 21 total)

```bash
agentcert service start [--config config.json] [--port 8932] [--network testnet] [--wallet-key key.json]
agentcert service health [--url http://localhost:8932]
agentcert service stats [--url http://localhost:8932]
agentcert service force-batch [--url http://localhost:8932]
```

## Dependencies

| Package | Group | Purpose |
|---------|-------|---------|
| `fastapi>=0.100.0` | service | REST API framework |
| `uvicorn>=0.20.0` | service | ASGI server |
| `httpx>=0.24.0` | client | HTTP client for SDK |

All optional — install with `pip install agentcert[service]` or `pip install agentcert[client]`.

## Open Items

- **PyPI re-publish**: Package on PyPI is v0.2.0. A version bump and re-publish is needed for the service/client additions.
- **Authentication**: The service has no auth. A future phase could add API key or JWT authentication.
- **Rate limiting**: No rate limiting on endpoints.
- **Async database**: SQLite via sqlite3 is synchronous, wrapped in `asyncio.to_thread` for the scheduler. A future phase could use `aiosqlite`.
- **PostgreSQL**: SQLite is fine for single-instance deployment. For production scale, a PostgreSQL adapter would be needed.
- **Docker**: No Dockerfile yet. Would simplify deployment.
- **GitHub Actions CI**: No CI pipeline yet.
