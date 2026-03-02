# AgentCert

Bitcoin-anchored trust infrastructure for AI agents.

## What This Project Does

AgentCert provides cryptographic identity certificates, tamper-proof audit trails, and Bitcoin-anchored verification for autonomous AI agents. Published on PyPI (`pip install agentcert`, v0.3.0), MIT license.

## Architecture

Developer's Agent (LangChain/CrewAI/AutoGen) → AgentCert Middleware (local signing, storage="both") → AgentCert Service (FastAPI + SQLite at api.agentcert.dev) → Bitcoin (OP_RETURN anchor)

## Project Structure

```
src/agentcert/              # 19 source modules
├── keys.py                 # secp256k1 keypair generation
├── certificate.py          # Certificate creation/signing
├── chain.py                # Update, revoke, verify chain
├── anchor.py               # Bitcoin OP_RETURN anchoring (SegWit/bech32)
├── verify.py               # 6-check certificate verification
├── audit.py                # Signed hash-chained audit trails (8 ActionTypes)
├── audit_verify.py         # 6-check entry + 11-check trail verification
├── merkle.py               # Binary SHA-256 Merkle tree
├── batch.py                # Batch creation, anchoring, proof verification
├── client.py               # httpx SDK client (14 methods)
├── cli.py                  # 21 CLI commands (click)
├── types.py                # 18 types (2 IntEnums + 16 dataclasses)
├── exceptions.py           # 13 custom exceptions
├── integrations/
│   └── langchain.py        # Backward-compat shim (re-exports from agentcert-langchain)
└── service/
    ├── app.py              # FastAPI, 13 REST endpoints
    ├── models.py           # SQLite, 4 tables, 25 query methods
    ├── scheduler.py        # Background BatchScheduler
    ├── config.py           # ServiceConfig (env vars or JSON)
    ├── dashboard.py        # 8 dashboard routes
    ├── templates/          # 9 Jinja2 templates
    └── static/             # style.css + main.js
tests/                      # 15 files, 424 tests
packages/                       # Framework integration packages
├── agentcert-middleware/       # Shared base (storage, retry, trust, coordinator)
├── agentcert-langchain/        # LangChain integration (37 tests)
├── agentcert-crewai/           # CrewAI integration (37 tests)
└── agentcert-autogen/          # AutoGen integration (47 tests)
demo/                       # 5 demo agents
papers/                     # whitepaper.pdf, condensed.pdf
```

## Key Numbers

| Metric | Value |
|--------|-------|
| Tests | 424 (core) + 258 (framework packages) = 682 total |
| API exports | 72 |
| CLI commands | 21 |
| REST endpoints | 13 |
| Dashboard pages | 8 |

## Tech Stack

- **Crypto:** secp256k1, ECDSA, SHA-256 (Bitcoin-native)
- **SDK:** Python 3.11+, cryptography, requests, click
- **Service:** FastAPI, SQLite, Jinja2, uvicorn
- **Client:** httpx
- **Integration:** langchain-core, crewai, autogen-agentchat (all optional, via `pip install agentcert[langchain/crewai/autogen]`)
- **Bitcoin:** SegWit P2WPKH, Blockstream Esplora API
- **Testing:** pytest, responses (HTTP mocking)

## Coding Standards

- Type hints on ALL public functions (Python 3.11+ union syntax)
- Google-style docstrings on ALL public functions
- No bare `except:` — use custom exceptions from `exceptions.py`
- Frozen dataclasses for immutable types
- Parameterized SQL queries (no string concatenation)
- All tests mock HTTP calls (no network access required)
- JSON serialization: `sort_keys=True, separators=(',',':')`

## OP_RETURN Format

38 bytes: `AIT\0` (4B) + version `\x01` (1B) + type (1B) + SHA-256 hash (32B)
- `\x01` = MERKLE_ROOT
- `\x02` = IDENTITY_CERT
- `\x03` = REVOCATION

## Commands

```bash
pytest tests/                           # Core tests (424)
pytest packages/                        # Framework package tests (258)
pytest tests/ --cov=agentcert          # With coverage
agentcert service start --port 8932    # Start FastAPI server
agentcert --help                       # All CLI commands
pip install -e ".[dev]"                # Install with all deps
```
