# AgentCert

Bitcoin-anchored identity certificates for AI agents.

AgentCert is the open-source Python implementation of **AIT-1** (Agent Identity Certificates) from the Agent Internet Trust protocol. It lets developers create cryptographically signed, Bitcoin-anchored identity certificates that bind a **creator** (human or company) to an **agent** (autonomous software) — with verifiable metadata, capabilities, constraints, and a risk tier.

Every certificate is signed with ECDSA/secp256k1, hashed with SHA-256, and optionally anchored to Bitcoin via OP_RETURN. Any third party can verify the certificate using only math and the blockchain.

**Proven on Bitcoin testnet:** [`6b3b8cd6...`](https://blockstream.info/testnet/tx/6b3b8cd6624d833e98add57823a7a8ba72134a9de4aae6b7eb7617ebd7cb771c)

## Install

```bash
pip install agentcert
```

Or from source:

```bash
git clone https://github.com/shaleenchauhan/agentcert.git
cd agentcert
pip install -e ".[dev]"
```

Requires Python 3.11+. Dependencies: `cryptography`, `requests`, `click`.

Optional extras:

```bash
pip install agentcert[langchain]   # LangChain integration
pip install agentcert[service]     # Anchoring service (FastAPI + uvicorn)
pip install agentcert[client]      # SDK client (httpx)
```

## Quickstart

```python
import agentcert

# Generate key pairs
creator_keys = agentcert.generate_keys()
agent_keys = agentcert.generate_keys()

# Create a signed certificate
cert = agentcert.create_certificate(
    creator_keys=creator_keys,
    agent_keys=agent_keys,
    name="procurement-agent-v1",
    platform="langchain",
    model_hash="sha256:a1b2c3d4e5f6",
    capabilities=["procurement", "negotiation"],
    constraints=["max-transaction-50000-usd"],
    risk_tier=3,
    expires_days=90,
)

# Verify it
result = agentcert.verify(cert)
assert result.valid
print(result.status)  # "VALID"

# Save to disk
agentcert.save_certificate(cert, "agent.cert.json")
agentcert.save_keys(creator_keys, "creator.keys.json")
```

## CLI

AgentCert ships a full command-line interface:

```bash
# Generate keys
agentcert keygen -o creator.keys.json
agentcert keygen -o agent.keys.json

# Create a certificate
agentcert create \
  --creator-keys creator.keys.json \
  --agent-keys agent.keys.json \
  --name "my-agent" \
  --platform "langchain" \
  --capabilities "procurement,negotiation" \
  --constraints "max-50k-usd" \
  --risk-tier 3 \
  --expires 90d \
  -o cert.json

# Inspect it
agentcert inspect cert.json

# Verify it
agentcert verify cert.json

# Update (add capabilities, new version in the chain)
agentcert update cert.json \
  --creator-keys creator.keys.json \
  --add-capability "invoicing" \
  -o cert-v2.json

# Revoke
agentcert revoke cert-v2.json \
  --creator-keys creator.keys.json \
  --reason "Decommissioned" \
  -o revoke.json

# Verify the full chain
agentcert verify-chain cert.json cert-v2.json revoke.json

# --- Audit Trail ---

# Create an audit trail bound to a certificate
agentcert audit create cert.json --agent-keys agent.keys.json -o trail.json

# Log actions
agentcert audit log trail.json --agent-keys agent.keys.json \
  --action-type API_CALL --summary "Called weather API" \
  --detail '{"url": "https://api.weather.com", "status": 200}'

agentcert audit log trail.json --agent-keys agent.keys.json \
  --action-type DECISION --summary "Selected cheapest vendor"

agentcert audit log trail.json --agent-keys agent.keys.json \
  --action-type TRANSACTION --summary "Placed order for 42 widgets" \
  --detail '{"vendor": "Acme", "amount": 42.0}'

# Verify the trail (with optional certificate binding)
agentcert audit verify trail.json --cert cert.json

# Inspect the trail
agentcert audit inspect trail.json --entries
```

## SDK API

All functions are available at the top level — no submodule imports needed.

### Keys

```python
creator_keys = agentcert.generate_keys()
agentcert.save_keys(creator_keys, "creator.keys.json")
creator_keys = agentcert.load_keys("creator.keys.json")

# Derive Bitcoin address (for funding anchor transactions)
address = agentcert.derive_bitcoin_address(creator_keys, network="testnet")
```

### Certificates

```python
cert = agentcert.create_certificate(
    creator_keys=creator_keys,
    agent_keys=agent_keys,
    name="my-agent",
    platform="langchain",
    model_hash="sha256:...",
    capabilities=["task-a", "task-b"],
    constraints=["spending-limit-1000"],
    risk_tier=2,
    expires_days=90,
)

agentcert.save_certificate(cert, "agent.cert.json")
cert = agentcert.load_certificate("agent.cert.json")
```

### Verification

The verifier runs 6 checks (all must pass for `VALID`):

1. **cert_id integrity** — SHA-256(body) matches cert_id
2. **creator_id derivation** — SHA-256(creator_public_key) matches creator_id
3. **agent_id derivation** — SHA-256(agent_public_key) matches agent_id
4. **Creator signature** — ECDSA verification against creator_public_key
5. **Anchor integrity** — certificate hash matches the anchored hash (if receipt provided)
6. **Expiration** — current time < expires

```python
result = agentcert.verify(cert)                # without anchor
result = agentcert.verify(cert, receipt)        # with anchor receipt

print(result.status)  # "VALID" or "INVALID"
print(result.valid)   # True / False

for check in result.checks:
    print(f"[{'PASS' if check.passed else 'FAIL'}] {check.name}: {check.detail}")
```

### Chain Operations

Certificates form a linked chain: create &rarr; update &rarr; ... &rarr; revoke.

```python
# Update (carries over unchanged fields)
updated = agentcert.update_certificate(
    previous_cert=cert,
    creator_keys=creator_keys,
    capabilities=["procurement", "negotiation", "invoicing"],
)

# Revoke (terminates the chain)
revocation = agentcert.revoke_certificate(
    previous_cert=updated,
    creator_keys=creator_keys,
    reason="Decommissioned",
)

# Verify the full chain
chain_result = agentcert.verify_chain([cert, updated, revocation])
print(chain_result.status)  # "REVOKED"
print(chain_result.valid)   # True (REVOKED is a valid terminal state)
```

### Audit Trail

Create a tamper-evident log of every action an agent takes, cryptographically signed and hash-chained:

```python
# Create an audit trail bound to a certificate
trail = agentcert.create_audit_trail(cert, agent_keys)

# Log actions (each entry is signed by the agent and chained to the previous)
agentcert.log_action(
    trail, agent_keys,
    action_type=agentcert.ActionType.API_CALL,
    action_summary="Queried vendor pricing API",
    action_detail={"url": "https://api.vendors.example/prices", "status": 200},
)

agentcert.log_action(
    trail, agent_keys,
    action_type=agentcert.ActionType.DECISION,
    action_summary="Selected cheapest vendor: Acme Corp",
)

agentcert.log_action(
    trail, agent_keys,
    action_type=agentcert.ActionType.TRANSACTION,
    action_summary="Placed purchase order for 500 widgets",
    action_detail={"vendor": "Acme Corp", "quantity": 500, "total": 6250.00},
)

# Verify the full trail (11 checks)
result = agentcert.verify_audit_trail(trail, cert)
print(result.status)  # "VALID"

# Verify a single entry (6 checks)
entry_result = agentcert.verify_audit_entry(trail.entries[0], cert)

# Inspect
info = agentcert.get_trail_info(trail)
print(info.entry_count)  # 3

# Filter entries
api_calls = agentcert.get_trail_entries(trail, action_type=agentcert.ActionType.API_CALL)
recent = agentcert.get_trail_entries(trail, start=1, end=2)

# Save / Load
agentcert.save_trail(trail, "trail.json")
trail = agentcert.load_trail("trail.json")
```

Action types: `API_CALL`, `TOOL_USE`, `DECISION`, `DATA_ACCESS`, `TRANSACTION`, `COMMUNICATION`, `ERROR`, `CUSTOM`.

Entry verification runs 6 checks: entry_id integrity, agent_id derivation, agent signature, sequence validity, timestamp validity, and certificate binding.

Trail verification runs 11 checks: non-empty trail, trail_id/cert_id/agent consistency, first-entry linkage, hash-chain integrity, sequence continuity, timestamp ordering, all entry IDs, all signatures, and certificate binding.

### Merkle Batching

Batch multiple audit entries into a Merkle tree and anchor the root in a single Bitcoin transaction. Any individual entry is then independently provable against the on-chain root via its O(log n) Merkle proof.

Without batching: 1,000 entries = 1,000 Bitcoin transactions (~$5,000 in fees).
With batching: 1,000 entries = 1 Bitcoin transaction (~$5 in fees).

```python
# Batch all trail entries into a Merkle tree
batch, tree = agentcert.create_batch_from_trail(trail)
print(f"Merkle root: {batch.merkle_root}")
print(f"Items: {batch.item_count}")

# Anchor the batch root to Bitcoin (1 transaction for all entries)
batch = agentcert.anchor_batch(batch, creator_keys=creator_keys, network="testnet")
print(f"Anchored: {batch.anchor_receipt.txid}")

# Get proof for a specific entry
entries = agentcert.get_trail_entries(trail)
proof = agentcert.get_proof_for_entry(entries[3], tree, batch)
print(f"Proof: {len(proof.siblings)} siblings")  # O(log n) hashes

# Verify: is this entry anchored on Bitcoin?
result = agentcert.verify_entry_in_batch(entries[3], proof, batch, certificate=cert)
print(result.status)  # "VALID"

# Save everything
agentcert.save_batch(batch, "batch.json")
agentcert.save_proofs(
    {e.entry_id: agentcert.get_proof_for_entry(e, tree, batch) for e in entries},
    "proofs.json",
)

# Later: verify from saved files
batch = agentcert.load_batch("batch.json")
proofs = agentcert.load_proofs("proofs.json")
result = agentcert.verify_batch_proof(entries[3].entry_id, proofs[entries[3].entry_id], batch)
```

You can also batch arbitrary items (hex hashes, bytes, or dicts):

```python
batch, tree = agentcert.create_batch(["aabb...", {"key": "value"}, raw_bytes])
```

CLI:

```bash
agentcert batch create trail.json -o batch.json
agentcert batch anchor batch.json --creator-keys ck.json --network testnet
agentcert batch verify batch.json --entry-id <hash>
agentcert batch inspect batch.json
agentcert batch proof batch.json --entry-id <hash> -o proof.json
```

### Anchoring Service

Run a service that receives signed audit entries, batches them into Merkle trees, and anchors roots to Bitcoin. Developers send signed entries to the API instead of managing Bitcoin transactions themselves.

**Trust model:** Private keys stay on the developer's machine. Entries are signed before being sent. The service cannot forge entries.

```bash
# Start the service
agentcert service start --port 8932 --network testnet

# Admin commands
agentcert service health
agentcert service stats
agentcert service force-batch
```

SDK client:

```python
from agentcert.client import AgentCertClient

with AgentCertClient("http://localhost:8932") as client:
    # Register certificate
    client.register_certificate(cert)

    # Submit signed entries
    result = client.submit_trail(trail)
    print(f"Accepted: {result['accepted']}")

    # Force a batch cycle
    batch = client.force_batch()

    # Get Merkle proof for an entry
    proof = client.get_proof(entry_id)
    if proof:
        print(f"Siblings: {len(proof.siblings)}")

    # Full verification via service
    verification = client.verify_entry(entry_id)
    print(f"Status: {verification['status']}")

    # Health check
    health = client.health()
```

API endpoints:

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/certificates` | Register a certificate |
| GET | `/api/v1/certificates/{id}` | Get a certificate |
| POST | `/api/v1/entries` | Submit signed entries |
| GET | `/api/v1/entries/{id}` | Get an entry |
| GET | `/api/v1/trails/{id}` | Get trail entries |
| GET | `/api/v1/proofs/{id}` | Get Merkle proof |
| GET | `/api/v1/verify/{id}` | Full verification |
| GET | `/api/v1/batches/{id}` | Get batch details |
| GET | `/api/v1/batches/latest` | Latest batch |
| POST | `/api/v1/admin/force-batch` | Force batch cycle |
| GET | `/api/v1/health` | Health check |
| GET | `/api/v1/stats` | Statistics |

### LangChain Integration

Add identity certificates and signed audit trails to any LangChain agent with a few lines of code. The middleware automatically captures all LLM calls, tool invocations, and agent decisions as signed audit entries. Works with both LangGraph agents and legacy `AgentExecutor`.

```python
from agentcert.integrations.langchain import AgentCertMiddleware

# Create middleware (generates certificate + audit trail)
middleware = AgentCertMiddleware(
    creator_keys="creator.keys.json",    # path or KeyPair
    agent_keys="agent.keys.json",        # path or KeyPair
    agent_name="procurement-agent-v1",
    capabilities=["procurement", "negotiation"],
    constraints=["max-transaction-50000-usd"],
    risk_tier=3,
)

# Pass the handler via config — works with any LangChain runnable
handler = middleware.get_handler()
result = agent.invoke(
    {"messages": [{"role": "user", "content": "Find the cheapest supplier"}]},
    config={"callbacks": [handler]},
)

# Verify the audit trail (11 checks)
verification = middleware.verify()
print(verification.status)  # "VALID"

# Inspect entries
for entry in middleware.get_entries():
    print(f"[{entry.sequence}] {entry.action_summary}")

# Filter by type
tools = middleware.get_entries(action_type=agentcert.ActionType.TOOL_USE)

# Save everything (certificate + trail)
middleware.save("./agent-audit/")

# Reload and continue logging
loaded = AgentCertMiddleware.load("./agent-audit/", agent_keys="agent.keys.json")
```

For legacy `AgentExecutor` objects, you can also use `wrap()` to inject the callback automatically:

```python
executor = middleware.wrap(executor)
result = executor.invoke({"input": "..."})
```

**Privacy:** LLM prompts, responses, and tool outputs are stored as SHA-256 hashes only — the trail proves what happened without exposing raw data.

**Log levels:** `"minimal"` (tools + decisions only), `"standard"` (default — adds LLM calls), `"verbose"` (adds chain events).

### Bitcoin Anchoring

Anchor a certificate to Bitcoin via an OP_RETURN transaction:

```python
# The creator's Bitcoin address must be funded first
address = agentcert.derive_bitcoin_address(creator_keys, network="testnet")
print(f"Fund this address: {address}")

# Anchor (builds, signs, and broadcasts a Bitcoin transaction)
receipt = agentcert.anchor(cert, creator_keys=creator_keys, network="testnet")
print(receipt.txid)

# Save the receipt for later verification
agentcert.save_receipt(receipt, "receipt.json")
receipt = agentcert.load_receipt("receipt.json")
```

The OP_RETURN payload is 38 bytes:

```
[AIT\0]   protocol tag     (4 bytes)
[0x01]    version           (1 byte)
[0x02]    IDENTITY_CERT     (1 byte)
[...]     SHA-256 hash      (32 bytes)
```

## Certificate Structure

```json
{
  "ait_version": 1,
  "cert_type": 1,
  "cert_id": "<SHA-256 of body>",
  "timestamp": 1739750000,
  "expires": 1747526000,
  "agent_public_key": "<33-byte compressed public key, hex>",
  "agent_id": "<SHA-256 of agent_public_key>",
  "creator_public_key": "<33-byte compressed public key, hex>",
  "creator_id": "<SHA-256 of creator_public_key>",
  "agent_metadata": {
    "name": "my-agent",
    "model_hash": "sha256:...",
    "platform": "langchain",
    "capabilities": ["procurement", "negotiation"],
    "constraints": ["max-transaction-50000-usd"],
    "risk_tier": 3
  },
  "previous_cert_id": null,
  "creator_signature": "<ECDSA DER signature, hex>"
}
```

| Field | Description |
|-------|-------------|
| `cert_type` | 1 = CREATION, 2 = UPDATE, 3 = REVOCATION |
| `cert_id` | SHA-256 of the certificate body (all fields except `cert_id` and `creator_signature`) |
| `creator_signature` | ECDSA/secp256k1 signature over the same body |
| `previous_cert_id` | Links to the prior certificate in the chain (null for the first) |

## How It Works

**Signing:** The cert_id and creator_signature are computed over the same canonical JSON body. The cert_id verifies integrity (any tampering changes the hash). The signature verifies authenticity (only the creator's private key can produce it). Both are independently checkable by any third party.

**Anchoring:** The anchor hash is SHA-256 of the *complete* certificate (including cert_id and signature). This goes into a Bitcoin OP_RETURN output. If anything is modified after anchoring, the anchor check fails.

**Chain verification** checks: each cert's `previous_cert_id` links to the prior cert's `cert_id`, the same creator throughout, valid signatures on every cert, and the final cert's type determines the chain status (ACTIVE or REVOKED).

For the full protocol design, threat model, and technical specification, see the [Research](#research) section.

## Development

```bash
git clone https://github.com/shaleenchauhan/agentcert.git
cd agentcert
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,langchain,service,client]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=agentcert --cov-report=term-missing

# Run examples
python examples/quickstart.py
python examples/full_lifecycle.py
python examples/audit_trail_demo.py
python examples/langchain_demo.py
python examples/batch_anchor_demo.py
python examples/service_demo.py
```

## Project Structure

```
agentcert/
  src/agentcert/
    __init__.py          # Public API (72 exports, no submodule imports needed)
    keys.py              # Key generation, save, load (secp256k1)
    certificate.py       # Certificate creation, signing, serialization
    chain.py             # Update, revoke, chain verification
    anchor.py            # Bitcoin OP_RETURN + Blockstream API
    verify.py            # 6-check certificate verification
    audit.py             # Audit trail creation, logging, persistence
    audit_verify.py      # 6-check entry + 11-check trail verification
    merkle.py            # Binary Merkle tree construction + proof generation
    batch.py             # Batch creation, anchoring, proof verification
    client.py            # SDK client for the anchoring service (httpx)
    service/
      app.py             # FastAPI application (12 endpoints)
      models.py          # SQLite database layer
      scheduler.py       # Background batching + anchoring scheduler
      config.py          # ServiceConfig dataclass
    integrations/
      langchain.py       # AgentCertCallbackHandler + AgentCertMiddleware
    types.py             # KeyPair, Certificate, AuditEntry, Batch, MerkleProof, etc.
    exceptions.py        # Custom exception hierarchy
    cli.py               # Click-based CLI (21 commands)
  tests/                 # 396 tests
  examples/              # quickstart.py, full_lifecycle.py, audit_trail_demo.py, langchain_demo.py, batch_anchor_demo.py, service_demo.py
  papers/                # Whitepaper, technical spec, condensed overview
```

## Technical Decisions

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Language | Python 3.11+ | AI/ML ecosystem standard |
| Curve | secp256k1 | Bitcoin-native, same keys for signing and anchoring |
| Signatures | ECDSA | Proven; Schnorr migration path later |
| Hashing | SHA-256 | Bitcoin-native |
| Serialization | JSON (deterministic) | `sort_keys=True, separators=(',',':')` |
| CLI | Click | Mature, clean subcommand support |
| Bitcoin API | Blockstream | No auth, free, reliable |
| Dependencies | 3 runtime | `cryptography`, `requests`, `click` |

## Research

AgentCert implements AIT-1 from the Agent Internet Trust protocol. The research papers cover the full protocol design, adversarial analysis, and technical specification:

- [**Whitepaper**](papers/whitepaper.pdf) — Protocol motivation, architecture, trust model, and threat analysis
- [**Condensed Overview**](papers/condensed.pdf) — Shorter summary of the protocol and its design rationale
- [**Technical Specification**](papers/technical-spec.pdf) — Formal specification of certificate structure, signing, anchoring, and verification

## License

MIT
