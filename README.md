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
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=agentcert --cov-report=term-missing

# Run examples
python examples/quickstart.py
python examples/full_lifecycle.py
```

## Project Structure

```
agentcert/
  src/agentcert/
    __init__.py          # Public API (33 exports, no submodule imports needed)
    keys.py              # Key generation, save, load (secp256k1)
    certificate.py       # Certificate creation, signing, serialization
    chain.py             # Update, revoke, chain verification
    anchor.py            # Bitcoin OP_RETURN + Blockstream API
    verify.py            # 6-check verification with structured results
    types.py             # KeyPair, Certificate, AgentMetadata, etc.
    exceptions.py        # Custom exception hierarchy
    cli.py               # Click-based CLI (8 commands)
  tests/                 # 119 tests, 93% coverage
  examples/              # quickstart.py, full_lifecycle.py
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
