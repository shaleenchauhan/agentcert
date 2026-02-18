"""AgentCert — Bitcoin-anchored identity certificates for AI agents.

Create, sign, anchor, and verify identity certificates for AI agents
using secp256k1 cryptography and Bitcoin OP_RETURN transactions.

Basic usage::

    import agentcert

    creator_keys = agentcert.generate_keys()
    agent_keys = agentcert.generate_keys()

    cert = agentcert.create_certificate(
        creator_keys=creator_keys,
        agent_keys=agent_keys,
        name="my-agent",
        platform="langchain",
        model_hash="sha256:...",
        capabilities=["task-x"],
        constraints=["max-cost-100"],
        risk_tier=2,
        expires_days=90,
    )

    result = agentcert.verify(cert)
    assert result.valid
"""

__version__ = "0.1.0"

# ── Keys ─────────────────────────────────────────────────────────────────────

from agentcert.keys import generate_keys, load_keys, save_keys

# ── Certificates ─────────────────────────────────────────────────────────────

from agentcert.certificate import (
    create_certificate,
    load_certificate,
    save_certificate,
)

# ── Chain operations ─────────────────────────────────────────────────────────

from agentcert.chain import revoke_certificate, update_certificate, verify_chain

# ── Anchoring ────────────────────────────────────────────────────────────────

from agentcert.anchor import (
    anchor,
    build_op_return_payload,
    compute_anchor_hash,
    derive_bitcoin_address,
    load_receipt,
    save_receipt,
)

# ── Verification ─────────────────────────────────────────────────────────────

from agentcert.verify import verify

# ── Types ────────────────────────────────────────────────────────────────────

from agentcert.types import (
    AgentMetadata,
    AnchorReceipt,
    Certificate,
    CertType,
    ChainResult,
    KeyPair,
    VerificationCheck,
    VerificationResult,
)

# ── Exceptions ───────────────────────────────────────────────────────────────

from agentcert.exceptions import (
    AgentCertError,
    AnchorError,
    CertificateError,
    ChainError,
    KeyGenerationError,
    KeyLoadError,
    SerializationError,
    SignatureError,
    VerificationError,
)

__all__ = [
    # Keys
    "generate_keys",
    "save_keys",
    "load_keys",
    # Certificates
    "create_certificate",
    "save_certificate",
    "load_certificate",
    # Chain
    "update_certificate",
    "revoke_certificate",
    "verify_chain",
    # Anchoring
    "anchor",
    "compute_anchor_hash",
    "build_op_return_payload",
    "derive_bitcoin_address",
    "save_receipt",
    "load_receipt",
    # Verification
    "verify",
    # Types
    "KeyPair",
    "Certificate",
    "AgentMetadata",
    "CertType",
    "AnchorReceipt",
    "VerificationResult",
    "VerificationCheck",
    "ChainResult",
    # Exceptions
    "AgentCertError",
    "KeyGenerationError",
    "KeyLoadError",
    "CertificateError",
    "SignatureError",
    "AnchorError",
    "VerificationError",
    "ChainError",
    "SerializationError",
]
