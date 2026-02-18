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

__version__ = "0.2.0"

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

# ── Audit Trail ─────────────────────────────────────────────────────────────

from agentcert.audit import (
    AuditTrail,
    create_audit_trail,
    get_trail_entries,
    get_trail_info,
    load_trail,
    log_action,
    save_trail,
)

from agentcert.audit_verify import verify_audit_entry, verify_audit_trail

# ── Types ────────────────────────────────────────────────────────────────────

from agentcert.types import (
    ActionType,
    AgentMetadata,
    AnchorReceipt,
    AuditEntry,
    AuditTrailInfo,
    AuditTrailVerificationResult,
    AuditVerificationCheck,
    AuditVerificationResult,
    Certificate,
    CertType,
    ChainResult,
    KeyPair,
    VerificationCheck,
    VerificationResult,
)

# ── Integrations (optional) ───────────────────────────────────────────────────

try:
    from agentcert.integrations.langchain import (
        AgentCertCallbackHandler,
        AgentCertMiddleware,
    )
except ImportError:
    pass

# ── Exceptions ───────────────────────────────────────────────────────────────

from agentcert.exceptions import (
    AgentCertError,
    AnchorError,
    AuditError,
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
    # Audit Trail
    "AuditTrail",
    "create_audit_trail",
    "log_action",
    "get_trail_info",
    "get_trail_entries",
    "save_trail",
    "load_trail",
    "verify_audit_entry",
    "verify_audit_trail",
    # Types
    "KeyPair",
    "Certificate",
    "AgentMetadata",
    "CertType",
    "AnchorReceipt",
    "VerificationResult",
    "VerificationCheck",
    "ChainResult",
    "ActionType",
    "AuditEntry",
    "AuditTrailInfo",
    "AuditVerificationCheck",
    "AuditVerificationResult",
    "AuditTrailVerificationResult",
    # Integrations (available when langchain is installed)
    "AgentCertCallbackHandler",
    "AgentCertMiddleware",
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
    "AuditError",
]
