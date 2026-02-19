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

__version__ = "0.3.0"

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

# ── Merkle Batching ────────────────────────────────────────────────────────

from agentcert.merkle import MerkleTree

from agentcert.batch import (
    anchor_batch,
    create_batch,
    create_batch_from_entries,
    create_batch_from_trail,
    get_proof_for_entry,
    get_proof_for_item,
    load_batch,
    load_proofs,
    save_batch,
    save_proofs,
    verify_batch_proof,
    verify_entry_in_batch,
)

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
    Batch,
    BatchVerificationCheck,
    BatchVerificationResult,
    Certificate,
    CertType,
    ChainResult,
    KeyPair,
    MerkleProof,
    VerificationCheck,
    VerificationResult,
)

# ── Client (optional — requires httpx) ───────────────────────────────────────

try:
    from agentcert.client import AgentCertClient
except ImportError:
    pass

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
    BatchError,
    CertificateError,
    ChainError,
    ClientError,
    KeyGenerationError,
    KeyLoadError,
    SerializationError,
    ServiceError,
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
    # Merkle Batching
    "MerkleTree",
    "create_batch",
    "create_batch_from_entries",
    "create_batch_from_trail",
    "anchor_batch",
    "get_proof_for_entry",
    "get_proof_for_item",
    "verify_batch_proof",
    "verify_entry_in_batch",
    "save_batch",
    "load_batch",
    "save_proofs",
    "load_proofs",
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
    "MerkleProof",
    "Batch",
    "BatchVerificationCheck",
    "BatchVerificationResult",
    # Client (available when httpx is installed)
    "AgentCertClient",
    # Integrations (available when langchain is installed)
    "AgentCertCallbackHandler",
    "AgentCertMiddleware",
    # Exceptions
    "AgentCertError",
    "KeyGenerationError",
    "KeyLoadError",
    "CertificateError",
    "ClientError",
    "SignatureError",
    "ServiceError",
    "AnchorError",
    "VerificationError",
    "ChainError",
    "SerializationError",
    "AuditError",
    "BatchError",
]
