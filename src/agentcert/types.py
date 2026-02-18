"""Data types for the AgentCert library."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import IntEnum
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey


class CertType(IntEnum):
    """Certificate type codes."""

    CREATION = 1
    UPDATE = 2
    REVOCATION = 3


class ActionType(IntEnum):
    """Audit trail action type codes.

    Categories of actions an agent can perform, logged in the audit trail.
    """

    API_CALL = 1
    TOOL_USE = 2
    DECISION = 3
    DATA_ACCESS = 4
    TRANSACTION = 5
    COMMUNICATION = 6
    ERROR = 7
    CUSTOM = 99


@dataclass(frozen=True)
class KeyPair:
    """A secp256k1 key pair.

    Attributes:
        private_key: The cryptography library private key object.
        public_key_hex: Compressed public key as a hex string (66 chars / 33 bytes).
    """

    private_key: EllipticCurvePrivateKey
    public_key_hex: str

    @property
    def identity(self) -> str:
        """Derive the identity (SHA-256 of the public key hex string)."""
        return hashlib.sha256(self.public_key_hex.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AgentMetadata:
    """Metadata describing an AI agent.

    Attributes:
        name: Human-readable agent name.
        model_hash: Hash of the model weights or code (e.g. "sha256:...").
        platform: Platform or framework (e.g. "langchain").
        capabilities: List of agent capabilities.
        constraints: List of operational constraints.
        risk_tier: Risk tier (1-5).
    """

    name: str
    model_hash: str
    platform: str
    capabilities: tuple[str, ...]
    constraints: tuple[str, ...]
    risk_tier: int

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict for JSON encoding."""
        return {
            "name": self.name,
            "model_hash": self.model_hash,
            "platform": self.platform,
            "capabilities": list(self.capabilities),
            "constraints": list(self.constraints),
            "risk_tier": self.risk_tier,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentMetadata:
        """Deserialize from a plain dict."""
        return cls(
            name=data["name"],
            model_hash=data["model_hash"],
            platform=data["platform"],
            capabilities=tuple(data["capabilities"]),
            constraints=tuple(data["constraints"]),
            risk_tier=data["risk_tier"],
        )


@dataclass(frozen=True)
class Certificate:
    """An AIT-1 agent identity certificate.

    Attributes:
        ait_version: Protocol version (always 1).
        cert_type: Certificate type (1=CREATION, 2=UPDATE, 3=REVOCATION).
        cert_id: SHA-256 hash of the certificate body.
        timestamp: Unix timestamp of certificate creation.
        expires: Unix timestamp of certificate expiration.
        agent_public_key: Compressed agent public key (hex).
        agent_id: SHA-256 of agent_public_key.
        creator_public_key: Compressed creator public key (hex).
        creator_id: SHA-256 of creator_public_key.
        agent_metadata: Agent metadata.
        previous_cert_id: ID of the previous certificate in the chain, or None.
        creator_signature: ECDSA signature over the certificate body (hex).
        revocation_reason: Reason for revocation (only set for REVOCATION certs).
    """

    ait_version: int
    cert_type: int
    cert_id: str
    timestamp: int
    expires: int
    agent_public_key: str
    agent_id: str
    creator_public_key: str
    creator_id: str
    agent_metadata: AgentMetadata
    previous_cert_id: str | None
    creator_signature: str
    revocation_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict matching the canonical certificate structure."""
        d: dict[str, Any] = {
            "ait_version": self.ait_version,
            "cert_type": self.cert_type,
            "cert_id": self.cert_id,
            "timestamp": self.timestamp,
            "expires": self.expires,
            "agent_public_key": self.agent_public_key,
            "agent_id": self.agent_id,
            "creator_public_key": self.creator_public_key,
            "creator_id": self.creator_id,
            "agent_metadata": self.agent_metadata.to_dict(),
            "previous_cert_id": self.previous_cert_id,
            "creator_signature": self.creator_signature,
        }
        if self.revocation_reason is not None:
            d["revocation_reason"] = self.revocation_reason
        return d

    def body_dict(self) -> dict[str, Any]:
        """Return the certificate body (all fields except cert_id and creator_signature).

        This is the data that gets hashed to produce cert_id and signed
        to produce creator_signature.
        """
        d = self.to_dict()
        d.pop("cert_id")
        d.pop("creator_signature")
        return d

    def body_bytes(self) -> bytes:
        """Return the canonical JSON-encoded body bytes."""
        return json.dumps(
            self.body_dict(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

    def canonical_bytes(self) -> bytes:
        """Return the canonical JSON encoding of the full certificate.

        This is what gets hashed for Bitcoin anchoring.
        """
        return json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Certificate:
        """Deserialize from a plain dict."""
        return cls(
            ait_version=data["ait_version"],
            cert_type=data["cert_type"],
            cert_id=data["cert_id"],
            timestamp=data["timestamp"],
            expires=data["expires"],
            agent_public_key=data["agent_public_key"],
            agent_id=data["agent_id"],
            creator_public_key=data["creator_public_key"],
            creator_id=data["creator_id"],
            agent_metadata=AgentMetadata.from_dict(data["agent_metadata"]),
            previous_cert_id=data["previous_cert_id"],
            creator_signature=data["creator_signature"],
            revocation_reason=data.get("revocation_reason"),
        )


@dataclass(frozen=True)
class AnchorReceipt:
    """Receipt from a Bitcoin anchoring operation.

    Attributes:
        txid: Bitcoin transaction ID.
        network: Bitcoin network ("testnet" or "mainnet").
        anchor_hash: SHA-256 hash of the full certificate (hex).
        op_return_hex: The full OP_RETURN payload (hex).
        cert_id: The cert_id of the anchored certificate.
    """

    txid: str
    network: str
    anchor_hash: str
    op_return_hex: str
    cert_id: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict."""
        return {
            "txid": self.txid,
            "network": self.network,
            "anchor_hash": self.anchor_hash,
            "op_return_hex": self.op_return_hex,
            "cert_id": self.cert_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AnchorReceipt:
        """Deserialize from a plain dict."""
        return cls(
            txid=data["txid"],
            network=data["network"],
            anchor_hash=data["anchor_hash"],
            op_return_hex=data["op_return_hex"],
            cert_id=data["cert_id"],
        )


@dataclass(frozen=True)
class VerificationCheck:
    """Result of a single verification check.

    Attributes:
        name: Check name (e.g. "cert_id_integrity").
        passed: Whether the check passed.
        detail: Human-readable description of the result.
    """

    name: str
    passed: bool
    detail: str


@dataclass(frozen=True)
class VerificationResult:
    """Aggregate result of certificate verification.

    Attributes:
        status: Overall status ("VALID" or "INVALID").
        checks: List of individual check results.
        cert_id: The cert_id that was verified.
    """

    status: str
    checks: tuple[VerificationCheck, ...]
    cert_id: str

    @property
    def valid(self) -> bool:
        """Whether the certificate is valid."""
        return self.status == "VALID"


@dataclass(frozen=True)
class ChainResult:
    """Result of certificate chain verification.

    Attributes:
        status: Chain status ("ACTIVE", "REVOKED", or "INVALID").
        checks: List of individual check results across the chain.
        chain_length: Number of certificates in the chain.
    """

    status: str
    checks: tuple[VerificationCheck, ...]
    chain_length: int

    @property
    def valid(self) -> bool:
        """Whether the chain is valid (ACTIVE or REVOKED, not INVALID)."""
        return self.status in ("ACTIVE", "REVOKED")


# ── Audit Trail Types ────────────────────────────────────────────────────────


@dataclass(frozen=True)
class AuditEntry:
    """A single entry in an agent's audit trail.

    Each entry is cryptographically signed by the agent and chained to the
    previous entry via ``previous_entry_id``, forming a tamper-evident log.

    Attributes:
        entry_id: SHA-256 hash of the entry body (all fields except entry_id
            and agent_signature).
        trail_id: Identifier linking this entry to a specific audit trail.
        sequence: Monotonically increasing sequence number (0-based).
        timestamp: Unix timestamp of when the action was logged.
        action_type: Category of the action (see ActionType enum).
        action_summary: Brief human-readable description of the action.
        action_detail: Structured details about the action.
        agent_public_key: Compressed public key of the signing agent (hex).
        agent_id: SHA-256 of agent_public_key.
        cert_id: The cert_id of the certificate this trail is bound to.
        previous_entry_id: entry_id of the prior entry, or None for the first.
        agent_signature: ECDSA signature over the entry body (hex).
    """

    entry_id: str
    trail_id: str
    sequence: int
    timestamp: int
    action_type: int
    action_summary: str
    action_detail: dict[str, Any]
    agent_public_key: str
    agent_id: str
    cert_id: str
    previous_entry_id: str | None
    agent_signature: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict for JSON encoding."""
        return {
            "entry_id": self.entry_id,
            "trail_id": self.trail_id,
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "action_type": self.action_type,
            "action_summary": self.action_summary,
            "action_detail": self.action_detail,
            "agent_public_key": self.agent_public_key,
            "agent_id": self.agent_id,
            "cert_id": self.cert_id,
            "previous_entry_id": self.previous_entry_id,
            "agent_signature": self.agent_signature,
        }

    def body_dict(self) -> dict[str, Any]:
        """Return the entry body (all fields except entry_id and agent_signature).

        This is the data that gets hashed to produce entry_id and signed
        to produce agent_signature.
        """
        d = self.to_dict()
        d.pop("entry_id")
        d.pop("agent_signature")
        return d

    def body_bytes(self) -> bytes:
        """Return the canonical JSON-encoded body bytes."""
        return json.dumps(
            self.body_dict(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditEntry:
        """Deserialize from a plain dict."""
        return cls(
            entry_id=data["entry_id"],
            trail_id=data["trail_id"],
            sequence=data["sequence"],
            timestamp=data["timestamp"],
            action_type=data["action_type"],
            action_summary=data["action_summary"],
            action_detail=data["action_detail"],
            agent_public_key=data["agent_public_key"],
            agent_id=data["agent_id"],
            cert_id=data["cert_id"],
            previous_entry_id=data["previous_entry_id"],
            agent_signature=data["agent_signature"],
        )


@dataclass(frozen=True)
class AuditTrailInfo:
    """Summary metadata for an audit trail.

    Attributes:
        trail_id: Unique trail identifier (SHA-256 hash).
        cert_id: The certificate this trail is bound to.
        agent_id: The agent whose actions are logged.
        entry_count: Number of entries in the trail.
        created: Unix timestamp of the first entry (or trail creation).
        last_entry: Unix timestamp of the most recent entry, or None.
    """

    trail_id: str
    cert_id: str
    agent_id: str
    entry_count: int
    created: int
    last_entry: int | None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict."""
        return {
            "trail_id": self.trail_id,
            "cert_id": self.cert_id,
            "agent_id": self.agent_id,
            "entry_count": self.entry_count,
            "created": self.created,
            "last_entry": self.last_entry,
        }


@dataclass(frozen=True)
class AuditVerificationCheck:
    """Result of a single audit entry verification check.

    Attributes:
        name: Check name (e.g. "entry_id_integrity").
        passed: Whether the check passed.
        detail: Human-readable description of the result.
    """

    name: str
    passed: bool
    detail: str


@dataclass(frozen=True)
class AuditVerificationResult:
    """Result of verifying a single audit entry.

    Attributes:
        status: "VALID" or "INVALID".
        checks: Individual check results.
        entry_id: The entry_id that was verified.
    """

    status: str
    checks: tuple[AuditVerificationCheck, ...]
    entry_id: str

    @property
    def valid(self) -> bool:
        """Whether the entry is valid."""
        return self.status == "VALID"


@dataclass(frozen=True)
class AuditTrailVerificationResult:
    """Result of verifying an entire audit trail.

    Attributes:
        status: "VALID" or "INVALID".
        checks: All checks across the trail.
        trail_id: The trail that was verified.
        entry_count: Number of entries verified.
    """

    status: str
    checks: tuple[AuditVerificationCheck, ...]
    trail_id: str
    entry_count: int

    @property
    def valid(self) -> bool:
        """Whether the trail is valid."""
        return self.status == "VALID"


# ── Merkle Batch Types ─────────────────────────────────────────────────────


@dataclass(frozen=True)
class MerkleProof:
    """Proof of inclusion for a single leaf in a Merkle tree.

    Attributes:
        leaf_hash: Hex string of the leaf hash.
        leaf_index: Position of the leaf in the tree.
        siblings: Hex strings of sibling hashes, bottom to top.
        directions: "left" or "right" — which side each sibling is on.
        root: Hex string of the Merkle root.
    """

    leaf_hash: str
    leaf_index: int
    siblings: tuple[str, ...]
    directions: tuple[str, ...]
    root: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict for JSON encoding."""
        return {
            "leaf_hash": self.leaf_hash,
            "leaf_index": self.leaf_index,
            "siblings": list(self.siblings),
            "directions": list(self.directions),
            "root": self.root,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MerkleProof:
        """Deserialize from a plain dict."""
        return cls(
            leaf_hash=data["leaf_hash"],
            leaf_index=data["leaf_index"],
            siblings=tuple(data["siblings"]),
            directions=tuple(data["directions"]),
            root=data["root"],
        )


@dataclass(frozen=True)
class Batch:
    """A batch of items anchored together via Merkle tree.

    Attributes:
        batch_id: SHA-256 of the Merkle root + timestamp.
        merkle_root: Hex string of the Merkle root.
        item_count: Number of items in the batch.
        item_hashes: Hex strings of all leaf hashes, in order.
        timestamp: When the batch was created (Unix seconds).
        anchor_receipt: Set after anchoring, None before.
    """

    batch_id: str
    merkle_root: str
    item_count: int
    item_hashes: tuple[str, ...]
    timestamp: int
    anchor_receipt: AnchorReceipt | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict for JSON encoding."""
        d: dict[str, Any] = {
            "batch_id": self.batch_id,
            "merkle_root": self.merkle_root,
            "item_count": self.item_count,
            "item_hashes": list(self.item_hashes),
            "timestamp": self.timestamp,
            "anchor_receipt": self.anchor_receipt.to_dict() if self.anchor_receipt else None,
        }
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Batch:
        """Deserialize from a plain dict."""
        receipt_data = data.get("anchor_receipt")
        return cls(
            batch_id=data["batch_id"],
            merkle_root=data["merkle_root"],
            item_count=data["item_count"],
            item_hashes=tuple(data["item_hashes"]),
            timestamp=data["timestamp"],
            anchor_receipt=AnchorReceipt.from_dict(receipt_data) if receipt_data else None,
        )


@dataclass(frozen=True)
class BatchVerificationCheck:
    """Result of a single batch verification check.

    Attributes:
        name: Check name (e.g. "merkle_proof").
        passed: Whether the check passed.
        detail: Human-readable description of the result.
    """

    name: str
    passed: bool
    detail: str


@dataclass(frozen=True)
class BatchVerificationResult:
    """Result of verifying an item against a batch anchor.

    Attributes:
        valid: Whether all applicable checks passed.
        status: "VALID", "INVALID", or "NOT_ANCHORED".
        item_hash: The item hash that was verified.
        merkle_root: The Merkle root of the batch.
        proof_valid: Whether the Merkle proof checks out.
        anchor_valid: Whether the anchor checks out (None if not anchored).
        checks: List of individual checks.
    """

    valid: bool
    status: str
    item_hash: str
    merkle_root: str
    proof_valid: bool
    anchor_valid: bool | None
    checks: tuple[BatchVerificationCheck, ...]
