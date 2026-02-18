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
