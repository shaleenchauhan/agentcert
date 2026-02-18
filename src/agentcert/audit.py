"""Audit trail creation, logging, and persistence.

An audit trail is a tamper-evident, cryptographically signed log of actions
performed by an agent. Each entry is signed by the agent's private key and
chained to the previous entry via ``previous_entry_id``, forming a hash chain.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Sequence

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

from agentcert.exceptions import AuditError
from agentcert.types import (
    ActionType,
    AuditEntry,
    AuditTrailInfo,
    Certificate,
    KeyPair,
)


# ── Internal helpers ─────────────────────────────────────────────────────────


def _compute_body_bytes(body: dict[str, Any]) -> bytes:
    """Compute the canonical JSON encoding of an entry body."""
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _compute_entry_id(body_bytes: bytes) -> str:
    """Compute the entry_id as SHA-256 of the body bytes."""
    return hashlib.sha256(body_bytes).hexdigest()


def _sign_body(private_key: ec.EllipticCurvePrivateKey, body_bytes: bytes) -> str:
    """Sign the body bytes with ECDSA/SHA-256 and return the signature as hex."""
    signature = private_key.sign(body_bytes, ec.ECDSA(hashes.SHA256()))
    return signature.hex()


def _generate_trail_id(cert_id: str, agent_id: str, created: int) -> str:
    """Generate a deterministic trail_id from cert_id + agent_id + creation time."""
    seed = f"{cert_id}:{agent_id}:{created}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


# ── AuditTrail class ────────────────────────────────────────────────────────


class AuditTrail:
    """A mutable audit trail bound to a certificate and agent.

    Use :func:`create_audit_trail` to create a new trail, or
    :func:`load_trail` to load an existing one from disk.

    Attributes:
        trail_id: Unique trail identifier (SHA-256 hash).
        cert_id: The certificate this trail is bound to.
        agent_id: The agent whose actions are logged.
        agent_public_key: Compressed public key of the agent (hex).
        created: Unix timestamp of trail creation.
        entries: Ordered list of audit entries.
    """

    def __init__(
        self,
        trail_id: str,
        cert_id: str,
        agent_id: str,
        agent_public_key: str,
        created: int,
        entries: list[AuditEntry] | None = None,
    ) -> None:
        self.trail_id = trail_id
        self.cert_id = cert_id
        self.agent_id = agent_id
        self.agent_public_key = agent_public_key
        self.created = created
        self.entries: list[AuditEntry] = entries if entries is not None else []

    def to_dict(self) -> dict[str, Any]:
        """Serialize the trail to a plain dict for JSON encoding."""
        return {
            "trail_id": self.trail_id,
            "cert_id": self.cert_id,
            "agent_id": self.agent_id,
            "agent_public_key": self.agent_public_key,
            "created": self.created,
            "entries": [e.to_dict() for e in self.entries],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditTrail:
        """Deserialize from a plain dict."""
        return cls(
            trail_id=data["trail_id"],
            cert_id=data["cert_id"],
            agent_id=data["agent_id"],
            agent_public_key=data["agent_public_key"],
            created=data["created"],
            entries=[AuditEntry.from_dict(e) for e in data.get("entries", [])],
        )


# ── Public API ───────────────────────────────────────────────────────────────


def create_audit_trail(
    cert: Certificate,
    agent_keys: KeyPair,
    *,
    timestamp: int | None = None,
) -> AuditTrail:
    """Create a new audit trail bound to a certificate.

    The trail is linked to the certificate's cert_id and the agent's identity.
    The agent_keys must match the agent_public_key in the certificate.

    Args:
        cert: The certificate this audit trail is for.
        agent_keys: The agent's key pair.
        timestamp: Override the creation timestamp (Unix seconds). Defaults to now.

    Returns:
        A new AuditTrail with no entries.

    Raises:
        AuditError: If the agent keys don't match the certificate.
    """
    if agent_keys.public_key_hex != cert.agent_public_key:
        raise AuditError(
            "Agent key mismatch: agent_keys.public_key_hex does not match "
            "cert.agent_public_key"
        )

    created = timestamp if timestamp is not None else int(time.time())
    trail_id = _generate_trail_id(cert.cert_id, cert.agent_id, created)

    return AuditTrail(
        trail_id=trail_id,
        cert_id=cert.cert_id,
        agent_id=cert.agent_id,
        agent_public_key=cert.agent_public_key,
        created=created,
    )


def log_action(
    trail: AuditTrail,
    agent_keys: KeyPair,
    *,
    action_type: ActionType | int,
    action_summary: str,
    action_detail: dict[str, Any] | None = None,
    timestamp: int | None = None,
) -> AuditEntry:
    """Log a new action to the audit trail.

    The entry is signed by the agent's private key and chained to the
    previous entry. The trail is mutated in place (entry appended).

    Args:
        trail: The audit trail to append to.
        agent_keys: The agent's key pair (must match the trail).
        action_type: Category of the action (ActionType enum or int).
        action_summary: Brief human-readable description.
        action_detail: Structured details (default: empty dict).
        timestamp: Override the entry timestamp. Defaults to now.

    Returns:
        The newly created and signed AuditEntry.

    Raises:
        AuditError: If the agent keys don't match or the action_summary is empty.
    """
    if agent_keys.public_key_hex != trail.agent_public_key:
        raise AuditError(
            "Agent key mismatch: agent_keys.public_key_hex does not match "
            "trail.agent_public_key"
        )

    if not action_summary or not action_summary.strip():
        raise AuditError("action_summary must not be empty")

    now = timestamp if timestamp is not None else int(time.time())
    sequence = len(trail.entries)
    previous_entry_id = trail.entries[-1].entry_id if trail.entries else None
    detail = action_detail if action_detail is not None else {}

    # Build the entry body (everything except entry_id and agent_signature)
    body = {
        "trail_id": trail.trail_id,
        "sequence": sequence,
        "timestamp": now,
        "action_type": int(action_type),
        "action_summary": action_summary,
        "action_detail": detail,
        "agent_public_key": trail.agent_public_key,
        "agent_id": trail.agent_id,
        "cert_id": trail.cert_id,
        "previous_entry_id": previous_entry_id,
    }

    try:
        body_bytes = _compute_body_bytes(body)
        entry_id = _compute_entry_id(body_bytes)
        signature = _sign_body(agent_keys.private_key, body_bytes)
    except AuditError:
        raise
    except Exception as exc:
        raise AuditError(f"Failed to create audit entry: {exc}") from exc

    entry = AuditEntry(
        entry_id=entry_id,
        trail_id=trail.trail_id,
        sequence=sequence,
        timestamp=now,
        action_type=int(action_type),
        action_summary=action_summary,
        action_detail=detail,
        agent_public_key=trail.agent_public_key,
        agent_id=trail.agent_id,
        cert_id=trail.cert_id,
        previous_entry_id=previous_entry_id,
        agent_signature=signature,
    )

    trail.entries.append(entry)
    return entry


def get_trail_info(trail: AuditTrail) -> AuditTrailInfo:
    """Get summary metadata for an audit trail.

    Args:
        trail: The audit trail.

    Returns:
        An AuditTrailInfo with trail metadata.
    """
    return AuditTrailInfo(
        trail_id=trail.trail_id,
        cert_id=trail.cert_id,
        agent_id=trail.agent_id,
        entry_count=len(trail.entries),
        created=trail.created,
        last_entry=trail.entries[-1].timestamp if trail.entries else None,
    )


def get_trail_entries(
    trail: AuditTrail,
    *,
    action_type: ActionType | int | None = None,
    start: int | None = None,
    end: int | None = None,
) -> list[AuditEntry]:
    """Get entries from an audit trail with optional filtering.

    Args:
        trail: The audit trail.
        action_type: Filter by action type (optional).
        start: Start sequence number (inclusive, optional).
        end: End sequence number (inclusive, optional).

    Returns:
        List of matching AuditEntry objects.
    """
    entries = trail.entries

    if action_type is not None:
        action_int = int(action_type)
        entries = [e for e in entries if e.action_type == action_int]

    if start is not None:
        entries = [e for e in entries if e.sequence >= start]

    if end is not None:
        entries = [e for e in entries if e.sequence <= end]

    return entries


def save_trail(trail: AuditTrail, path: str | Path) -> None:
    """Save an audit trail to a JSON file.

    Args:
        trail: The audit trail to save.
        path: File path to write to.

    Raises:
        AuditError: If saving fails.
    """
    try:
        Path(path).write_text(
            json.dumps(trail.to_dict(), indent=2) + "\n", encoding="utf-8"
        )
    except Exception as exc:
        raise AuditError(f"Failed to save audit trail to {path}: {exc}") from exc


def load_trail(path: str | Path) -> AuditTrail:
    """Load an audit trail from a JSON file.

    Args:
        path: File path to read from.

    Returns:
        The loaded AuditTrail.

    Raises:
        AuditError: If loading or parsing fails.
    """
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return AuditTrail.from_dict(data)
    except Exception as exc:
        raise AuditError(f"Failed to load audit trail from {path}: {exc}") from exc
