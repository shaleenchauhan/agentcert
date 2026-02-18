"""Certificate creation, signing, and serialization."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Sequence

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

from agentcert.exceptions import CertificateError, SerializationError
from agentcert.types import AgentMetadata, Certificate, CertType, KeyPair


def _compute_body_bytes(body: dict) -> bytes:
    """Compute the canonical JSON encoding of a certificate body."""
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _compute_cert_id(body_bytes: bytes) -> str:
    """Compute the cert_id as SHA-256 of the body bytes."""
    return hashlib.sha256(body_bytes).hexdigest()


def _sign_body(private_key: ec.EllipticCurvePrivateKey, body_bytes: bytes) -> str:
    """Sign the body bytes with ECDSA/SHA-256 and return the signature as hex."""
    signature = private_key.sign(body_bytes, ec.ECDSA(hashes.SHA256()))
    return signature.hex()


def create_certificate(
    *,
    creator_keys: KeyPair,
    agent_keys: KeyPair,
    name: str,
    platform: str,
    model_hash: str,
    capabilities: Sequence[str],
    constraints: Sequence[str],
    risk_tier: int,
    expires_days: int,
    timestamp: int | None = None,
) -> Certificate:
    """Create a new agent identity certificate (cert_type=CREATION).

    The certificate is signed by the creator's private key and includes
    a computed cert_id (SHA-256 of the body).

    Args:
        creator_keys: The creator's key pair (used for signing).
        agent_keys: The agent's key pair (public key embedded in cert).
        name: Human-readable agent name.
        platform: Platform or framework name.
        model_hash: Hash of the model (e.g. "sha256:...").
        capabilities: List of agent capabilities.
        constraints: List of operational constraints.
        risk_tier: Risk tier (1-5).
        expires_days: Number of days until the certificate expires.
        timestamp: Override the creation timestamp (Unix seconds). Defaults to now.

    Returns:
        A signed Certificate.

    Raises:
        CertificateError: If certificate creation fails.
    """
    if risk_tier < 1 or risk_tier > 5:
        raise CertificateError(f"risk_tier must be between 1 and 5, got {risk_tier}")
    if expires_days < 1:
        raise CertificateError(f"expires_days must be positive, got {expires_days}")

    try:
        now = timestamp if timestamp is not None else int(time.time())
        expires = now + (expires_days * 86400)

        metadata = AgentMetadata(
            name=name,
            model_hash=model_hash,
            platform=platform,
            capabilities=tuple(capabilities),
            constraints=tuple(constraints),
            risk_tier=risk_tier,
        )

        # Build the body dict (everything except cert_id and creator_signature)
        body = {
            "ait_version": 1,
            "cert_type": CertType.CREATION,
            "timestamp": now,
            "expires": expires,
            "agent_public_key": agent_keys.public_key_hex,
            "agent_id": agent_keys.identity,
            "creator_public_key": creator_keys.public_key_hex,
            "creator_id": creator_keys.identity,
            "agent_metadata": metadata.to_dict(),
            "previous_cert_id": None,
        }

        body_bytes = _compute_body_bytes(body)
        cert_id = _compute_cert_id(body_bytes)
        signature = _sign_body(creator_keys.private_key, body_bytes)

        return Certificate(
            ait_version=1,
            cert_type=CertType.CREATION,
            cert_id=cert_id,
            timestamp=now,
            expires=expires,
            agent_public_key=agent_keys.public_key_hex,
            agent_id=agent_keys.identity,
            creator_public_key=creator_keys.public_key_hex,
            creator_id=creator_keys.identity,
            agent_metadata=metadata,
            previous_cert_id=None,
            creator_signature=signature,
        )
    except CertificateError:
        raise
    except Exception as exc:
        raise CertificateError(f"Failed to create certificate: {exc}") from exc


def save_certificate(cert: Certificate, path: str | Path) -> None:
    """Save a certificate to a JSON file.

    Args:
        cert: The certificate to save.
        path: File path to write to.

    Raises:
        SerializationError: If saving fails.
    """
    try:
        Path(path).write_text(
            json.dumps(cert.to_dict(), indent=2) + "\n", encoding="utf-8"
        )
    except Exception as exc:
        raise SerializationError(f"Failed to save certificate to {path}: {exc}") from exc


def load_certificate(path: str | Path) -> Certificate:
    """Load a certificate from a JSON file.

    Args:
        path: File path to read from.

    Returns:
        The loaded Certificate.

    Raises:
        SerializationError: If loading or parsing fails.
    """
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return Certificate.from_dict(data)
    except Exception as exc:
        raise SerializationError(
            f"Failed to load certificate from {path}: {exc}"
        ) from exc
