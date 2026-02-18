"""Certificate chain operations: update, revoke, and chain verification."""

from __future__ import annotations

import time
from typing import Sequence

from agentcert.certificate import _compute_body_bytes, _compute_cert_id, _sign_body
from agentcert.exceptions import ChainError
from agentcert.types import (
    AgentMetadata,
    Certificate,
    CertType,
    ChainResult,
    KeyPair,
    VerificationCheck,
)
from agentcert.verify import check_cert_id, check_signature


def update_certificate(
    *,
    previous_cert: Certificate,
    creator_keys: KeyPair,
    name: str | None = None,
    platform: str | None = None,
    model_hash: str | None = None,
    capabilities: Sequence[str] | None = None,
    constraints: Sequence[str] | None = None,
    risk_tier: int | None = None,
    expires_days: int | None = None,
    timestamp: int | None = None,
) -> Certificate:
    """Create an update certificate that extends a previous certificate.

    Fields not explicitly provided are carried over from the previous certificate.
    The update is signed by the creator's private key.

    Args:
        previous_cert: The certificate to update.
        creator_keys: The creator's key pair (must match the original creator).
        name: New agent name (or None to keep previous).
        platform: New platform (or None to keep previous).
        model_hash: New model hash (or None to keep previous).
        capabilities: New capabilities list (or None to keep previous).
        constraints: New constraints list (or None to keep previous).
        risk_tier: New risk tier (or None to keep previous).
        expires_days: Days until expiration (or None to use same duration as previous).
        timestamp: Override creation timestamp (or None for current time).

    Returns:
        A signed update Certificate with cert_type=UPDATE.

    Raises:
        ChainError: If the update is invalid.
    """
    if creator_keys.public_key_hex != previous_cert.creator_public_key:
        raise ChainError("Creator key does not match the previous certificate's creator")

    if previous_cert.cert_type == CertType.REVOCATION:
        raise ChainError("Cannot update a revoked certificate")

    prev_meta = previous_cert.agent_metadata
    new_risk = risk_tier if risk_tier is not None else prev_meta.risk_tier
    if new_risk < 1 or new_risk > 5:
        raise ChainError(f"risk_tier must be between 1 and 5, got {new_risk}")

    now = timestamp if timestamp is not None else int(time.time())

    if expires_days is not None:
        if expires_days < 1:
            raise ChainError(f"expires_days must be positive, got {expires_days}")
        expires = now + (expires_days * 86400)
    else:
        # Carry over the same duration as the previous certificate
        original_duration = previous_cert.expires - previous_cert.timestamp
        expires = now + original_duration

    metadata = AgentMetadata(
        name=name if name is not None else prev_meta.name,
        model_hash=model_hash if model_hash is not None else prev_meta.model_hash,
        platform=platform if platform is not None else prev_meta.platform,
        capabilities=tuple(capabilities) if capabilities is not None else prev_meta.capabilities,
        constraints=tuple(constraints) if constraints is not None else prev_meta.constraints,
        risk_tier=new_risk,
    )

    body = {
        "ait_version": 1,
        "cert_type": CertType.UPDATE,
        "timestamp": now,
        "expires": expires,
        "agent_public_key": previous_cert.agent_public_key,
        "agent_id": previous_cert.agent_id,
        "creator_public_key": creator_keys.public_key_hex,
        "creator_id": creator_keys.identity,
        "agent_metadata": metadata.to_dict(),
        "previous_cert_id": previous_cert.cert_id,
    }

    body_bytes = _compute_body_bytes(body)
    cert_id = _compute_cert_id(body_bytes)
    signature = _sign_body(creator_keys.private_key, body_bytes)

    return Certificate(
        ait_version=1,
        cert_type=CertType.UPDATE,
        cert_id=cert_id,
        timestamp=now,
        expires=expires,
        agent_public_key=previous_cert.agent_public_key,
        agent_id=previous_cert.agent_id,
        creator_public_key=creator_keys.public_key_hex,
        creator_id=creator_keys.identity,
        agent_metadata=metadata,
        previous_cert_id=previous_cert.cert_id,
        creator_signature=signature,
    )


def revoke_certificate(
    *,
    previous_cert: Certificate,
    creator_keys: KeyPair,
    reason: str,
    timestamp: int | None = None,
) -> Certificate:
    """Create a revocation certificate for a previous certificate.

    The revocation is signed by the creator's private key. Once revoked,
    the certificate chain is permanently terminated.

    Args:
        previous_cert: The certificate to revoke.
        creator_keys: The creator's key pair (must match the original creator).
        reason: Human-readable reason for revocation.
        timestamp: Override creation timestamp (or None for current time).

    Returns:
        A signed revocation Certificate with cert_type=REVOCATION.

    Raises:
        ChainError: If the revocation is invalid.
    """
    if creator_keys.public_key_hex != previous_cert.creator_public_key:
        raise ChainError("Creator key does not match the previous certificate's creator")

    if previous_cert.cert_type == CertType.REVOCATION:
        raise ChainError("Certificate is already revoked")

    if not reason or not reason.strip():
        raise ChainError("Revocation reason must not be empty")

    now = timestamp if timestamp is not None else int(time.time())
    # Revocations keep the same expiry as the previous cert
    expires = previous_cert.expires

    body: dict = {
        "ait_version": 1,
        "cert_type": CertType.REVOCATION,
        "timestamp": now,
        "expires": expires,
        "agent_public_key": previous_cert.agent_public_key,
        "agent_id": previous_cert.agent_id,
        "creator_public_key": creator_keys.public_key_hex,
        "creator_id": creator_keys.identity,
        "agent_metadata": previous_cert.agent_metadata.to_dict(),
        "previous_cert_id": previous_cert.cert_id,
        "revocation_reason": reason,
    }

    body_bytes = _compute_body_bytes(body)
    cert_id = _compute_cert_id(body_bytes)
    signature = _sign_body(creator_keys.private_key, body_bytes)

    return Certificate(
        ait_version=1,
        cert_type=CertType.REVOCATION,
        cert_id=cert_id,
        timestamp=now,
        expires=expires,
        agent_public_key=previous_cert.agent_public_key,
        agent_id=previous_cert.agent_id,
        creator_public_key=creator_keys.public_key_hex,
        creator_id=creator_keys.identity,
        agent_metadata=previous_cert.agent_metadata,
        previous_cert_id=previous_cert.cert_id,
        creator_signature=signature,
        revocation_reason=reason,
    )


def verify_chain(certs: Sequence[Certificate]) -> ChainResult:
    """Verify a certificate chain.

    Checks that:
    - The chain is non-empty.
    - The first certificate is a CREATION cert.
    - Each subsequent cert's previous_cert_id matches the prior cert's cert_id.
    - All certificates share the same creator and agent.
    - Every certificate has a valid cert_id and signature.
    - The chain status is determined by the final cert's type.

    Args:
        certs: Ordered list of certificates forming the chain.

    Returns:
        A ChainResult with status ACTIVE, REVOKED, or INVALID.
    """
    checks: list[VerificationCheck] = []

    if not certs:
        checks.append(VerificationCheck(
            name="chain_non_empty", passed=False, detail="Chain is empty",
        ))
        return ChainResult(status="INVALID", checks=tuple(checks), chain_length=0)

    checks.append(VerificationCheck(
        name="chain_non_empty", passed=True,
        detail=f"Chain has {len(certs)} certificate(s)",
    ))

    # First cert must be CREATION
    first = certs[0]
    is_creation = first.cert_type == CertType.CREATION
    checks.append(VerificationCheck(
        name="first_is_creation", passed=is_creation,
        detail="First certificate is CREATION" if is_creation else (
            f"First certificate has type {first.cert_type}, expected CREATION (1)"
        ),
    ))

    if first.previous_cert_id is not None:
        checks.append(VerificationCheck(
            name="first_no_previous", passed=False,
            detail="First certificate should not have a previous_cert_id",
        ))
    else:
        checks.append(VerificationCheck(
            name="first_no_previous", passed=True,
            detail="First certificate has no previous_cert_id",
        ))

    # Verify each certificate individually
    for i, cert in enumerate(certs):
        prefix = f"cert[{i}]"

        # cert_id integrity
        id_check = check_cert_id(cert)
        checks.append(VerificationCheck(
            name=f"{prefix}_cert_id", passed=id_check.passed, detail=id_check.detail,
        ))

        # Signature
        sig_check = check_signature(cert)
        checks.append(VerificationCheck(
            name=f"{prefix}_signature", passed=sig_check.passed, detail=sig_check.detail,
        ))

    # Chain linkage and consistency
    creator_pub = first.creator_public_key
    agent_pub = first.agent_public_key

    for i in range(1, len(certs)):
        prev = certs[i - 1]
        curr = certs[i]
        prefix = f"cert[{i}]"

        # previous_cert_id linkage
        linked = curr.previous_cert_id == prev.cert_id
        checks.append(VerificationCheck(
            name=f"{prefix}_linkage", passed=linked,
            detail="Linked to previous certificate" if linked else (
                f"previous_cert_id mismatch: expected {prev.cert_id[:16]}..., "
                f"got {curr.previous_cert_id[:16] if curr.previous_cert_id else 'None'}..."
            ),
        ))

        # Same creator
        same_creator = curr.creator_public_key == creator_pub
        checks.append(VerificationCheck(
            name=f"{prefix}_same_creator", passed=same_creator,
            detail="Same creator as chain origin" if same_creator else "Creator mismatch",
        ))

        # Same agent
        same_agent = curr.agent_public_key == agent_pub
        checks.append(VerificationCheck(
            name=f"{prefix}_same_agent", passed=same_agent,
            detail="Same agent as chain origin" if same_agent else "Agent mismatch",
        ))

        # Type ordering: no certs after a REVOCATION
        if prev.cert_type == CertType.REVOCATION:
            checks.append(VerificationCheck(
                name=f"{prefix}_post_revocation", passed=False,
                detail="Certificate follows a revocation (chain should have ended)",
            ))

    # Determine overall status
    all_passed = all(c.passed for c in checks)
    if not all_passed:
        status = "INVALID"
    elif certs[-1].cert_type == CertType.REVOCATION:
        status = "REVOKED"
    else:
        status = "ACTIVE"

    return ChainResult(status=status, checks=tuple(checks), chain_length=len(certs))
