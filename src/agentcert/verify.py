"""Certificate verification: all 6 checks with structured results."""

from __future__ import annotations

import hashlib
import time

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

from agentcert.anchor import compute_anchor_hash
from agentcert.certificate import _compute_body_bytes, _compute_cert_id
from agentcert.types import (
    AnchorReceipt,
    Certificate,
    VerificationCheck,
    VerificationResult,
)


# ── Individual checks ────────────────────────────────────────────────────────


def check_cert_id(cert: Certificate) -> VerificationCheck:
    """Check 1: cert_id integrity — SHA-256(body) matches cert_id."""
    body_bytes = cert.body_bytes()
    expected = _compute_cert_id(body_bytes)
    passed = cert.cert_id == expected
    detail = (
        "cert_id matches body hash"
        if passed
        else f"cert_id mismatch: expected {expected[:16]}..., got {cert.cert_id[:16]}..."
    )
    return VerificationCheck(name="cert_id_integrity", passed=passed, detail=detail)


def check_creator_id(cert: Certificate) -> VerificationCheck:
    """Check 2: creator_id derivation — SHA-256(creator_public_key) matches creator_id."""
    expected = hashlib.sha256(cert.creator_public_key.encode("utf-8")).hexdigest()
    passed = cert.creator_id == expected
    detail = (
        "creator_id correctly derived from creator_public_key"
        if passed
        else f"creator_id mismatch: expected {expected[:16]}..., got {cert.creator_id[:16]}..."
    )
    return VerificationCheck(
        name="creator_id_derivation", passed=passed, detail=detail
    )


def check_agent_id(cert: Certificate) -> VerificationCheck:
    """Check 3: agent_id derivation — SHA-256(agent_public_key) matches agent_id."""
    expected = hashlib.sha256(cert.agent_public_key.encode("utf-8")).hexdigest()
    passed = cert.agent_id == expected
    detail = (
        "agent_id correctly derived from agent_public_key"
        if passed
        else f"agent_id mismatch: expected {expected[:16]}..., got {cert.agent_id[:16]}..."
    )
    return VerificationCheck(name="agent_id_derivation", passed=passed, detail=detail)


def check_signature(cert: Certificate) -> VerificationCheck:
    """Check 4: Creator signature — ECDSA verification against creator_public_key."""
    try:
        pub_key_bytes = bytes.fromhex(cert.creator_public_key)
        pub_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256K1(), pub_key_bytes
        )
        sig_bytes = bytes.fromhex(cert.creator_signature)
        body_bytes = cert.body_bytes()
        pub_key.verify(sig_bytes, body_bytes, ec.ECDSA(hashes.SHA256()))
        return VerificationCheck(
            name="creator_signature", passed=True, detail="Signature valid"
        )
    except InvalidSignature:
        return VerificationCheck(
            name="creator_signature", passed=False, detail="Signature invalid"
        )
    except Exception as exc:
        return VerificationCheck(
            name="creator_signature",
            passed=False,
            detail=f"Signature verification error: {exc}",
        )


def check_anchor(cert: Certificate, receipt: AnchorReceipt) -> VerificationCheck:
    """Check 5: Anchor integrity — certificate hash matches anchored hash."""
    expected = compute_anchor_hash(cert).hex()
    passed = receipt.anchor_hash == expected
    detail = (
        f"Anchor hash matches (tx: {receipt.txid[:16]}...)"
        if passed
        else (
            f"Anchor hash mismatch: expected {expected[:16]}..., "
            f"got {receipt.anchor_hash[:16]}..."
        )
    )
    return VerificationCheck(name="anchor_integrity", passed=passed, detail=detail)


def check_expiration(
    cert: Certificate, *, now: int | None = None
) -> VerificationCheck:
    """Check 6: Expiration — current time < expires."""
    current = now if now is not None else int(time.time())
    passed = current < cert.expires
    if passed:
        remaining = cert.expires - current
        days = remaining // 86400
        detail = f"Certificate valid ({days} day(s) remaining)"
    else:
        elapsed = current - cert.expires
        days = elapsed // 86400
        detail = f"Certificate expired ({days} day(s) ago)"
    return VerificationCheck(name="expiration", passed=passed, detail=detail)


# ── Full verification ────────────────────────────────────────────────────────


def verify(
    cert: Certificate,
    receipt: AnchorReceipt | None = None,
    *,
    now: int | None = None,
) -> VerificationResult:
    """Run all verification checks on a certificate.

    Runs 6 checks (5 if no receipt is provided):
        1. cert_id integrity
        2. creator_id derivation
        3. agent_id derivation
        4. Creator signature (ECDSA)
        5. Anchor integrity (skipped if no receipt)
        6. Expiration

    Args:
        cert: The certificate to verify.
        receipt: The anchor receipt (optional; skip anchor check if absent).
        now: Override the current time for expiration check (Unix seconds).

    Returns:
        A VerificationResult with status "VALID" or "INVALID" and individual checks.
    """
    checks: list[VerificationCheck] = [
        check_cert_id(cert),
        check_creator_id(cert),
        check_agent_id(cert),
        check_signature(cert),
    ]

    if receipt is not None:
        checks.append(check_anchor(cert, receipt))
    else:
        checks.append(
            VerificationCheck(
                name="anchor_integrity",
                passed=True,
                detail="Anchor check skipped (no receipt provided)",
            )
        )

    checks.append(check_expiration(cert, now=now))

    all_passed = all(c.passed for c in checks)
    status = "VALID" if all_passed else "INVALID"

    return VerificationResult(
        status=status, checks=tuple(checks), cert_id=cert.cert_id
    )
