"""Audit trail verification: entry-level and trail-level checks.

verify_audit_entry() runs 6 checks on a single entry:
    1. entry_id integrity — SHA-256(body) matches entry_id
    2. agent_id derivation — SHA-256(agent_public_key) matches agent_id
    3. Agent signature — ECDSA verification against agent_public_key
    4. Sequence validity — sequence is a non-negative integer
    5. Timestamp validity — timestamp is a positive integer
    6. Certificate binding — cert_id matches the provided certificate (if given)

verify_audit_trail() runs 11 checks across the entire trail:
    1. Trail non-empty — at least one entry
    2. trail_id consistency — all entries share the same trail_id
    3. cert_id consistency — all entries share the same cert_id
    4. Agent consistency — all entries share the same agent_id and agent_public_key
    5. First entry linkage — first entry has previous_entry_id=None
    6. Chain integrity — each entry's previous_entry_id matches prior entry's entry_id
    7. Sequence continuity — sequences are 0, 1, 2, ... with no gaps
    8. Timestamp ordering — timestamps are non-decreasing
    9. All entry_id integrity checks pass
    10. All agent signatures valid
    11. Certificate binding — trail cert_id matches provided certificate (if given)
"""

from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

from agentcert.audit import _compute_body_bytes, _compute_entry_id
from agentcert.types import (
    AuditEntry,
    AuditVerificationCheck,
    AuditVerificationResult,
    AuditTrailVerificationResult,
    Certificate,
)
from agentcert.audit import AuditTrail


# ── Single-entry checks ─────────────────────────────────────────────────────


def _check_entry_id(entry: AuditEntry) -> AuditVerificationCheck:
    """Check 1: entry_id integrity — SHA-256(body) matches entry_id."""
    body_bytes = entry.body_bytes()
    expected = _compute_entry_id(body_bytes)
    passed = entry.entry_id == expected
    detail = (
        "entry_id matches body hash"
        if passed
        else f"entry_id mismatch: expected {expected[:16]}..., got {entry.entry_id[:16]}..."
    )
    return AuditVerificationCheck(name="entry_id_integrity", passed=passed, detail=detail)


def _check_agent_id(entry: AuditEntry) -> AuditVerificationCheck:
    """Check 2: agent_id derivation — SHA-256(agent_public_key) matches agent_id."""
    expected = hashlib.sha256(entry.agent_public_key.encode("utf-8")).hexdigest()
    passed = entry.agent_id == expected
    detail = (
        "agent_id correctly derived from agent_public_key"
        if passed
        else f"agent_id mismatch: expected {expected[:16]}..., got {entry.agent_id[:16]}..."
    )
    return AuditVerificationCheck(name="agent_id_derivation", passed=passed, detail=detail)


def _check_agent_signature(entry: AuditEntry) -> AuditVerificationCheck:
    """Check 3: Agent signature — ECDSA verification against agent_public_key."""
    try:
        pub_key_bytes = bytes.fromhex(entry.agent_public_key)
        pub_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256K1(), pub_key_bytes
        )
        sig_bytes = bytes.fromhex(entry.agent_signature)
        body_bytes = entry.body_bytes()
        pub_key.verify(sig_bytes, body_bytes, ec.ECDSA(hashes.SHA256()))
        return AuditVerificationCheck(
            name="agent_signature", passed=True, detail="Signature valid"
        )
    except InvalidSignature:
        return AuditVerificationCheck(
            name="agent_signature", passed=False, detail="Signature invalid"
        )
    except Exception as exc:
        return AuditVerificationCheck(
            name="agent_signature",
            passed=False,
            detail=f"Signature verification error: {exc}",
        )


def _check_sequence(entry: AuditEntry) -> AuditVerificationCheck:
    """Check 4: Sequence validity — sequence is a non-negative integer."""
    passed = isinstance(entry.sequence, int) and entry.sequence >= 0
    detail = (
        f"Sequence valid ({entry.sequence})"
        if passed
        else f"Invalid sequence: {entry.sequence}"
    )
    return AuditVerificationCheck(name="sequence_validity", passed=passed, detail=detail)


def _check_timestamp(entry: AuditEntry) -> AuditVerificationCheck:
    """Check 5: Timestamp validity — timestamp is a positive integer."""
    passed = isinstance(entry.timestamp, int) and entry.timestamp > 0
    detail = (
        f"Timestamp valid ({entry.timestamp})"
        if passed
        else f"Invalid timestamp: {entry.timestamp}"
    )
    return AuditVerificationCheck(name="timestamp_validity", passed=passed, detail=detail)


def _check_cert_binding(
    entry: AuditEntry, cert: Certificate
) -> AuditVerificationCheck:
    """Check 6: Certificate binding — cert_id matches the provided certificate."""
    passed = entry.cert_id == cert.cert_id
    detail = (
        "cert_id matches certificate"
        if passed
        else f"cert_id mismatch: entry has {entry.cert_id[:16]}..., cert has {cert.cert_id[:16]}..."
    )
    return AuditVerificationCheck(name="cert_binding", passed=passed, detail=detail)


# ── Single-entry verification ────────────────────────────────────────────────


def verify_audit_entry(
    entry: AuditEntry,
    cert: Certificate | None = None,
) -> AuditVerificationResult:
    """Verify a single audit entry.

    Runs 6 checks (5 if no certificate is provided):
        1. entry_id integrity
        2. agent_id derivation
        3. Agent signature (ECDSA)
        4. Sequence validity
        5. Timestamp validity
        6. Certificate binding (skipped if no certificate)

    Args:
        entry: The audit entry to verify.
        cert: The certificate to check binding against (optional).

    Returns:
        An AuditVerificationResult with status and individual checks.
    """
    checks: list[AuditVerificationCheck] = [
        _check_entry_id(entry),
        _check_agent_id(entry),
        _check_agent_signature(entry),
        _check_sequence(entry),
        _check_timestamp(entry),
    ]

    if cert is not None:
        checks.append(_check_cert_binding(entry, cert))
    else:
        checks.append(
            AuditVerificationCheck(
                name="cert_binding",
                passed=True,
                detail="Certificate binding check skipped (no certificate provided)",
            )
        )

    all_passed = all(c.passed for c in checks)
    status = "VALID" if all_passed else "INVALID"

    return AuditVerificationResult(
        status=status, checks=tuple(checks), entry_id=entry.entry_id
    )


# ── Trail-level checks ──────────────────────────────────────────────────────


def verify_audit_trail(
    trail: AuditTrail,
    cert: Certificate | None = None,
) -> AuditTrailVerificationResult:
    """Verify an entire audit trail.

    Runs 11 checks:
        1.  Trail non-empty
        2.  trail_id consistency
        3.  cert_id consistency
        4.  Agent consistency (agent_id and agent_public_key)
        5.  First entry linkage (previous_entry_id is None)
        6.  Chain integrity (previous_entry_id chain)
        7.  Sequence continuity (0, 1, 2, ...)
        8.  Timestamp ordering (non-decreasing)
        9.  All entry_id integrity checks pass
        10. All agent signatures valid
        11. Certificate binding (skipped if no certificate)

    Args:
        trail: The audit trail to verify.
        cert: The certificate to check binding against (optional).

    Returns:
        An AuditTrailVerificationResult with status and all checks.
    """
    checks: list[AuditVerificationCheck] = []
    entries = trail.entries

    # Check 1: Trail non-empty
    if not entries:
        checks.append(AuditVerificationCheck(
            name="trail_non_empty", passed=False, detail="Trail has no entries"
        ))
        return AuditTrailVerificationResult(
            status="INVALID",
            checks=tuple(checks),
            trail_id=trail.trail_id,
            entry_count=0,
        )

    checks.append(AuditVerificationCheck(
        name="trail_non_empty", passed=True,
        detail=f"Trail has {len(entries)} entry(ies)"
    ))

    # Check 2: trail_id consistency
    bad_trail_ids = [e for e in entries if e.trail_id != trail.trail_id]
    if not bad_trail_ids:
        checks.append(AuditVerificationCheck(
            name="trail_id_consistency", passed=True,
            detail="All entries reference the correct trail_id"
        ))
    else:
        checks.append(AuditVerificationCheck(
            name="trail_id_consistency", passed=False,
            detail=f"{len(bad_trail_ids)} entry(ies) have mismatched trail_id"
        ))

    # Check 3: cert_id consistency
    bad_cert_ids = [e for e in entries if e.cert_id != trail.cert_id]
    if not bad_cert_ids:
        checks.append(AuditVerificationCheck(
            name="cert_id_consistency", passed=True,
            detail="All entries reference the correct cert_id"
        ))
    else:
        checks.append(AuditVerificationCheck(
            name="cert_id_consistency", passed=False,
            detail=f"{len(bad_cert_ids)} entry(ies) have mismatched cert_id"
        ))

    # Check 4: Agent consistency
    bad_agents = [
        e for e in entries
        if e.agent_id != trail.agent_id or e.agent_public_key != trail.agent_public_key
    ]
    if not bad_agents:
        checks.append(AuditVerificationCheck(
            name="agent_consistency", passed=True,
            detail="All entries have consistent agent identity"
        ))
    else:
        checks.append(AuditVerificationCheck(
            name="agent_consistency", passed=False,
            detail=f"{len(bad_agents)} entry(ies) have mismatched agent identity"
        ))

    # Check 5: First entry linkage
    first = entries[0]
    if first.previous_entry_id is None:
        checks.append(AuditVerificationCheck(
            name="first_entry_linkage", passed=True,
            detail="First entry has previous_entry_id=None"
        ))
    else:
        checks.append(AuditVerificationCheck(
            name="first_entry_linkage", passed=False,
            detail=f"First entry has previous_entry_id={first.previous_entry_id[:16]}... (expected None)"
        ))

    # Check 6: Chain integrity
    chain_ok = True
    chain_detail = "Hash chain is intact"
    for i in range(1, len(entries)):
        if entries[i].previous_entry_id != entries[i - 1].entry_id:
            chain_ok = False
            chain_detail = (
                f"Chain broken at entry {i}: previous_entry_id does not match "
                f"entry {i - 1}'s entry_id"
            )
            break
    checks.append(AuditVerificationCheck(
        name="chain_integrity", passed=chain_ok, detail=chain_detail
    ))

    # Check 7: Sequence continuity
    seq_ok = True
    seq_detail = f"Sequences are continuous (0..{len(entries) - 1})"
    for i, entry in enumerate(entries):
        if entry.sequence != i:
            seq_ok = False
            seq_detail = f"Sequence gap at entry {i}: expected {i}, got {entry.sequence}"
            break
    checks.append(AuditVerificationCheck(
        name="sequence_continuity", passed=seq_ok, detail=seq_detail
    ))

    # Check 8: Timestamp ordering
    ts_ok = True
    ts_detail = "Timestamps are non-decreasing"
    for i in range(1, len(entries)):
        if entries[i].timestamp < entries[i - 1].timestamp:
            ts_ok = False
            ts_detail = (
                f"Timestamp regression at entry {i}: "
                f"{entries[i].timestamp} < {entries[i - 1].timestamp}"
            )
            break
    checks.append(AuditVerificationCheck(
        name="timestamp_ordering", passed=ts_ok, detail=ts_detail
    ))

    # Check 9: All entry_id integrity
    bad_ids = []
    for entry in entries:
        check = _check_entry_id(entry)
        if not check.passed:
            bad_ids.append(entry.sequence)
    if not bad_ids:
        checks.append(AuditVerificationCheck(
            name="all_entry_ids", passed=True,
            detail=f"All {len(entries)} entry_id(s) match their body hashes"
        ))
    else:
        checks.append(AuditVerificationCheck(
            name="all_entry_ids", passed=False,
            detail=f"entry_id mismatch at sequence(s): {bad_ids}"
        ))

    # Check 10: All agent signatures
    bad_sigs = []
    for entry in entries:
        check = _check_agent_signature(entry)
        if not check.passed:
            bad_sigs.append(entry.sequence)
    if not bad_sigs:
        checks.append(AuditVerificationCheck(
            name="all_signatures", passed=True,
            detail=f"All {len(entries)} signature(s) valid"
        ))
    else:
        checks.append(AuditVerificationCheck(
            name="all_signatures", passed=False,
            detail=f"Invalid signature at sequence(s): {bad_sigs}"
        ))

    # Check 11: Certificate binding
    if cert is not None:
        if trail.cert_id == cert.cert_id:
            checks.append(AuditVerificationCheck(
                name="cert_binding", passed=True,
                detail="Trail cert_id matches certificate"
            ))
        else:
            checks.append(AuditVerificationCheck(
                name="cert_binding", passed=False,
                detail=f"Trail cert_id {trail.cert_id[:16]}... does not match cert {cert.cert_id[:16]}..."
            ))
    else:
        checks.append(AuditVerificationCheck(
            name="cert_binding", passed=True,
            detail="Certificate binding check skipped (no certificate provided)"
        ))

    all_passed = all(c.passed for c in checks)
    status = "VALID" if all_passed else "INVALID"

    return AuditTrailVerificationResult(
        status=status,
        checks=tuple(checks),
        trail_id=trail.trail_id,
        entry_count=len(entries),
    )
