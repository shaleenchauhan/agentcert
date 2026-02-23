"""Trust verification module for agent-to-agent certificate exchange.

This is the core of the AgentCert demo — before any transaction happens,
both agents verify each other's certificates.
"""

import time

import agentcert


class TrustVerificationResult:
    def __init__(self, trusted: bool, reason: str, checks: dict):
        self.trusted = trusted
        self.reason = reason
        self.checks = checks


def verify_counterparty(
    their_cert,
    required_capabilities: list[str] | None = None,
    max_risk_tier: int | None = None,
) -> TrustVerificationResult:
    """Verify a counterparty agent's certificate before transacting.

    This is the trust handshake — the core of what AgentCert enables.
    """
    checks = {}

    # 1. Verify certificate integrity and signature
    result = agentcert.verify(their_cert)
    checks["certificate_valid"] = result.valid
    if not result.valid:
        failed = [c.name for c in result.checks if not c.passed]
        return TrustVerificationResult(
            trusted=False,
            reason=f"Certificate verification failed: {', '.join(failed)}",
            checks=checks,
        )

    # 2. Check not expired
    checks["not_expired"] = their_cert.expires > time.time()
    if not checks["not_expired"]:
        return TrustVerificationResult(
            trusted=False, reason="Certificate expired", checks=checks,
        )

    # 3. Check not revoked (cert_type 3 = REVOCATION)
    checks["not_revoked"] = their_cert.cert_type != 3
    if not checks["not_revoked"]:
        return TrustVerificationResult(
            trusted=False, reason="Certificate has been revoked", checks=checks,
        )

    # 4. Check required capabilities
    if required_capabilities:
        agent_caps = list(their_cert.agent_metadata.capabilities)
        missing = [c for c in required_capabilities if c not in agent_caps]
        checks["has_required_capabilities"] = len(missing) == 0
        if missing:
            return TrustVerificationResult(
                trusted=False,
                reason=f"Missing required capabilities: {', '.join(missing)}",
                checks=checks,
            )

    # 5. Check risk tier
    if max_risk_tier is not None:
        agent_risk = their_cert.agent_metadata.risk_tier
        checks["acceptable_risk_tier"] = agent_risk <= max_risk_tier
        if not checks["acceptable_risk_tier"]:
            return TrustVerificationResult(
                trusted=False,
                reason=f"Risk tier {agent_risk} exceeds maximum {max_risk_tier}",
                checks=checks,
            )

    return TrustVerificationResult(
        trusted=True,
        reason="All verification checks passed — trust established",
        checks=checks,
    )
