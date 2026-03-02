"""Trust verification for peer agent certificates."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from agentcert.types import Certificate

logger = logging.getLogger("agentcert.middleware")


@dataclass(frozen=True)
class TrustResult:
    """Result of verifying a peer agent's certificate.

    Attributes:
        valid: Overall trust decision.
        signature_valid: Certificate signature check passed.
        chain_valid: Certificate chain integrity check passed.
        revocation_status: ``"valid"``, ``"revoked"``, or ``"unknown"``.
        revocation_checked: Whether revocation was actually checked via service.
        details: Full check details dict.
    """

    valid: bool
    signature_valid: bool
    chain_valid: bool
    revocation_status: str
    revocation_checked: bool
    details: dict = field(default_factory=dict)


class TrustVerifier:
    """Verifies another agent's certificate and revocation status.

    Used by framework-specific verification tools (Role 4).

    Verification steps:
        1. Verify certificate signature (local math — always works)
        2. Verify certificate chain integrity (local math — always works)
        3. Check revocation status via managed service (STUB: returns ``"unknown"``)

    STUB (tracked in managed-service-integration-stubs.md):
        - Revocation check returns ``revocation_status="unknown"``,
          ``revocation_checked=False``
        - Will wire to ``GET /api/v1/revocations/{cert_id}`` when available (Stub 2)
        - Creator compromise check not implemented (Stub 7)

    Args:
        service_url: Optional URL of the AgentCert service for revocation checks.
        api_key: Optional API key for service authentication.
    """

    def __init__(
        self, service_url: str | None = None, api_key: str | None = None
    ) -> None:
        self.service_url = service_url
        self.api_key = api_key
        self._client = None
        if service_url:
            from agentcert.client import AgentCertClient

            self._client = AgentCertClient(service_url)

    def verify_peer(self, peer_cert: Certificate) -> TrustResult:
        """Verify a peer certificate.

        Uses ``agentcert.verify()`` for local math checks (signature + chain).
        Revocation currently returns ``"unknown"`` (Stub 2).

        Args:
            peer_cert: The peer agent's certificate to verify.

        Returns:
            A TrustResult with verification details.
        """
        from agentcert.verify import verify

        # Step 1 + 2: Use agentcert.verify() for signature + chain checks
        result = verify(peer_cert)

        signature_valid = result.valid
        chain_valid = result.valid

        # Step 3: Revocation check (STUB — no dedicated endpoint)
        revocation_status = "unknown"
        revocation_checked = False
        # TODO: When GET /api/v1/revocations/{cert_id} exists, call it here

        overall_valid = (
            signature_valid
            and chain_valid
            and revocation_status != "revoked"
        )

        return TrustResult(
            valid=overall_valid,
            signature_valid=signature_valid,
            chain_valid=chain_valid,
            revocation_status=revocation_status,
            revocation_checked=revocation_checked,
            details={
                "verification_result": result,
                "service_url": self.service_url,
                "note": (
                    "Revocation check stubbed — returns 'unknown' until "
                    "managed service v2"
                    if not revocation_checked
                    else None
                ),
            },
        )
