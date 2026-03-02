"""CrewAI verification tool for peer agent certificates."""

from __future__ import annotations

import logging
from typing import Any, TYPE_CHECKING

from crewai.tools import BaseTool

if TYPE_CHECKING:
    from agentcert_crewai.middleware import AgentCertCrewAIMiddleware

logger = logging.getLogger("agentcert.middleware.crewai")


class AgentCertVerifyTool(BaseTool):
    """CrewAI tool for verifying another agent's identity certificate.

    Loads a peer certificate from a JSON file, verifies its cryptographic
    signature, checks chain integrity, and reports revocation status.

    Uses the ``TrustVerifier`` from the middleware's configuration.
    The result is logged as a ``DECISION`` entry in the calling agent's
    audit trail.

    Example::

        middleware = AgentCertCrewAIMiddleware(...)
        verify_tool = middleware.get_verify_tool()

        agent = Agent(
            role="Auditor",
            tools=[verify_tool],
        )

    Attributes:
        name: Tool name shown to the agent.
        description: How/when/why to use the tool.
    """

    name: str = "verify_agent_certificate"
    description: str = (
        "Verify another AI agent's identity certificate and check its "
        "revocation status. Input: file path to a certificate JSON file. "
        "Returns: verification result with signature validity and "
        "revocation status."
    )

    # Private attribute — Pydantic v2 style
    _middleware: Any = None

    def __init__(self, middleware: AgentCertCrewAIMiddleware, **kwargs: Any) -> None:
        """Initialize the verify tool with a reference to the middleware.

        Args:
            middleware: The AgentCertCrewAIMiddleware that owns this tool.
            **kwargs: Additional arguments for BaseTool.
        """
        super().__init__(**kwargs)
        self._middleware = middleware

    def _run(self, cert_path: str) -> str:
        """Verify a peer certificate from a JSON file.

        Steps:
            1. Load peer cert from path
            2. Verify with ``TrustVerifier.verify_peer()``
            3. Log ``DECISION`` entry to this agent's trail
            4. Return human-readable result

        Args:
            cert_path: File path to the peer certificate JSON file.

        Returns:
            Human-readable verification result string.
        """
        try:
            import agentcert
            from agentcert.types import ActionType

            peer_cert = agentcert.load_certificate(cert_path)
            verifier = self._middleware.get_trust_verifier()
            result = verifier.verify_peer(peer_cert)

            # Log the verification decision
            self._middleware._log_action(
                action_type=ActionType.DECISION,
                action_summary=f"Verified peer cert: {peer_cert.cert_id[:16]}...",
                action_detail={
                    "peer_cert_id": peer_cert.cert_id,
                    "valid": result.valid,
                    "signature_valid": result.signature_valid,
                    "revocation_status": result.revocation_status,
                },
            )

            status = "TRUSTED" if result.valid else "UNTRUSTED"
            lines = [
                f"Certificate Verification: {status}",
                f"  Cert ID: {peer_cert.cert_id[:16]}...",
                f"  Agent: {peer_cert.agent_metadata.name}",
                f"  Signature valid: {result.signature_valid}",
                f"  Chain valid: {result.chain_valid}",
                f"  Revocation status: {result.revocation_status}",
            ]
            if not result.revocation_checked:
                lines.append(
                    "  Note: Revocation check unavailable (returns 'unknown')"
                )
            return "\n".join(lines)

        except FileNotFoundError:
            return f"Error: Certificate file not found: {cert_path}"
        except Exception as e:
            logger.error("AgentCertVerifyTool failed: %s", e)
            return f"Error verifying certificate: {e}"
