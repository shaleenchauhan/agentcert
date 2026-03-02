"""Async verification tool for AutoGen agents.

Creates a plain async function that can be passed to
``AssistantAgent(tools=[...])``. AutoGen uses the function's name,
docstring, and type hints to generate the LLM tool schema.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from agentcert_autogen.middleware import AgentCertAutoGenMiddleware

logger = logging.getLogger("agentcert.autogen.tool")


def create_verify_tool(
    middleware: AgentCertAutoGenMiddleware,
) -> Callable[..., Any]:
    """Create an async verification tool for AutoGen.

    The returned function can be passed directly to
    ``AssistantAgent(tools=[verify_agent_certificate])``.

    AutoGen v0.4 uses plain functions as tools. The function's
    ``__name__``, ``__doc__``, and type hints are used to describe
    the tool to the LLM.

    Args:
        middleware: The middleware instance providing trust verification.

    Returns:
        An async function that verifies a peer agent's certificate.
    """
    import agentcert
    from agentcert.types import ActionType

    async def verify_agent_certificate(cert_path: str) -> str:
        """Verify another AI agent's identity certificate and check its revocation status.

        Args:
            cert_path: File path to a certificate JSON file.

        Returns:
            Verification result including signature validity and revocation status.
        """
        try:
            peer_cert = agentcert.load_certificate(cert_path)
        except Exception as e:
            return f"Failed to load certificate from {cert_path}: {e}"

        trust_verifier = middleware.get_trust_verifier()
        result = trust_verifier.verify_peer(peer_cert)

        peer_name = getattr(peer_cert, "name", None)
        if peer_name is None:
            peer_name = peer_cert.agent_metadata.name if hasattr(peer_cert, "agent_metadata") else peer_cert.cert_id[:16]

        if result.valid:
            status = "VALID"
        elif result.revocation_status == "revoked":
            status = "REVOKED"
        else:
            status = "INVALID"

        middleware._log_action(
            action_type=ActionType.DECISION,
            action_summary=f"Verified agent '{peer_name}' — status: {status}",
            action_detail={
                "peer_cert_id": peer_cert.cert_id,
                "valid": result.valid,
                "revocation_status": result.revocation_status,
            },
        )

        sig_mark = "\u2713" if result.signature_valid else "\u2717"
        chain_mark = "\u2713" if result.chain_valid else "\u2717"

        return (
            f"Certificate verification for '{peer_name}':\n"
            f"  Overall: {status}\n"
            f"  Signature: {sig_mark}\n"
            f"  Chain: {chain_mark}\n"
            f"  Revocation: {result.revocation_status}\n"
        )

    return verify_agent_certificate
