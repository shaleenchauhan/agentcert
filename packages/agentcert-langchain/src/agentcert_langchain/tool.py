"""AgentCert verification tool for LangChain agents.

Provides :class:`AgentCertVerifyTool`, a LangChain ``BaseTool`` that lets an
agent verify another agent's identity certificate during execution (Role 4).
"""

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING, Any

from langchain_core.tools import BaseTool
from pydantic import Field

from agentcert.certificate import load_certificate
from agentcert.types import ActionType, Certificate

if TYPE_CHECKING:
    from agentcert_middleware import BaseMiddleware


class AgentCertVerifyTool(BaseTool):
    """LangChain tool for verifying another agent's identity certificate.

    When invoked by the agent:

    1. Loads the peer certificate from the provided path or JSON string.
    2. Runs ``TrustVerifier.verify_peer()`` — signature, chain, revocation check.
    3. Logs a ``DECISION`` audit entry recording the verification result.
    4. Returns a human-readable result so the agent can decide whether to proceed.

    Args:
        middleware: The :class:`BaseMiddleware` instance (or subclass) that
            owns this tool.

    Example::

        verify_tool = middleware.get_verify_tool()
        agent = create_react_agent(llm, tools=[verify_tool, ...])
    """

    name: str = "verify_agent_certificate"
    description: str = (
        "Verify another AI agent's identity certificate and check its "
        "revocation status. Input is a file path to a certificate JSON file "
        "or a raw certificate JSON string. Returns verification result "
        "including signature validity and revocation status."
    )

    middleware: Any = Field(exclude=True)

    model_config = {"arbitrary_types_allowed": True}

    def _run(self, cert_input: str) -> str:
        """Verify a peer certificate.

        Args:
            cert_input: Path to a certificate JSON file, or a raw JSON string.

        Returns:
            Human-readable verification result string.
        """
        # Load the peer certificate
        if os.path.exists(cert_input):
            peer_cert = load_certificate(cert_input)
        else:
            cert_data = json.loads(cert_input)
            peer_cert = Certificate.from_dict(cert_data)

        # Run trust verification
        trust_verifier = self.middleware.get_trust_verifier()
        result = trust_verifier.verify_peer(peer_cert)

        # Determine status and peer name
        peer_name = getattr(
            peer_cert.agent_metadata, "name", peer_cert.cert_id[:16]
        )
        if result.valid:
            status = "VALID"
        elif result.revocation_status == "revoked":
            status = "REVOKED"
        else:
            status = "INVALID"

        # Log the verification as a DECISION entry
        self.middleware._log_action(
            action_type=ActionType.DECISION,
            action_summary=f"Verified agent '{peer_name}' — status: {status}",
            action_detail={
                "peer_cert_id": peer_cert.cert_id,
                "peer_name": peer_name,
                "valid": result.valid,
                "signature_valid": result.signature_valid,
                "chain_valid": result.chain_valid,
                "revocation_status": result.revocation_status,
            },
        )

        # Return readable result for the LLM
        sig = "valid" if result.signature_valid else "INVALID"
        chain = "valid" if result.chain_valid else "INVALID"
        return (
            f"Certificate verification for '{peer_name}':\n"
            f"  Overall: {status}\n"
            f"  Signature: {sig}\n"
            f"  Chain: {chain}\n"
            f"  Revocation: {result.revocation_status}\n"
        )
