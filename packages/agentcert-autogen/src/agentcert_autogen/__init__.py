"""AgentCert integration for AutoGen agents and teams.

Provides async-native middleware for single agents and multi-agent teams
with cryptographic audit trails and Bitcoin-anchored verification.
"""

__version__ = "0.1.0"

__all__ = [
    "AgentCertAutoGenMiddleware",
    "AgentCertTeamMiddleware",
    "create_verify_tool",
]

from agentcert_autogen.middleware import AgentCertAutoGenMiddleware
from agentcert_autogen.team_middleware import AgentCertTeamMiddleware
from agentcert_autogen.tool import create_verify_tool
