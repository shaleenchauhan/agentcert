"""AgentCert trust infrastructure integration for LangChain agents.

Provides identity certificates, signed audit trails, and peer verification
for LangChain agents via a callback handler and optional verification tool.

Install::

    pip install agentcert-langchain

Quick start::

    from agentcert_langchain import AgentCertLangChainMiddleware

    middleware = AgentCertLangChainMiddleware(
        creator_keys="creator.keys.json",
        agent_keys="agent.keys.json",
        agent_name="my-agent",
    )
    handler = middleware.get_handler()
    result = agent.invoke(input, config={"callbacks": [handler]})
    middleware.save()
"""

from agentcert_langchain.handler import (
    MINIMAL,
    STANDARD,
    VERBOSE,
    AgentCertCallbackHandler,
    _extract_model_name,
    _extract_tool_name,
    _sha256_hash,
)
from agentcert_langchain.middleware import AgentCertLangChainMiddleware
from agentcert_langchain.tool import AgentCertVerifyTool

__all__ = [
    "AgentCertLangChainMiddleware",
    "AgentCertCallbackHandler",
    "AgentCertVerifyTool",
    "MINIMAL",
    "STANDARD",
    "VERBOSE",
    "_sha256_hash",
    "_extract_model_name",
    "_extract_tool_name",
]

__version__ = "0.1.0"
