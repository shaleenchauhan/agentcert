"""Backward compatibility shim.

The LangChain integration has moved to the ``agentcert-langchain`` package.
This shim maintains the old import paths::

    from agentcert.integrations.langchain import AgentCertMiddleware
    from agentcert.integrations.langchain import AgentCertCallbackHandler

Install the new package with::

    pip install agentcert-langchain
"""

try:
    from agentcert_langchain import (
        AgentCertCallbackHandler,
        AgentCertLangChainMiddleware,
        AgentCertVerifyTool,
        MINIMAL,
        STANDARD,
        VERBOSE,
        _extract_model_name,
        _extract_tool_name,
        _sha256_hash,
    )

    # Backward-compatible name
    AgentCertMiddleware = AgentCertLangChainMiddleware
except ImportError:
    raise ImportError(
        "The LangChain integration has moved to the 'agentcert-langchain' "
        "package. Install it with: pip install agentcert-langchain\n"
        "Or: pip install agentcert[langchain]"
    )

__all__ = [
    "AgentCertMiddleware",
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
