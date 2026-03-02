# agentcert-langchain

AgentCert trust infrastructure integration for LangChain agents. Provides cryptographic identity certificates, tamper-proof audit trails, and peer verification for autonomous AI agents running on LangChain.

## Install

```bash
pip install agentcert-langchain
# or via the main package:
pip install agentcert[langchain]
```

## Quickstart

```python
from agentcert_langchain import AgentCertLangChainMiddleware
import agentcert

creator_keys = agentcert.generate_keys()
agent_keys = agentcert.generate_keys()

middleware = AgentCertLangChainMiddleware(
    creator_keys=creator_keys,
    agent_keys=agent_keys,
    agent_name="my-agent",
    capabilities=["search", "analysis"],
)
handler = middleware.get_handler()

result = agent.invoke(input, config={"callbacks": [handler]})

print(middleware.verify().status)  # "VALID"
middleware.save("./audit/")
```

## Storage Modes

Control where audit trails are persisted:

```python
# Local only (default) — writes JSON to disk
middleware = AgentCertLangChainMiddleware(
    ..., storage="local", storage_dir="./audit/"
)

# Service only — submits to AgentCert managed service
middleware = AgentCertLangChainMiddleware(
    ..., storage="service", service_url="https://agentcert.dev"
)

# Both — local backup + service submission
middleware = AgentCertLangChainMiddleware(
    ..., storage="both", storage_dir="./audit/",
    service_url="https://agentcert.dev"
)
```

Enable auto-save to persist entries as they're logged:

```python
middleware = AgentCertLangChainMiddleware(
    ..., auto_save=True, auto_save_interval=1
)
```

## Trust Verification

Let your agent verify another agent's certificate before transacting:

```python
middleware = AgentCertLangChainMiddleware(...)
verify_tool = middleware.get_verify_tool()

# Add to your agent's tools
agent = create_react_agent(llm, tools=[verify_tool, ...])

# Or invoke directly
result = verify_tool._run("path/to/peer_certificate.json")
```

The verification tool:
1. Loads the peer certificate from a file path or JSON string
2. Checks signature validity and certificate chain integrity
3. Checks revocation status via the managed service (when available)
4. Logs a DECISION audit entry with the verification result
5. Returns a human-readable result for the LLM

## What Gets Logged

| LangChain Event | ActionType | Log Level |
|----------------|------------|-----------|
| `on_llm_end()` | `API_CALL` | standard+ |
| `on_chat_model_end()` | `API_CALL` | standard+ |
| `on_tool_end()` | `TOOL_USE` | all |
| `on_agent_action()` | `DECISION` | all |
| `on_agent_finish()` | `DECISION` | all |
| `on_chain_end()` | `API_CALL` | verbose |
| `on_*_error()` | `ERROR` | same as event |

LLM prompts and responses are SHA-256 hashed, never stored in plaintext.

## Log Levels

- **minimal**: Tool and agent events only (skips LLM and chain events)
- **standard** (default): Tool, agent, and LLM events (skips chain events)
- **verbose**: All events including top-level chain start/end

## Dashboard

View audit trails in the AgentCert dashboard:

```bash
agentcert service start --port 8932
# Open http://localhost:8932/dashboard
```

## Links

- [AgentCert repository](https://github.com/shaleenchauhan/agentcert)
- [PyPI: agentcert](https://pypi.org/project/agentcert/)
- [Documentation](https://agentcert.dev)
