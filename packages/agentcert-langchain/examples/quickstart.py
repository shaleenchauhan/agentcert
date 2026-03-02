"""AgentCert + LangChain quickstart example.

Demonstrates creating an AgentCert middleware, attaching the callback handler
to a LangChain agent, and verifying the audit trail after execution.

Prerequisites::

    pip install agentcert-langchain langchain langchain-openai
"""

from agentcert_langchain import AgentCertLangChainMiddleware

# 1. Generate keys (one-time setup — in production, load from file)
import agentcert

creator_keys = agentcert.generate_keys()
agent_keys = agentcert.generate_keys()

# 2. Create middleware
middleware = AgentCertLangChainMiddleware(
    creator_keys=creator_keys,
    agent_keys=agent_keys,
    agent_name="research-agent",
    capabilities=["web_search", "analysis"],
    risk_tier=2,
)

# 3. Get the callback handler
handler = middleware.get_handler()

# 4. Use with any LangChain runnable via config
# result = agent.invoke(
#     {"messages": [HumanMessage(content="Find recent AI papers")]},
#     config={"callbacks": [handler]},
# )

# 5. Verify the audit trail
result = middleware.verify()
print(f"Trail status: {result.status}")
print(f"Entries logged: {result.entry_count}")

# 6. Save certificate + trail to disk
middleware.save("./my-agent-audit/")
print("Saved to ./my-agent-audit/")
