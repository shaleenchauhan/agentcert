"""Two-agent trust verification example.

Demonstrates Agent A verifying Agent B's identity certificate before
deciding whether to transact. The verification result is logged as an
audit entry in Agent A's trail.

Prerequisites::

    pip install agentcert-langchain langchain langchain-openai
"""

import agentcert
from agentcert_langchain import AgentCertLangChainMiddleware

# ── Setup keys ──────────────────────────────────────────────────────────
creator_keys = agentcert.generate_keys()
agent_a_keys = agentcert.generate_keys()
agent_b_keys = agentcert.generate_keys()

# ── Agent B: create identity ────────────────────────────────────────────
agent_b_middleware = AgentCertLangChainMiddleware(
    creator_keys=creator_keys,
    agent_keys=agent_b_keys,
    agent_name="supplier-agent",
    capabilities=["order_fulfillment", "inventory_check"],
    risk_tier=2,
)
# Save Agent B's certificate so Agent A can verify it
agent_b_middleware.save("./agent-b-audit/")
print(f"Agent B cert: {agent_b_middleware.get_certificate().cert_id[:16]}...")

# ── Agent A: verify Agent B before transacting ─────────────────────────
agent_a_middleware = AgentCertLangChainMiddleware(
    creator_keys=creator_keys,
    agent_keys=agent_a_keys,
    agent_name="procurement-agent",
    capabilities=["purchasing", "analysis"],
    risk_tier=3,
)

# Get the verification tool and use it directly
verify_tool = agent_a_middleware.get_verify_tool()

# Or pass it to a LangChain agent:
# agent = create_react_agent(llm, tools=[verify_tool, ...])

# Verify Agent B's certificate from file
result = verify_tool._run("./agent-b-audit/certificate.json")
print(f"\nVerification result:\n{result}")

# Check the audit trail — verification is logged
entries = agent_a_middleware.get_entries()
print(f"Agent A audit entries: {len(entries)}")
for entry in entries:
    print(f"  [{entry.action_type}] {entry.action_summary}")

# Verify Agent A's trail integrity
verification = agent_a_middleware.verify()
print(f"\nAgent A trail: {verification.status}")
