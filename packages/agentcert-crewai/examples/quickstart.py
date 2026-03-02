"""Single-agent CrewAI quickstart with AgentCert audit trail.

Demonstrates:
- Key generation
- Middleware setup with step_callback
- Agent + Task + Crew execution
- Trail verification and persistence

Requires: pip install agentcert-crewai
Note: Requires OPENAI_API_KEY or similar LLM config for actual execution.
"""

import agentcert
from agentcert_crewai import AgentCertCrewAIMiddleware
from crewai import Agent, Task, Crew

# 1. Generate keys
creator_keys = agentcert.generate_keys()
agent_keys = agentcert.generate_keys()

# 2. Create middleware
middleware = AgentCertCrewAIMiddleware(
    creator_keys=creator_keys,
    agent_keys=agent_keys,
    agent_name="research-agent",
    capabilities=["web_search", "analysis"],
    risk_tier=2,
    storage="local",
    storage_dir="./agentcert-audit/",
)

print(f"Agent certificate: {middleware.certificate.cert_id[:16]}...")

# 3. Create CrewAI agent with step_callback
agent = Agent(
    role="Research Analyst",
    goal="Find comprehensive data on AI trust frameworks",
    backstory="You are an expert AI researcher with deep knowledge of trust and safety.",
    step_callback=middleware.step_callback,
    tools=[middleware.get_verify_tool()],
)

# 4. Create task and crew
task = Task(
    description="Research the current state of AI trust frameworks and standards.",
    agent=agent,
    expected_output="A summary of AI trust frameworks",
)
crew = Crew(agents=[agent], tasks=[task])

# 5. Run (requires LLM API key)
# result = crew.kickoff()

# 6. Verify and save
verification = middleware.verify()
print(f"Trail verification: {verification.status}")
print(f"Entries logged: {len(middleware.trail.entries)}")

middleware.save()
print("Audit trail saved to ./agentcert-audit/research-agent/")
