"""Multi-agent crew with two-tier AgentCert audit trail.

Demonstrates:
- Two-agent crew with coordinator identity
- Agent-level audit trails (step_callback)
- Crew-level audit trail (task_callback on coordinator)
- Coordinator identity auto-generation and persistence
- Verification of all trails

Requires: pip install agentcert-crewai
Note: Requires OPENAI_API_KEY or similar LLM config for actual execution.
"""

import agentcert
from agentcert_crewai import AgentCertCrewMiddleware
from crewai import Agent, Task, Crew

# 1. Generate keys for creator and agents
creator_keys = agentcert.generate_keys()
researcher_keys = agentcert.generate_keys()
writer_keys = agentcert.generate_keys()

# 2. Create crew middleware (coordinator auto-generated)
crew_mw = AgentCertCrewMiddleware(
    creator_keys=creator_keys,
    crew_name="research-writing-crew",
    agents={
        "researcher": {
            "keys": researcher_keys,
            "capabilities": ["web_search", "analysis"],
            "risk_tier": 2,
        },
        "writer": {
            "keys": writer_keys,
            "capabilities": ["writing", "editing"],
            "risk_tier": 1,
        },
    },
    storage="local",
    storage_dir="./agentcert-audit/",
)

print(f"Coordinator cert: {crew_mw.coordinator_certificate.cert_id[:16]}...")
print(f"Researcher cert:  {crew_mw.get_agent_middleware('researcher').certificate.cert_id[:16]}...")
print(f"Writer cert:      {crew_mw.get_agent_middleware('writer').certificate.cert_id[:16]}...")

# 3. Create CrewAI agents with step_callbacks
researcher = Agent(
    role="Research Analyst",
    goal="Find comprehensive data on AI trust",
    backstory="Expert AI researcher",
    step_callback=crew_mw.get_step_callback("researcher"),
    tools=[crew_mw.get_verify_tool("researcher")],
)

writer = Agent(
    role="Technical Writer",
    goal="Write clear, accurate reports",
    backstory="Expert technical writer",
    step_callback=crew_mw.get_step_callback("writer"),
)

# 4. Create tasks with task_callbacks (logs to coordinator trail)
research_task = Task(
    description="Research the current state of AI trust frameworks.",
    agent=researcher,
    expected_output="Research findings summary",
    callback=crew_mw.get_task_callback(),
)

writing_task = Task(
    description="Write a report based on the research findings.",
    agent=writer,
    expected_output="Final report document",
    callback=crew_mw.get_task_callback(),
)

# 5. Assemble and run crew
crew = Crew(
    agents=[researcher, writer],
    tasks=[research_task, writing_task],
)

# Uncomment to run (requires LLM API key):
# result = crew.kickoff()

# 6. Verify all trails
results = crew_mw.verify_all()
for name, result in results.items():
    print(f"  {name}: {result.status} ({result.entry_count} entries)")

# 7. Save all trails
crew_mw.save()
print("\nAll trails saved to ./agentcert-audit/")
print("  Researcher trail: ./agentcert-audit/researcher/trail.json")
print("  Writer trail:     ./agentcert-audit/writer/trail.json")
print("  Coordinator:      ./agentcert-audit/research-writing-crew-coordinator/trail.json")
