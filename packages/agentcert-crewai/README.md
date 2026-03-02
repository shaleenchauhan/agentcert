# agentcert-crewai

AgentCert trust infrastructure integration for CrewAI agents and crews.

Provides cryptographic identity certificates, tamper-proof audit trails, and peer verification for CrewAI agents — from single-agent scripts to multi-agent crews with coordinator identity.

## Install

```bash
pip install agentcert-crewai
```

## Single-Agent Quickstart

```python
import agentcert
from agentcert_crewai import AgentCertCrewAIMiddleware
from crewai import Agent, Task, Crew

creator_keys = agentcert.generate_keys()
agent_keys = agentcert.generate_keys()

middleware = AgentCertCrewAIMiddleware(
    creator_keys=creator_keys,
    agent_keys=agent_keys,
    agent_name="research-agent",
    capabilities=["web_search"],
    risk_tier=2,
)

agent = Agent(
    role="Research Analyst",
    goal="Find data on AI trust",
    backstory="Expert researcher",
    step_callback=middleware.step_callback,
)
task = Task(description="Research AI trust standards", agent=agent, expected_output="Report")
crew = Crew(agents=[agent], tasks=[task])
result = crew.kickoff()

verification = middleware.verify()
middleware.save()
```

## Multi-Agent Crew with Coordinator

Two-tier observation captures agent-level steps and crew-level task completions:

```python
from agentcert_crewai import AgentCertCrewMiddleware

crew_mw = AgentCertCrewMiddleware(
    creator_keys=creator_keys,
    crew_name="research-crew",
    agents={
        "researcher": {
            "keys": researcher_keys,
            "capabilities": ["web_search"],
            "risk_tier": 2,
        },
        "writer": {
            "keys": writer_keys,
            "capabilities": ["writing"],
            "risk_tier": 1,
        },
    },
    storage="local",
    storage_dir="./agentcert-audit/",
)

researcher = Agent(
    role="Researcher",
    goal="Find data",
    backstory="Expert",
    step_callback=crew_mw.get_step_callback("researcher"),
    tools=[crew_mw.get_verify_tool("researcher")],
)
writer = Agent(
    role="Writer",
    goal="Write report",
    backstory="Expert",
    step_callback=crew_mw.get_step_callback("writer"),
)

research_task = Task(
    description="Research AI trust",
    agent=researcher,
    expected_output="Findings",
    callback=crew_mw.get_task_callback(),
)
write_task = Task(
    description="Write report",
    agent=writer,
    expected_output="Report",
    callback=crew_mw.get_task_callback(),
)

crew = Crew(agents=[researcher, writer], tasks=[research_task, write_task])
result = crew.kickoff()

results = crew_mw.verify_all()
crew_mw.save()
```

## What Gets Logged

### Agent-level (step_callback)
Each agent step is captured with the appropriate ActionType:

| CrewAI Step | ActionType | Summary |
|------------|------------|---------|
| Tool invocation (AgentAction) | TOOL_USE | Tool name + input hash |
| Final answer (AgentFinish) | DECISION | Output hash |
| Tool result (ToolResult) | TOOL_USE | Result hash |

### Crew-level (task_callback)
Task completions logged to the coordinator trail:

| Event | ActionType | Summary |
|-------|------------|---------|
| Task completed | DECISION | Agent name + task description + output hash |

## Coordinator Identity

- **Auto-generated** on first run from creator keys
- **Persisted** to `{storage_dir}/{crew_name}-coordinator/` for reuse
- **Overridable** via `coordinator_keys` parameter for power users
- **Independent** certificate and trail — separate from agent certificates

## Output Directory Structure

```
agentcert-audit/
├── researcher/
│   ├── cert.json          # Agent certificate
│   └── trail.json         # Agent-level audit trail
├── writer/
│   ├── cert.json
│   └── trail.json
└── research-crew-coordinator/
    ├── keys.json           # Coordinator keys (auto-generated)
    ├── cert.json           # Coordinator certificate
    └── trail.json          # Crew-level audit trail
```

## Trust Verification Tool

The verify tool lets agents check peer certificates during execution:

```python
verify_tool = middleware.get_verify_tool()
agent = Agent(role="Auditor", tools=[verify_tool], ...)
```

## Storage Modes

- `"local"` — JSON files to disk (default)
- `"service"` — submit to AgentCert managed service
- `"both"` — local backup + service submission

## Links

- [AgentCert main repo](https://github.com/shaleenchauhan/agentcert)
- [agentcert-middleware](https://github.com/shaleenchauhan/agentcert/tree/main/packages/agentcert-middleware)
