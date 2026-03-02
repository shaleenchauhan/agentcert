# agentcert-autogen

AgentCert trust infrastructure integration for [AutoGen](https://github.com/microsoft/autogen) agents and teams.

Provides async-native middleware for single agents and multi-agent teams with cryptographic audit trails and Bitcoin-anchored verification.

## Installation

```bash
pip install agentcert-autogen
```

## Quick Start — Single Agent

```python
import asyncio
from autogen_agentchat.agents import AssistantAgent
from agentcert_autogen import AgentCertAutoGenMiddleware

async def get_weather(city: str) -> str:
    """Get the current weather for a city."""
    return f"Sunny in {city}"

async def main():
    middleware = AgentCertAutoGenMiddleware(
        creator_keys="creator.keys.json",
        agent_keys="agent.keys.json",
        agent_name="weather_agent",
        capabilities=["weather"],
        storage="local",
    )

    agent = AssistantAgent(
        name="weather_agent",
        model_client=model_client,  # your ChatCompletionClient
        tools=middleware.wrap_tools([get_weather]),
    )

    result = await middleware.run(agent, "What's the weather in London?")

    # Verify audit trail integrity
    verification = middleware.verify()
    print(f"Trail valid: {verification.status}")

    # Persist to disk
    await middleware.save()

asyncio.run(main())
```

## Quick Start — Multi-Agent Team

```python
import asyncio
from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.teams import SelectorGroupChat
from agentcert_autogen import AgentCertTeamMiddleware

async def search_web(query: str) -> str:
    """Search the web."""
    return f"Results for: {query}"

async def main():
    team_middleware = AgentCertTeamMiddleware(
        creator_keys="creator.keys.json",
        team_name="research_team",
        agents={
            "researcher": {
                "keys": "researcher.keys.json",
                "capabilities": ["web_search"],
            },
            "analyst": {
                "keys": "analyst.keys.json",
                "capabilities": ["analysis"],
            },
        },
        storage="local",
    )

    researcher = AssistantAgent(
        name="researcher",
        model_client=model_client,
        tools=team_middleware.wrap_tools("researcher", [search_web]),
    )
    analyst = AssistantAgent(
        name="analyst",
        model_client=model_client,
    )

    team = SelectorGroupChat(
        participants=[researcher, analyst],
        model_client=model_client,
    )

    result = await team_middleware.run(team, "Research and analyze AI trust")

    # Verify all trails (each agent + coordinator)
    verification = team_middleware.verify_all()
    for name, v in verification.items():
        print(f"  {name}: {v.status}")

    await team_middleware.save()

asyncio.run(main())
```

## How It Works

AutoGen v0.4 has no callback system. This middleware integrates through two complementary mechanisms:

### 1. Tool Wrapping

`wrap_tools()` wraps each tool function to capture every invocation as a signed `TOOL_USE` audit entry. The wrapper preserves the original function's name, docstring, and type hints so AutoGen's tool handling works unchanged.

### 2. Stream Processing

`process_stream()` reads the async stream from `run_stream()` and maps typed messages to ActionTypes:

| AutoGen Message Type | ActionType | Notes |
|---|---|---|
| `ToolCallRequestEvent` | `TOOL_USE` | Agent decided to call a tool |
| `ToolCallExecutionEvent` | *(skipped)* | Already captured by wrap_tools |
| `TextMessage` | `DECISION` | Agent text response |
| `StopMessage` | `DECISION` | Agent stop signal |
| `HandoffMessage` | `DECISION` | Agent handoff |
| `ThoughtEvent` | `DECISION` | Agent reasoning |
| `SelectSpeakerEvent` | `DECISION` | Team speaker selection |
| `SelectorEvent` | `DECISION` | Selector decision |

## Team Types

All three AutoGen team types are supported:

### RoundRobinGroupChat

Agents take turns in order. Each agent's messages go to their individual audit trail. No special coordinator events.

### SelectorGroupChat

An LLM selects the next speaker. Selection events (`SelectorEvent`) are routed to the coordinator trail. Agent messages go to individual trails.

### MagenticOneGroupChat

An orchestrator plans and delegates. Orchestrator messages go to the coordinator trail. Agent messages go to individual trails.

**Note:** `MagenticOneGroupChat` does NOT support nested teams.

## Coordinator Identity

The `AgentCertTeamMiddleware` automatically creates a coordinator identity for team-level events. The coordinator follows a three-tier strategy:

1. **Explicit override** — if `coordinator_keys` is provided
2. **Load from disk** — if keys were previously saved
3. **Auto-generate** — create and persist new keys

## Verification Tool

Give agents the ability to verify other agents' certificates:

```python
verify_tool = middleware.get_verify_tool()

agent = AssistantAgent(
    name="verifier",
    model_client=model_client,
    tools=[verify_tool],
)
```

The tool loads a peer certificate from a file path and returns signature validity, chain integrity, and revocation status.

## Storage Modes

| Mode | Description |
|---|---|
| `"local"` | Save to local filesystem (default) |
| `"service"` | Submit to AgentCert managed service |
| `"both"` | Local + service (local is primary) |

## Async-Native

All methods that interact with the network are async:

- `await middleware.run(agent, task)`
- `await middleware.process_stream(stream)`
- `await middleware.save()`

## Requirements

- Python 3.11+
- `agentcert-middleware>=0.1.0`
- `autogen-agentchat>=0.4.0`

## License

MIT
