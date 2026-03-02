"""AgentCert + AutoGen team example — SelectorGroupChat with audit trails.

Each agent gets its own signed audit trail. A coordinator trail captures
team-level orchestration events (e.g., which agent was selected).

Prerequisites:
    pip install agentcert-autogen
    agentcert keygen creator.keys.json
    agentcert keygen researcher.keys.json
    agentcert keygen analyst.keys.json

Replace MockModelClient with your real model client (e.g., OpenAIChatCompletionClient).
"""

from __future__ import annotations

import asyncio

from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.teams import SelectorGroupChat

from agentcert_autogen import AgentCertTeamMiddleware


# --- Sample tools ---


async def search_web(query: str) -> str:
    """Search the web for information."""
    return f"Search results for: {query}"


async def analyze_data(data: str) -> str:
    """Analyze data and provide insights."""
    return f"Analysis of: {data}"


# --- Main ---


async def main() -> None:
    # 1. Create team middleware (generates per-agent certs + coordinator)
    team_middleware = AgentCertTeamMiddleware(
        creator_keys="creator.keys.json",
        team_name="research_team",
        agents={
            "researcher": {
                "keys": "researcher.keys.json",
                "capabilities": ["web_search", "data_collection"],
            },
            "analyst": {
                "keys": "analyst.keys.json",
                "capabilities": ["data_analysis", "report_generation"],
            },
        },
        storage="local",
        storage_dir="./agentcert-audit/",
    )

    # 2. Create agents with wrapped tools
    researcher = AssistantAgent(
        name="researcher",
        model_client=model_client,  # type: ignore[name-defined]  # replace with real client
        tools=team_middleware.wrap_tools("researcher", [search_web]),
        description="Searches the web for information.",
    )

    analyst = AssistantAgent(
        name="analyst",
        model_client=model_client,  # type: ignore[name-defined]
        tools=team_middleware.wrap_tools("analyst", [analyze_data]),
        description="Analyzes data and provides insights.",
    )

    # 3. Create team
    team = SelectorGroupChat(
        participants=[researcher, analyst],
        model_client=model_client,  # type: ignore[name-defined]
    )

    # 4. Run team with automatic audit capture
    result = await team_middleware.run(team, "Research and analyze AI trust mechanisms")
    print("Team result:", result)

    # 5. Verify all trails
    verification = team_middleware.verify_all()
    print("\nVerification results:")
    for name, v in verification.items():
        print(f"  {name}: {v.status}")

    # 6. Inspect per-agent entries
    for name, mw in team_middleware.agent_middlewares.items():
        entries = mw.get_entries()
        print(f"\n{name} trail: {len(entries)} entries")
        for entry in entries:
            print(f"  [{entry.action_type}] {entry.action_summary}")

    # Coordinator entries
    coord_entries = team_middleware.coordinator.get_entries()
    print(f"\nCoordinator trail: {len(coord_entries)} entries")
    for entry in coord_entries:
        print(f"  [{entry.action_type}] {entry.action_summary}")

    # 7. Save all trails
    await team_middleware.save()
    print("\nAll audit trails saved to ./agentcert-audit/")


if __name__ == "__main__":
    asyncio.run(main())
