"""AgentCert + AutoGen quickstart — single agent with tool wrapping.

Prerequisites:
    pip install agentcert-autogen
    agentcert keygen creator.keys.json
    agentcert keygen agent.keys.json

Replace MockModelClient with your real model client (e.g., OpenAIChatCompletionClient).
"""

from __future__ import annotations

import asyncio

from autogen_agentchat.agents import AssistantAgent

from agentcert_autogen import AgentCertAutoGenMiddleware


# --- Sample tool ---


async def get_weather(city: str) -> str:
    """Get the current weather for a city."""
    return f"Sunny, 22°C in {city}"


# --- Mock model client (replace with real client) ---


class MockModelClient:
    """Placeholder — replace with OpenAIChatCompletionClient or similar."""

    # See tests/conftest.py for a working mock implementation.
    ...


# --- Main ---


async def main() -> None:
    # 1. Create middleware (generates certificate + audit trail)
    middleware = AgentCertAutoGenMiddleware(
        creator_keys="creator.keys.json",
        agent_keys="agent.keys.json",
        agent_name="weather_agent",
        capabilities=["weather_lookup"],
        storage="local",
        storage_dir="./agentcert-audit/",
    )

    # 2. Create agent with wrapped tools
    agent = AssistantAgent(
        name="weather_agent",
        model_client=model_client,  # type: ignore[name-defined]  # replace with real client
        tools=middleware.wrap_tools([get_weather]),
    )

    # 3. Run agent with automatic audit capture
    result = await middleware.run(agent, "What's the weather in London?")
    print("Agent result:", result)

    # 4. Verify audit trail integrity
    verification = middleware.verify()
    print(f"Trail valid: {verification.status}")
    for check in verification.checks:
        print(f"  {check.name}: {'PASS' if check.passed else 'FAIL'}")

    # 5. Persist to disk
    await middleware.save()
    print("Audit trail saved to ./agentcert-audit/weather_agent/")


if __name__ == "__main__":
    asyncio.run(main())
