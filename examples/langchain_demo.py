"""AgentCert LangChain Integration Demo.

Demonstrates how to add identity certificates and signed audit trails
to a LangChain agent with just a few lines of code.

This demo simulates LangChain callback events (no real API keys needed)
to show the full developer experience:

    1. Create middleware (certificate + trail in one step)
    2. Wrap an AgentExecutor
    3. Simulate an agent run (LLM calls, tool use, decisions)
    4. Inspect the audit trail
    5. Verify the trail (11 checks)
    6. Save and reload

In production, you'd replace the simulated events with a real
AgentExecutor — the middleware captures everything automatically.

Run:
    python examples/langchain_demo.py
"""

from uuid import uuid4

import agentcert
from agentcert.integrations.langchain import AgentCertMiddleware


def section(title: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}\n")


def main() -> None:
    # ── Step 1: Create Middleware ──────────────────────────────────────

    section("Step 1: Create Middleware")

    creator_keys = agentcert.generate_keys()
    agent_keys = agentcert.generate_keys()

    middleware = AgentCertMiddleware(
        creator_keys=creator_keys,
        agent_keys=agent_keys,
        agent_name="procurement-agent-v1",
        platform="langchain",
        model_hash="sha256:a1b2c3d4e5f67890",
        capabilities=["procurement", "negotiation"],
        constraints=["max-transaction-50000-usd"],
        risk_tier=3,
    )

    cert = middleware.get_certificate()
    print(f"Certificate: {cert.cert_id[:16]}...")
    print(f"Agent:       {cert.agent_metadata.name}")
    print(f"Trail:       {middleware.get_trail().trail_id[:16]}...")

    # ── Step 2: Wrap an Executor ──────────────────────────────────────

    section("Step 2: Wrap an Executor")

    # In production:
    #   from langchain.agents import AgentExecutor
    #   executor = AgentExecutor(agent=agent, tools=tools)
    #   middleware.wrap(executor)
    #   result = executor.invoke({"input": "..."})
    #
    # For this demo, we simulate by calling the handler directly:

    class MockExecutor:
        callbacks = None

    executor = middleware.wrap(MockExecutor())
    handler = executor.callbacks[0]
    print(f"Handler injected: {type(handler).__name__}")
    print(f"Callbacks on executor: {len(executor.callbacks)}")

    # ── Step 3: Simulate an Agent Run ─────────────────────────────────

    section("Step 3: Simulate Agent Run")

    print("Simulating: 'Find the cheapest supplier for 1000 widgets'\n")

    # LLM call 1: Planning
    rid1 = uuid4()
    handler.on_llm_start(
        {"kwargs": {"model_name": "gpt-4o-mini"}},
        ["Find the cheapest supplier for 1000 widgets"],
        run_id=rid1,
    )

    class MockGen:
        def __init__(self, text):
            self.text = text

    class MockLLMResult:
        def __init__(self, text):
            self.generations = [[MockGen(text)]]

    handler.on_llm_end(
        MockLLMResult("I should search for widget suppliers and compare prices."),
        run_id=rid1,
    )
    print("[1] LLM call: gpt-4o-mini (planning)")

    # Agent decides to use search tool
    class MockAction:
        def __init__(self, tool, tool_input, log):
            self.tool = tool
            self.tool_input = tool_input
            self.log = log

    handler.on_agent_action(
        MockAction("web_search", {"query": "widget suppliers bulk pricing"},
                    "Thought: I need to search for suppliers."),
        run_id=uuid4(),
    )
    print("[2] Agent decision: use web_search")

    # Tool call: web_search
    rid2 = uuid4()
    handler.on_tool_start(
        {"name": "web_search"},
        "widget suppliers bulk pricing",
        run_id=rid2,
    )
    handler.on_tool_end(
        "Acme Corp: $12.50/unit, Widgets Inc: $14.00/unit, BestWidgets: $11.75/unit",
        run_id=rid2,
    )
    print("[3] Tool call: web_search")

    # LLM call 2: Analysis
    rid3 = uuid4()
    handler.on_llm_start(
        {"kwargs": {"model_name": "gpt-4o-mini"}},
        ["Based on results, which supplier is cheapest?"],
        run_id=rid3,
    )
    handler.on_llm_end(
        MockLLMResult("BestWidgets offers the lowest price at $11.75/unit."),
        run_id=rid3,
    )
    print("[4] LLM call: gpt-4o-mini (analysis)")

    # Agent finishes
    class MockFinish:
        def __init__(self):
            self.return_values = {
                "output": "BestWidgets is cheapest at $11.75/unit for 1000 widgets ($11,750 total)."
            }
            self.log = "Final Answer: BestWidgets"

    handler.on_agent_finish(MockFinish(), run_id=uuid4())
    print("[5] Agent finished")

    print(f"\nTotal entries logged: {len(middleware.get_entries())}")

    # ── Step 4: Inspect the Trail ─────────────────────────────────────

    section("Step 4: Inspect Audit Trail")

    for entry in middleware.get_entries():
        action_name = agentcert.ActionType(entry.action_type).name
        print(f"  [seq {entry.sequence}] {action_name:10s} | {entry.action_summary}")
        if "output_hash" in entry.action_detail:
            print(f"             output_hash: {entry.action_detail['output_hash'][:16]}...")
        if "duration_ms" in entry.action_detail:
            print(f"             duration:    {entry.action_detail['duration_ms']}ms")

    # Filter by type
    print(f"\nAPI_CALL entries:  {len(middleware.get_entries(action_type=agentcert.ActionType.API_CALL))}")
    print(f"TOOL_USE entries:  {len(middleware.get_entries(action_type=agentcert.ActionType.TOOL_USE))}")
    print(f"DECISION entries:  {len(middleware.get_entries(action_type=agentcert.ActionType.DECISION))}")

    # ── Step 5: Verify ────────────────────────────────────────────────

    section("Step 5: Verify Trail (11 checks)")

    result = middleware.verify()
    for check in result.checks:
        status = "PASS" if check.passed else "FAIL"
        print(f"  [{status}] {check.name}: {check.detail}")

    print(f"\nTrail ID:    {result.trail_id[:16]}...")
    print(f"Entries:     {result.entry_count}")
    print(f"Status:      {result.status}")

    # ── Step 6: Save & Reload ─────────────────────────────────────────

    section("Step 6: Save & Reload")

    middleware.save("./demo-agent-audit/")
    print("Saved: ./demo-agent-audit/")
    print("  certificate.json")
    print("  trail.json")

    # Reload
    loaded = AgentCertMiddleware.load("./demo-agent-audit/", agent_keys)
    print(f"\nReloaded: {len(loaded.get_entries())} entries")
    print(f"Verification: {loaded.verify().status}")

    # Continue logging after reload
    rid4 = uuid4()
    loaded.get_handler().on_tool_start(
        {"name": "email"}, "Send confirmation to procurement team", run_id=rid4,
    )
    loaded.get_handler().on_tool_end("Email sent successfully", run_id=rid4)
    print(f"\nAfter new entry: {len(loaded.get_entries())} entries")
    print(f"Still valid: {loaded.verify().status}")

    # ── Production Usage ──────────────────────────────────────────────

    section("Production Usage")

    print("""In production, the integration is just a few lines:

    from langchain.agents import create_react_agent, AgentExecutor
    from langchain_openai import ChatOpenAI
    from agentcert.integrations.langchain import AgentCertMiddleware

    # Standard LangChain setup
    llm = ChatOpenAI(model="gpt-4o-mini")
    agent = create_react_agent(llm, tools, prompt)
    executor = AgentExecutor(agent=agent, tools=tools)

    # Add AgentCert (3 lines)
    middleware = AgentCertMiddleware(
        creator_keys="creator.keys.json",
        agent_keys="agent.keys.json",
        agent_name="my-agent",
        capabilities=["search", "compute"],
    )
    executor = middleware.wrap(executor)

    # Use as normal — all actions logged automatically
    result = executor.invoke({"input": "..."})

    # Verify and save
    print(middleware.verify().status)  # "VALID"
    middleware.save("./audit/")""")

    print(f"\nDone. LangChain integration demo complete.")


if __name__ == "__main__":
    main()
