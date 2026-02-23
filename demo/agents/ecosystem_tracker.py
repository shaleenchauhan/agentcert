"""Agent 2: AI Ecosystem Tracker.

Uses Claude (Sonnet) + Tavily to monitor the AI agent ecosystem for
new frameworks, funding rounds, and product launches. All actions are
captured as signed, hash-chained audit entries via AgentCertMiddleware.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

import agentcert
from agentcert.integrations.langchain import AgentCertMiddleware
from langchain_anthropic import ChatAnthropic
from langchain_core.messages import SystemMessage, HumanMessage
from langchain_core.tools import tool
from langgraph.prebuilt import create_react_agent
from tavily import TavilyClient

KEYS_DIR = os.path.join(os.path.dirname(__file__), "..", "keys")

tavily_client = TavilyClient(api_key=os.environ["TAVILY_API_KEY"])


@tool
def search_ai_ecosystem(query: str) -> str:
    """Search the web for AI agent ecosystem developments."""
    results = tavily_client.search(
        query=query,
        max_results=5,
        search_depth="basic",
    )
    formatted = []
    for r in results.get("results", []):
        formatted.append(
            f"Title: {r['title']}\nURL: {r['url']}\nSnippet: {r['content'][:300]}\n"
        )
    return "\n---\n".join(formatted) if formatted else "No results found."


@tool
def fetch_article(url: str) -> str:
    """Fetch the full content of an article given its URL."""
    try:
        result = tavily_client.extract(urls=[url])
        if result.get("results"):
            content = result["results"][0].get("raw_content", "")
            return content[:3000] if content else "No content extracted."
        return "Could not fetch article content."
    except Exception as e:
        return f"Error fetching article: {e}"


SYSTEM_PROMPT = (
    "You are an AI ecosystem analyst. Your job is to:\n"
    "1. Search for the latest developments in the AI agent ecosystem — "
    "new frameworks, platforms, funding rounds, product launches, and partnerships\n"
    "2. Fetch and analyze the most relevant articles (at least 3)\n"
    "3. Produce a market briefing with:\n"
    "   - Key developments found (with company names, amounts, dates where available)\n"
    "   - Trends: what patterns do you see across these developments?\n"
    "   - Notable new entrants or pivots\n"
    "   - Market signal: is the AI agent space accelerating, plateauing, or consolidating?\n\n"
    "Focus specifically on AI AGENTS (autonomous, tool-using AI systems), "
    "not general AI/ML news."
)


def run():
    """Run the ecosystem tracker agent and return the middleware."""
    # AgentCert identity + audit trail
    middleware = AgentCertMiddleware(
        creator_keys=os.path.join(KEYS_DIR, "creator.keys.json"),
        agent_keys=os.path.join(KEYS_DIR, "ecosystem-tracker.keys.json"),
        agent_name="ecosystem-tracker-v1",
        platform="langchain",
        capabilities=["web-search", "data-extraction", "market-analysis"],
        constraints=["read-only", "no-financial-transactions", "public-sources-only"],
        risk_tier=1,
    )

    # LLM + tools
    llm = ChatAnthropic(model="claude-sonnet-4-20250514", max_tokens=4096)
    tools = [search_ai_ecosystem, fetch_article]

    # Create ReAct agent via LangGraph
    agent = create_react_agent(llm, tools)

    # Run with AgentCert callback handler
    handler = middleware.get_handler()
    result = agent.invoke(
        {
            "messages": [
                SystemMessage(content=SYSTEM_PROMPT),
                HumanMessage(
                    content="Search for the latest AI agent ecosystem developments "
                    "— new frameworks, funding rounds, product launches, and major "
                    "partnerships from the past month. Produce a market briefing."
                ),
            ],
        },
        config={"callbacks": [handler]},
    )

    # Print the agent's response
    final_message = result["messages"][-1]
    print("\n" + "=" * 70)
    print("MARKET BRIEFING")
    print("=" * 70)
    print(final_message.content)

    # Print audit trail summary
    entries = middleware.get_entries()
    print("\n" + "=" * 70)
    print(f"AUDIT TRAIL — {len(entries)} entries")
    print("=" * 70)
    for entry in entries:
        action_name = agentcert.ActionType(entry.action_type).name
        print(f"  [seq {entry.sequence}] {action_name:15s} | {entry.action_summary}")

    # Verify
    verification = middleware.verify()
    print("\n" + "=" * 70)
    print("VERIFICATION")
    print("=" * 70)
    for check in verification.checks:
        icon = "✓" if check.passed else "✗"
        print(f"  {icon} {check.name}: {check.detail}")
    print(f"\nStatus: {verification.status}")

    # Certificate info
    cert = middleware.get_certificate()
    print(f"\nCertificate ID: {cert.cert_id}")
    print(f"Agent name:     {cert.agent_metadata.name}")

    # Save
    output_dir = os.path.join(
        os.path.dirname(__file__), "..", "output", "ecosystem-tracker"
    )
    os.makedirs(output_dir, exist_ok=True)
    middleware.save(output_dir)
    print(f"\nCertificate and trail saved to: {output_dir}")

    return middleware


if __name__ == "__main__":
    run()
