"""Agent 4: Shopping Agent.

Uses Claude (Sonnet) to evaluate domain options and make a purchase
decision. Searches are done sequentially due to Porkbun's rate limit
(1 check per 10s). The agent analyzes results and picks the best option,
then triggers a trust handshake with the Vendor Agent before purchasing.
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

from .trust_verification import verify_counterparty

KEYS_DIR = os.path.join(os.path.dirname(__file__), "..", "keys")

# Set by the orchestrator before run() is called
_vendor_agent = None
_shopping_middleware = None


def set_vendor(vendor):
    global _vendor_agent
    _vendor_agent = vendor


def set_middleware(middleware):
    global _shopping_middleware
    _shopping_middleware = middleware


@tool
def check_domain(domain: str) -> str:
    """Check if a single domain is available and get its price.

    Pass a full domain name like 'agentcert-trust.xyz'.
    Note: each check takes ~11 seconds due to API rate limits.
    """
    check = _vendor_agent.check_domain(domain)
    if check.get("error"):
        return f"{domain}: ERROR — {check['error']}"
    status = "AVAILABLE" if check.get("available") else "UNAVAILABLE"
    price = check.get("price", "unknown")
    return f"{domain}: {status} — ${price}/yr"


@tool
def purchase_domain(domain: str) -> str:
    """Purchase a domain through the vendor agent.

    This triggers a trust handshake: both agents verify each other's
    certificates before the transaction proceeds. Only call this after
    confirming the domain is available.
    """
    shopping_cert = _shopping_middleware.get_certificate()
    vendor_cert = _vendor_agent.get_certificate()

    # Verify vendor certificate
    vendor_trust = verify_counterparty(
        vendor_cert,
        required_capabilities=["domain-sales"],
    )

    if not vendor_trust.trusted:
        return f"VENDOR REJECTED: {vendor_trust.reason}. Transaction aborted."

    # Send purchase request (vendor verifies our cert internally)
    result = _vendor_agent.handle_purchase_request(domain, shopping_cert)

    if result["success"]:
        return f"SUCCESS: {result['message']}"
    else:
        return f"FAILED: {result['reason']}"


SYSTEM_PROMPT = (
    "You are a shopping agent tasked with finding and purchasing a domain name.\n\n"
    "Your goal: Purchase an available, affordable domain related to "
    "'agent trust' or 'agent identity' or 'agentcert'. Budget: under $15.\n\n"
    "IMPORTANT: Each domain check takes ~11 seconds due to API rate limits. "
    "Be strategic — check only the most promising names. Do NOT check more "
    "than 6 domains total.\n\n"
    "Steps:\n"
    "1. Check 3-5 creative domain names one at a time (use .xyz, .site, or "
    ".click — they're cheapest at ~$2/yr)\n"
    "2. Pick the first available one that's under $15\n"
    "3. Purchase it immediately using the purchase_domain tool\n\n"
    "Try unique, distinctive names that are unlikely to be taken, e.g.:\n"
    "agentcert-trust.xyz, verifyagent2025.site, agentchain-id.xyz\n\n"
    "The vendor will verify your identity certificate before processing."
)


def run(vendor, middleware):
    """Run the shopping agent. Returns the agent's final response."""
    set_vendor(vendor)
    set_middleware(middleware)

    llm = ChatAnthropic(model="claude-sonnet-4-20250514", max_tokens=4096)
    tools = [check_domain, purchase_domain]

    agent = create_react_agent(llm, tools)

    handler = middleware.get_handler()
    result = agent.invoke(
        {
            "messages": [
                SystemMessage(content=SYSTEM_PROMPT),
                HumanMessage(
                    content="Find and purchase an available domain related to AI "
                    "agent trust or identity. Budget: under $15. Be strategic — "
                    "check only a few creative names."
                ),
            ],
        },
        config={"callbacks": [handler]},
    )

    final_message = result["messages"][-1]
    return final_message.content
