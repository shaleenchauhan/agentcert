"""Agent 3: Code Review Agent.

Uses Claude (Sonnet) + GitHub API to review the AgentCert repository
for code quality and security issues. All actions are captured as
signed, hash-chained audit entries via AgentCertMiddleware.
"""

import base64
import os
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

import agentcert
from agentcert.integrations.langchain import AgentCertMiddleware
from langchain_anthropic import ChatAnthropic
from langchain_core.messages import SystemMessage, HumanMessage
from langchain_core.tools import tool
from langgraph.prebuilt import create_react_agent

KEYS_DIR = os.path.join(os.path.dirname(__file__), "..", "keys")

GITHUB_API = "https://api.github.com"
REPO = "shaleenchauhan/agentcert"


@tool
def list_repo_files(path: str = "") -> str:
    """List files in the agentcert GitHub repository at the given path. Use empty string for root."""
    headers = {"Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}"}
    url = f"{GITHUB_API}/repos/{REPO}/contents/{path}"
    resp = requests.get(url, headers=headers)
    if resp.status_code != 200:
        return f"Error: {resp.status_code} - {resp.text[:200]}"
    items = resp.json()
    formatted = []
    for item in items:
        icon = "📁" if item["type"] == "dir" else "📄"
        formatted.append(f"{icon} {item['path']} ({item['type']})")
    return "\n".join(formatted)


@tool
def fetch_file_content(path: str) -> str:
    """Fetch the content of a specific file from the agentcert GitHub repository."""
    headers = {"Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}"}
    url = f"{GITHUB_API}/repos/{REPO}/contents/{path}"
    resp = requests.get(url, headers=headers)
    if resp.status_code != 200:
        return f"Error: {resp.status_code} - {resp.text[:200]}"
    data = resp.json()
    if data.get("encoding") == "base64":
        content = base64.b64decode(data["content"]).decode("utf-8", errors="replace")
        if len(content) > 5000:
            return content[:5000] + f"\n\n... [truncated, full file is {len(content)} chars]"
        return content
    return "Could not decode file content."


SYSTEM_PROMPT = (
    "You are a senior code reviewer specializing in cryptography and security. "
    "Your job is to:\n"
    "1. Explore the repository structure to understand the codebase\n"
    "2. Fetch and review key source files — focus on cryptographic operations, "
    "signature verification, and Bitcoin anchoring\n"
    "3. Produce a code review report with:\n"
    "   - Architecture assessment: is the code well-structured?\n"
    "   - Security review: any cryptographic issues, key handling concerns, "
    "or vulnerability patterns?\n"
    "   - Code quality: naming, error handling, test coverage observations\n"
    "   - Specific findings: cite file names and line-level observations "
    "where possible\n"
    "   - Overall rating: PASS / PASS WITH NOTES / NEEDS WORK / FAIL\n\n"
    "Review at least 4 source files. Focus on the core modules "
    "(certificate.py, verify.py, anchor.py, audit.py, audit_verify.py)."
)


def run():
    """Run the code review agent and return the middleware."""
    # AgentCert identity + audit trail
    middleware = AgentCertMiddleware(
        creator_keys=os.path.join(KEYS_DIR, "creator.keys.json"),
        agent_keys=os.path.join(KEYS_DIR, "code-reviewer.keys.json"),
        agent_name="code-review-v1",
        platform="langchain",
        capabilities=["github-read", "code-analysis", "security-review"],
        constraints=["read-only", "no-write-access", "public-repos-only"],
        risk_tier=2,
    )

    # LLM + tools
    llm = ChatAnthropic(model="claude-sonnet-4-20250514", max_tokens=4096)
    tools = [list_repo_files, fetch_file_content]

    # Create ReAct agent via LangGraph
    agent = create_react_agent(llm, tools)

    # Run with AgentCert callback handler
    handler = middleware.get_handler()
    result = agent.invoke(
        {
            "messages": [
                SystemMessage(content=SYSTEM_PROMPT),
                HumanMessage(
                    content="Review the GitHub repository shaleenchauhan/agentcert. "
                    "Focus on cryptographic security, code quality, and architecture. "
                    "Produce a detailed code review report."
                ),
            ],
        },
        config={"callbacks": [handler]},
    )

    # Print the agent's response
    final_message = result["messages"][-1]
    print("\n" + "=" * 70)
    print("CODE REVIEW REPORT")
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
        os.path.dirname(__file__), "..", "output", "code-reviewer"
    )
    os.makedirs(output_dir, exist_ok=True)
    middleware.save(output_dir)
    print(f"\nCertificate and trail saved to: {output_dir}")

    return middleware


if __name__ == "__main__":
    run()
