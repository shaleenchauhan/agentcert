"""Shared test fixtures for agentcert-crewai tests."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

import agentcert
from agentcert.audit import create_audit_trail
from agentcert.types import Certificate, KeyPair


# ── CrewAI step_output fakes ────────────────────────────────────────────────
# These mirror the real CrewAI types (AgentAction, AgentFinish, ToolResult)
# so we can test step_callback without needing an LLM.


@dataclass
class FakeAgentAction:
    """Mimics crewai.agents.parser.AgentAction."""

    thought: str
    tool: str
    tool_input: str
    text: str
    result: str | None = None


@dataclass
class FakeAgentFinish:
    """Mimics crewai.agents.parser.AgentFinish."""

    thought: str
    output: str
    text: str


@dataclass
class FakeToolResult:
    """Mimics crewai.tools.tool_types.ToolResult."""

    result: str
    result_as_answer: bool = False


@dataclass
class FakeTaskOutput:
    """Mimics crewai.tasks.task_output.TaskOutput (subset of fields)."""

    description: str
    name: str | None
    raw: str
    agent: str
    summary: str | None = None
    expected_output: str | None = None
    pydantic: Any = None
    json_dict: dict | None = None


# ── Key / cert fixtures ──────────────────────────────────────────────────────


@pytest.fixture
def creator_keys() -> KeyPair:
    """Generate a fresh creator key pair."""
    return agentcert.generate_keys()


@pytest.fixture
def agent_keys() -> KeyPair:
    """Generate a fresh agent key pair."""
    return agentcert.generate_keys()


@pytest.fixture
def second_agent_keys() -> KeyPair:
    """Generate a second agent key pair (for multi-agent tests)."""
    return agentcert.generate_keys()


@pytest.fixture
def certificate(creator_keys: KeyPair, agent_keys: KeyPair) -> Certificate:
    """Create a signed certificate."""
    return agentcert.create_certificate(
        creator_keys=creator_keys,
        agent_keys=agent_keys,
        name="test-agent",
        platform="crewai",
        model_hash="sha256:test",
        capabilities=["test"],
        constraints=[],
        risk_tier=3,
        expires_days=90,
    )


@pytest.fixture
def tmp_storage_dir(tmp_path):
    """Temporary directory for storage tests."""
    return str(tmp_path / "agentcert-audit")
