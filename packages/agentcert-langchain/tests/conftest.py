"""Shared test fixtures for agentcert-langchain tests."""

from __future__ import annotations

import json
from uuid import uuid4

import pytest

import agentcert
from agentcert.audit import create_audit_trail
from agentcert.types import Certificate, KeyPair


@pytest.fixture
def creator_keys() -> KeyPair:
    """Generate a fresh creator key pair."""
    return agentcert.generate_keys()


@pytest.fixture
def agent_keys() -> KeyPair:
    """Generate a fresh agent key pair."""
    return agentcert.generate_keys()


@pytest.fixture
def certificate(creator_keys: KeyPair, agent_keys: KeyPair) -> Certificate:
    """Create a signed certificate."""
    return agentcert.create_certificate(
        creator_keys=creator_keys,
        agent_keys=agent_keys,
        name="lc-test",
        platform="langchain",
        model_hash="sha256:test",
        capabilities=["search"],
        constraints=["none"],
        risk_tier=1,
        expires_days=30,
    )


@pytest.fixture
def peer_keys() -> KeyPair:
    """Generate a key pair for a peer agent."""
    return agentcert.generate_keys()


@pytest.fixture
def peer_certificate(
    creator_keys: KeyPair, peer_keys: KeyPair
) -> Certificate:
    """Create a signed certificate for a peer agent."""
    return agentcert.create_certificate(
        creator_keys=creator_keys,
        agent_keys=peer_keys,
        name="peer-agent",
        platform="langchain",
        model_hash="sha256:peer",
        capabilities=["analysis"],
        constraints=[],
        risk_tier=2,
        expires_days=30,
    )


# ── Mock LangChain objects ─────────────────────────────────────────────────


class MockAgentAction:
    """Mock LangChain AgentAction."""

    def __init__(
        self, tool: str = "web_search", tool_input: dict | None = None, log: str = ""
    ) -> None:
        self.tool = tool
        self.tool_input = tool_input or {"query": "test"}
        self.log = log


class MockAgentFinish:
    """Mock LangChain AgentFinish."""

    def __init__(
        self, return_values: dict | None = None, log: str = ""
    ) -> None:
        self.return_values = return_values or {"output": "done"}
        self.log = log


class MockGeneration:
    """Mock LangChain Generation."""

    def __init__(self, text: str = "response text") -> None:
        self.text = text


class MockLLMResult:
    """Mock LangChain LLMResult."""

    def __init__(self, text: str = "response text") -> None:
        self.generations = [[MockGeneration(text)]]


class MockExecutor:
    """Mock LangChain AgentExecutor with callbacks attribute."""

    def __init__(self, callbacks: list | None = None) -> None:
        self.callbacks = callbacks


class MockNoCallbacks:
    """Object with no callbacks attribute."""

    pass
