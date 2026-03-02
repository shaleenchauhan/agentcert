"""Tests for AgentCertAutoGenMiddleware (single-agent)."""

from __future__ import annotations

import asyncio
import functools
from typing import Any
from unittest.mock import patch

import pytest

import agentcert
from agentcert.types import ActionType, KeyPair
from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.base import TaskResult
from autogen_agentchat.messages import (
    TextMessage,
    ToolCallExecutionEvent,
    ToolCallRequestEvent,
)
from autogen_core import FunctionCall
from autogen_core.models import FunctionExecutionResult

from agentcert_autogen.middleware import AgentCertAutoGenMiddleware
from conftest import MockModelClient


# ---------------------------------------------------------------------------
# Sample tool functions
# ---------------------------------------------------------------------------


async def get_weather(city: str) -> str:
    """Get the current weather for a city."""
    return f"Sunny in {city}"


def search_web(query: str) -> str:
    """Search the web for a query."""
    return f"Results for: {query}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _make_stream(messages: list[Any]) -> Any:
    """Create an async generator yielding the given messages."""
    for msg in messages:
        yield msg


# ---------------------------------------------------------------------------
# TestInit
# ---------------------------------------------------------------------------


class TestInit:
    """Tests for middleware initialization."""

    def test_creates_certificate(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str
    ) -> None:
        mw = AgentCertAutoGenMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test_agent",
            storage_dir=tmp_storage_dir,
        )
        assert mw.certificate is not None
        assert mw.agent_name == "test_agent"

    def test_creates_empty_trail(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str
    ) -> None:
        mw = AgentCertAutoGenMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test_agent",
            storage_dir=tmp_storage_dir,
        )
        assert mw.trail is not None
        assert len(mw.trail.entries) == 0

    def test_platform_is_autogen(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str
    ) -> None:
        mw = AgentCertAutoGenMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test_agent",
            storage_dir=tmp_storage_dir,
        )
        assert mw.certificate.agent_metadata.platform == "autogen"

    def test_custom_capabilities(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str
    ) -> None:
        mw = AgentCertAutoGenMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test_agent",
            capabilities=["web_search", "analysis"],
            constraints=["no_pii"],
            risk_tier=2,
            storage_dir=tmp_storage_dir,
        )
        meta = mw.certificate.agent_metadata
        assert "web_search" in meta.capabilities
        assert "analysis" in meta.capabilities
        assert "no_pii" in meta.constraints
        assert meta.risk_tier == 2


# ---------------------------------------------------------------------------
# TestWrapTools
# ---------------------------------------------------------------------------


class TestWrapTools:
    """Tests for tool wrapping."""

    def test_preserves_function_name(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str
    ) -> None:
        mw = AgentCertAutoGenMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test_agent",
            storage_dir=tmp_storage_dir,
        )
        wrapped = mw.wrap_tools([get_weather])
        assert wrapped[0].__name__ == "get_weather"

    def test_preserves_docstring(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str
    ) -> None:
        mw = AgentCertAutoGenMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test_agent",
            storage_dir=tmp_storage_dir,
        )
        wrapped = mw.wrap_tools([get_weather])
        assert wrapped[0].__doc__ == get_weather.__doc__

    def test_preserves_annotations(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str
    ) -> None:
        mw = AgentCertAutoGenMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test_agent",
            storage_dir=tmp_storage_dir,
        )
        wrapped = mw.wrap_tools([get_weather])
        assert wrapped[0].__wrapped__ is get_weather

    @pytest.mark.asyncio
    async def test_async_tool_logs_tool_use(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str
    ) -> None:
        mw = AgentCertAutoGenMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test_agent",
            storage_dir=tmp_storage_dir,
        )
        wrapped = mw.wrap_tools([get_weather])
        result = await wrapped[0](city="London")
        assert result == "Sunny in London"

        entries = mw.get_entries(ActionType.TOOL_USE)
        assert len(entries) == 1
        assert "get_weather" in entries[0].action_summary

    def test_sync_tool_logs_tool_use(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str
    ) -> None:
        mw = AgentCertAutoGenMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test_agent",
            storage_dir=tmp_storage_dir,
        )
        wrapped = mw.wrap_tools([search_web])
        result = wrapped[0](query="test")
        assert result == "Results for: test"

        entries = mw.get_entries(ActionType.TOOL_USE)
        assert len(entries) == 1
        assert "search_web" in entries[0].action_summary

    @pytest.mark.asyncio
    async def test_wrapped_tools_work_with_autogen(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str
    ) -> None:
        """Wrapped tools are accepted by AssistantAgent."""
        mw = AgentCertAutoGenMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="weather_agent",
            storage_dir=tmp_storage_dir,
        )
        wrapped = mw.wrap_tools([get_weather])

        client = MockModelClient(
            responses=[
                [FunctionCall(id="c1", arguments='{"city":"Paris"}', name="get_weather")],
                "Done.",
            ]
        )
        agent = AssistantAgent(
            name="weather_agent",
            model_client=client,
            tools=wrapped,
            reflect_on_tool_use=True,
        )
        result = await agent.run(task="Weather in Paris?")
        assert isinstance(result, TaskResult)

        # The wrapped tool should have logged a TOOL_USE entry
        entries = mw.get_entries(ActionType.TOOL_USE)
        assert len(entries) >= 1


# ---------------------------------------------------------------------------
# TestProcessStream
# ---------------------------------------------------------------------------


class TestProcessStream:
    """Tests for stream processing."""

    @pytest.mark.asyncio
    async def test_maps_text_message_to_decision(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str
    ) -> None:
        mw = AgentCertAutoGenMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test_agent",
            storage_dir=tmp_storage_dir,
        )
        stream = _make_stream([
            TextMessage(source="test_agent", content="Hello, world!"),
        ])
        result = await mw.process_stream(stream)
        assert result is None  # No TaskResult in stream

        entries = mw.get_entries(ActionType.DECISION)
        assert len(entries) == 1
        assert "test_agent" in entries[0].action_summary

    @pytest.mark.asyncio
    async def test_maps_tool_request_to_tool_use(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str
    ) -> None:
        mw = AgentCertAutoGenMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test_agent",
            storage_dir=tmp_storage_dir,
        )
        stream = _make_stream([
            ToolCallRequestEvent(
                source="test_agent",
                content=[FunctionCall(id="c1", arguments="{}", name="my_tool")],
            ),
        ])
        result = await mw.process_stream(stream)

        entries = mw.get_entries(ActionType.TOOL_USE)
        assert len(entries) == 1
        assert "Tool call requested" in entries[0].action_summary

    @pytest.mark.asyncio
    async def test_skips_tool_execution_event(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str
    ) -> None:
        mw = AgentCertAutoGenMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test_agent",
            storage_dir=tmp_storage_dir,
        )
        stream = _make_stream([
            ToolCallExecutionEvent(
                source="test_agent",
                content=[FunctionExecutionResult(content="result", name="my_tool", call_id="c1")],
            ),
        ])
        result = await mw.process_stream(stream)

        # ToolCallExecutionEvent is skipped (already captured by wrap_tools)
        assert len(mw.trail.entries) == 0

    @pytest.mark.asyncio
    async def test_skips_user_messages(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str
    ) -> None:
        mw = AgentCertAutoGenMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test_agent",
            storage_dir=tmp_storage_dir,
        )
        stream = _make_stream([
            TextMessage(source="user", content="Hi!"),
        ])
        result = await mw.process_stream(stream)

        assert len(mw.trail.entries) == 0

    @pytest.mark.asyncio
    async def test_captures_task_result(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str
    ) -> None:
        mw = AgentCertAutoGenMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test_agent",
            storage_dir=tmp_storage_dir,
        )
        task_result = TaskResult(
            messages=[TextMessage(source="test_agent", content="Done")],
            stop_reason="complete",
        )
        stream = _make_stream([
            TextMessage(source="test_agent", content="Processing..."),
            task_result,
        ])
        result = await mw.process_stream(stream)

        assert result is task_result
        # TextMessage should be logged, TaskResult should not
        entries = mw.get_entries(ActionType.DECISION)
        assert len(entries) == 1


# ---------------------------------------------------------------------------
# TestRun
# ---------------------------------------------------------------------------


class TestRun:
    """Tests for the run() convenience method."""

    @pytest.mark.asyncio
    async def test_run_returns_task_result(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str
    ) -> None:
        mw = AgentCertAutoGenMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test_agent",
            storage_dir=tmp_storage_dir,
        )
        client = MockModelClient(responses=["Hello back!"])
        agent = AssistantAgent(name="test_agent", model_client=client)

        result = await mw.run(agent, "Hello")
        assert isinstance(result, TaskResult)

        # Should have logged the agent's text response as DECISION
        entries = mw.get_entries(ActionType.DECISION)
        assert len(entries) >= 1

    @pytest.mark.asyncio
    async def test_run_with_tools(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str
    ) -> None:
        mw = AgentCertAutoGenMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="weather_agent",
            storage_dir=tmp_storage_dir,
        )
        wrapped = mw.wrap_tools([get_weather])
        client = MockModelClient(
            responses=[
                [FunctionCall(id="c1", arguments='{"city":"NYC"}', name="get_weather")],
                "Weather is sunny.",
            ]
        )
        agent = AssistantAgent(
            name="weather_agent",
            model_client=client,
            tools=wrapped,
            reflect_on_tool_use=True,
        )

        result = await mw.run(agent, "Weather in NYC?")
        assert isinstance(result, TaskResult)

        # Should have both TOOL_USE and DECISION entries
        tool_entries = mw.get_entries(ActionType.TOOL_USE)
        decision_entries = mw.get_entries(ActionType.DECISION)
        assert len(tool_entries) >= 1
        assert len(decision_entries) >= 1


# ---------------------------------------------------------------------------
# TestNonInterference
# ---------------------------------------------------------------------------


class TestNonInterference:
    """Tests for non-interference: failures don't crash the agent."""

    @pytest.mark.asyncio
    async def test_storage_failure_does_not_crash(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str
    ) -> None:
        mw = AgentCertAutoGenMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test_agent",
            auto_save=True,
            storage_dir=tmp_storage_dir,
        )
        # Sabotage storage
        with patch.object(mw._storage, "persist_entry", side_effect=OSError("Disk full")):
            stream = _make_stream([
                TextMessage(source="test_agent", content="Test"),
            ])
            # Should not raise
            result = await mw.process_stream(stream)

        # Entry should still be in memory
        assert len(mw.trail.entries) == 1


# ---------------------------------------------------------------------------
# TestSave
# ---------------------------------------------------------------------------


class TestSave:
    """Tests for async save."""

    @pytest.mark.asyncio
    async def test_async_save(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str
    ) -> None:
        mw = AgentCertAutoGenMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test_agent",
            storage_dir=tmp_storage_dir,
        )
        stream = _make_stream([
            TextMessage(source="test_agent", content="Saving..."),
        ])
        await mw.process_stream(stream)

        # Should not raise
        await mw.save(directory=tmp_storage_dir)

    @pytest.mark.asyncio
    async def test_save_creates_files(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str
    ) -> None:
        import os

        mw = AgentCertAutoGenMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test_agent",
            storage_dir=tmp_storage_dir,
        )
        mw._log_action(ActionType.DECISION, "test action")
        await mw.save(directory=tmp_storage_dir)

        agent_dir = os.path.join(tmp_storage_dir, "test_agent")
        assert os.path.exists(os.path.join(agent_dir, "trail.json"))
        assert os.path.exists(os.path.join(agent_dir, "cert.json"))


# ---------------------------------------------------------------------------
# TestVerify
# ---------------------------------------------------------------------------


class TestVerify:
    """Tests for trail verification."""

    def test_empty_trail_is_invalid(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str
    ) -> None:
        """Empty trails are INVALID (trail_non_empty check fails)."""
        mw = AgentCertAutoGenMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test_agent",
            storage_dir=tmp_storage_dir,
        )
        result = mw.verify()
        assert result.status == "INVALID"

    def test_trail_with_entries_is_valid(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str
    ) -> None:
        mw = AgentCertAutoGenMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test_agent",
            storage_dir=tmp_storage_dir,
        )
        mw._log_action(ActionType.DECISION, "step 1")
        mw._log_action(ActionType.TOOL_USE, "step 2")
        result = mw.verify()
        assert result.status == "VALID"


# ---------------------------------------------------------------------------
# TestGetVerifyTool
# ---------------------------------------------------------------------------


class TestGetVerifyTool:
    """Tests for verification tool generation."""

    def test_returns_async_function(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str
    ) -> None:
        mw = AgentCertAutoGenMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test_agent",
            storage_dir=tmp_storage_dir,
        )
        tool = mw.get_verify_tool()
        assert asyncio.iscoroutinefunction(tool)
        assert tool.__name__ == "verify_agent_certificate"

    def test_tool_has_docstring(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str
    ) -> None:
        mw = AgentCertAutoGenMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test_agent",
            storage_dir=tmp_storage_dir,
        )
        tool = mw.get_verify_tool()
        assert tool.__doc__ is not None
        assert "certificate" in tool.__doc__.lower()

    def test_tool_has_type_hints(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str
    ) -> None:
        mw = AgentCertAutoGenMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test_agent",
            storage_dir=tmp_storage_dir,
        )
        tool = mw.get_verify_tool()
        annotations = tool.__annotations__
        assert "cert_path" in annotations
        assert "return" in annotations

    @pytest.mark.asyncio
    async def test_tool_verifies_valid_cert(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str, tmp_path: Any
    ) -> None:
        mw = AgentCertAutoGenMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test_agent",
            storage_dir=tmp_storage_dir,
        )
        # Save a cert to verify
        peer_keys = agentcert.generate_keys()
        peer_cert = agentcert.create_certificate(
            creator_keys=creator_keys,
            agent_keys=peer_keys,
            name="peer_agent",
            platform="test",
            model_hash="sha256:test",
            capabilities=["testing"],
            constraints=[],
            risk_tier=3,
            expires_days=90,
        )
        cert_path = str(tmp_path / "peer_cert.json")
        agentcert.save_certificate(peer_cert, cert_path)

        tool = mw.get_verify_tool()
        result = await tool(cert_path=cert_path)
        assert "VALID" in result

        # Should have logged a DECISION entry
        entries = mw.get_entries(ActionType.DECISION)
        assert any("Verified agent" in e.action_summary for e in entries)

    @pytest.mark.asyncio
    async def test_tool_handles_missing_file(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str
    ) -> None:
        mw = AgentCertAutoGenMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test_agent",
            storage_dir=tmp_storage_dir,
        )
        tool = mw.get_verify_tool()
        result = await tool(cert_path="/nonexistent/cert.json")
        assert "Failed" in result

    def test_tool_accepted_by_autogen(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str
    ) -> None:
        """Verification tool can be passed to AssistantAgent."""
        mw = AgentCertAutoGenMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test_agent",
            storage_dir=tmp_storage_dir,
        )
        tool = mw.get_verify_tool()
        client = MockModelClient()

        # Should not raise
        agent = AssistantAgent(
            name="verifier_agent",
            model_client=client,
            tools=[tool],
        )
