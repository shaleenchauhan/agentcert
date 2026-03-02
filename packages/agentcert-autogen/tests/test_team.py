"""Tests for AgentCertTeamMiddleware (multi-agent)."""

from __future__ import annotations

import asyncio
import os
from typing import Any
from unittest.mock import patch

import pytest

import agentcert
from agentcert.types import ActionType, KeyPair
from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.base import TaskResult
from autogen_agentchat.messages import (
    SelectSpeakerEvent,
    SelectorEvent,
    TextMessage,
    ToolCallRequestEvent,
)
from autogen_core import FunctionCall

from agentcert_autogen.middleware import AgentCertAutoGenMiddleware
from agentcert_autogen.team_middleware import AgentCertTeamMiddleware
from conftest import MockModelClient


# ---------------------------------------------------------------------------
# Sample tool
# ---------------------------------------------------------------------------


async def search_web(query: str) -> str:
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


class TestTeamInit:
    """Tests for team middleware initialization."""

    def test_creates_agent_middlewares(
        self, creator_keys: KeyPair, agent_keys: KeyPair, second_agent_keys: KeyPair,
        tmp_storage_dir: str,
    ) -> None:
        mw = AgentCertTeamMiddleware(
            creator_keys=creator_keys,
            team_name="test_team",
            agents={
                "researcher": {"keys": agent_keys, "capabilities": ["web_search"]},
                "analyst": {"keys": second_agent_keys, "capabilities": ["analysis"]},
            },
            storage_dir=tmp_storage_dir,
        )
        assert "researcher" in mw.agent_middlewares
        assert "analyst" in mw.agent_middlewares
        assert isinstance(mw.agent_middlewares["researcher"], AgentCertAutoGenMiddleware)

    def test_creates_coordinator(
        self, creator_keys: KeyPair, agent_keys: KeyPair, second_agent_keys: KeyPair,
        tmp_storage_dir: str,
    ) -> None:
        mw = AgentCertTeamMiddleware(
            creator_keys=creator_keys,
            team_name="test_team",
            agents={
                "researcher": {"keys": agent_keys},
                "analyst": {"keys": second_agent_keys},
            },
            storage_dir=tmp_storage_dir,
        )
        assert mw.coordinator is not None
        assert mw.coordinator.agent_name == "test_team-coordinator"

    def test_team_name_property(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str,
    ) -> None:
        mw = AgentCertTeamMiddleware(
            creator_keys=creator_keys,
            team_name="my_team",
            agents={"agent_a": {"keys": agent_keys}},
            storage_dir=tmp_storage_dir,
        )
        assert mw.team_name == "my_team"


# ---------------------------------------------------------------------------
# TestCoordinator
# ---------------------------------------------------------------------------


class TestCoordinator:
    """Tests for coordinator identity management."""

    def test_auto_generate_coordinator(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str,
    ) -> None:
        mw = AgentCertTeamMiddleware(
            creator_keys=creator_keys,
            team_name="test_team",
            agents={"agent_a": {"keys": agent_keys}},
            storage_dir=tmp_storage_dir,
        )
        # Coordinator should have a valid certificate
        coord_cert = mw.coordinator.certificate
        assert coord_cert is not None

        # Add an entry so trail is non-empty (empty trails are INVALID)
        mw.coordinator._log_action(ActionType.DECISION, "initialized")
        result = mw.coordinator.verify()
        assert result.status == "VALID"

    def test_coordinator_persists_and_reloads(
        self, creator_keys: KeyPair, agent_keys: KeyPair, second_agent_keys: KeyPair,
        tmp_storage_dir: str,
    ) -> None:
        """Second instantiation should reload coordinator keys from disk."""
        mw1 = AgentCertTeamMiddleware(
            creator_keys=creator_keys,
            team_name="persist_team",
            agents={"agent_a": {"keys": agent_keys}},
            storage_dir=tmp_storage_dir,
        )
        coord_cert_1 = mw1.coordinator.certificate

        # Create again — should reload coordinator from disk
        mw2 = AgentCertTeamMiddleware(
            creator_keys=creator_keys,
            team_name="persist_team",
            agents={"agent_b": {"keys": second_agent_keys}},
            storage_dir=tmp_storage_dir,
        )
        coord_cert_2 = mw2.coordinator.certificate

        # Same coordinator identity (same agent_id from same keys)
        assert coord_cert_1.agent_id == coord_cert_2.agent_id

    def test_explicit_coordinator_keys_override(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str,
    ) -> None:
        explicit_keys = agentcert.generate_keys()
        mw = AgentCertTeamMiddleware(
            creator_keys=creator_keys,
            team_name="test_team",
            agents={"agent_a": {"keys": agent_keys}},
            coordinator_keys=explicit_keys,
            storage_dir=tmp_storage_dir,
        )
        # Coordinator should use the explicit keys
        assert mw.coordinator.certificate.agent_id == explicit_keys.identity


# ---------------------------------------------------------------------------
# TestEventRouting
# ---------------------------------------------------------------------------


class TestEventRouting:
    """Tests for routing stream events to correct agent trails."""

    @pytest.mark.asyncio
    async def test_agent_message_routes_to_agent_trail(
        self, creator_keys: KeyPair, agent_keys: KeyPair, second_agent_keys: KeyPair,
        tmp_storage_dir: str,
    ) -> None:
        mw = AgentCertTeamMiddleware(
            creator_keys=creator_keys,
            team_name="test_team",
            agents={
                "researcher": {"keys": agent_keys},
                "analyst": {"keys": second_agent_keys},
            },
            storage_dir=tmp_storage_dir,
        )

        # Mock team.run_stream()
        class MockTeam:
            def run_stream(self, task: str) -> Any:
                return _make_stream([
                    TextMessage(source="researcher", content="Found data."),
                    TextMessage(source="analyst", content="Analysis complete."),
                    TaskResult(
                        messages=[TextMessage(source="analyst", content="Done")],
                        stop_reason="complete",
                    ),
                ])

        result = await mw.run(MockTeam(), "Research AI trust")
        assert isinstance(result, TaskResult)

        # Researcher trail should have 1 entry
        researcher_entries = mw.agent_middlewares["researcher"].get_entries()
        assert len(researcher_entries) == 1
        assert "researcher" in researcher_entries[0].action_summary

        # Analyst trail should have 1 entry
        analyst_entries = mw.agent_middlewares["analyst"].get_entries()
        assert len(analyst_entries) == 1
        assert "analyst" in analyst_entries[0].action_summary

    @pytest.mark.asyncio
    async def test_unknown_source_routes_to_coordinator(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str,
    ) -> None:
        mw = AgentCertTeamMiddleware(
            creator_keys=creator_keys,
            team_name="test_team",
            agents={"agent_a": {"keys": agent_keys}},
            storage_dir=tmp_storage_dir,
        )

        class MockTeam:
            def run_stream(self, task: str) -> Any:
                return _make_stream([
                    TextMessage(source="orchestrator", content="Planning..."),
                    TaskResult(messages=[], stop_reason="complete"),
                ])

        await mw.run(MockTeam(), "Do something")

        coord_entries = mw.coordinator.get_entries()
        assert len(coord_entries) == 1
        assert "orchestrator" in coord_entries[0].action_summary

    @pytest.mark.asyncio
    async def test_tool_request_routes_to_agent(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str,
    ) -> None:
        mw = AgentCertTeamMiddleware(
            creator_keys=creator_keys,
            team_name="test_team",
            agents={"agent_a": {"keys": agent_keys}},
            storage_dir=tmp_storage_dir,
        )

        class MockTeam:
            def run_stream(self, task: str) -> Any:
                return _make_stream([
                    ToolCallRequestEvent(
                        source="agent_a",
                        content=[FunctionCall(id="c1", arguments="{}", name="tool")],
                    ),
                    TaskResult(messages=[], stop_reason="complete"),
                ])

        await mw.run(MockTeam(), "Do something")

        agent_entries = mw.agent_middlewares["agent_a"].get_entries(ActionType.TOOL_USE)
        assert len(agent_entries) == 1

    @pytest.mark.asyncio
    async def test_skips_user_messages(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str,
    ) -> None:
        mw = AgentCertTeamMiddleware(
            creator_keys=creator_keys,
            team_name="test_team",
            agents={"agent_a": {"keys": agent_keys}},
            storage_dir=tmp_storage_dir,
        )

        class MockTeam:
            def run_stream(self, task: str) -> Any:
                return _make_stream([
                    TextMessage(source="user", content="Hello"),
                    TaskResult(messages=[], stop_reason="complete"),
                ])

        await mw.run(MockTeam(), "Hello")

        # No entries anywhere
        assert len(mw.agent_middlewares["agent_a"].get_entries()) == 0
        assert len(mw.coordinator.get_entries()) == 0


# ---------------------------------------------------------------------------
# TestTeamTypes
# ---------------------------------------------------------------------------


class TestTeamTypes:
    """Tests for different team type message patterns."""

    @pytest.mark.asyncio
    async def test_round_robin_pattern(
        self, creator_keys: KeyPair, agent_keys: KeyPair, second_agent_keys: KeyPair,
        tmp_storage_dir: str,
    ) -> None:
        """RoundRobin: sequential agent messages, no special events."""
        mw = AgentCertTeamMiddleware(
            creator_keys=creator_keys,
            team_name="rr_team",
            agents={
                "agent_a": {"keys": agent_keys},
                "agent_b": {"keys": second_agent_keys},
            },
            storage_dir=tmp_storage_dir,
        )

        class MockRoundRobin:
            def run_stream(self, task: str) -> Any:
                return _make_stream([
                    TextMessage(source="agent_a", content="Step 1"),
                    TextMessage(source="agent_b", content="Step 2"),
                    TextMessage(source="agent_a", content="Step 3"),
                    TaskResult(messages=[], stop_reason="complete"),
                ])

        await mw.run(MockRoundRobin(), "Do task")

        assert len(mw.agent_middlewares["agent_a"].get_entries()) == 2
        assert len(mw.agent_middlewares["agent_b"].get_entries()) == 1
        assert len(mw.coordinator.get_entries()) == 0

    @pytest.mark.asyncio
    async def test_selector_pattern(
        self, creator_keys: KeyPair, agent_keys: KeyPair, second_agent_keys: KeyPair,
        tmp_storage_dir: str,
    ) -> None:
        """SelectorGroupChat: includes selection events routed to coordinator."""
        mw = AgentCertTeamMiddleware(
            creator_keys=creator_keys,
            team_name="sel_team",
            agents={
                "agent_a": {"keys": agent_keys},
                "agent_b": {"keys": second_agent_keys},
            },
            storage_dir=tmp_storage_dir,
        )

        class MockSelector:
            def run_stream(self, task: str) -> Any:
                return _make_stream([
                    # Selector picks agent_a
                    SelectorEvent(source="sel_team", content="agent_a"),
                    TextMessage(source="agent_a", content="I'll start."),
                    # Selector picks agent_b
                    SelectorEvent(source="sel_team", content="agent_b"),
                    TextMessage(source="agent_b", content="My turn."),
                    TaskResult(messages=[], stop_reason="complete"),
                ])

        await mw.run(MockSelector(), "Do task")

        # Agent messages in their trails
        assert len(mw.agent_middlewares["agent_a"].get_entries()) == 1
        assert len(mw.agent_middlewares["agent_b"].get_entries()) == 1

        # Selection events go to coordinator (source="sel_team" not a known agent)
        coord_entries = mw.coordinator.get_entries()
        assert len(coord_entries) == 2
        assert all("SelectorEvent" in e.action_summary for e in coord_entries)

    @pytest.mark.asyncio
    async def test_magentic_one_pattern(
        self, creator_keys: KeyPair, agent_keys: KeyPair, second_agent_keys: KeyPair,
        tmp_storage_dir: str,
    ) -> None:
        """MagenticOne: orchestrator planning events go to coordinator."""
        mw = AgentCertTeamMiddleware(
            creator_keys=creator_keys,
            team_name="m1_team",
            agents={
                "agent_a": {"keys": agent_keys},
                "agent_b": {"keys": second_agent_keys},
            },
            storage_dir=tmp_storage_dir,
        )

        class MockMagenticOne:
            def run_stream(self, task: str) -> Any:
                return _make_stream([
                    TextMessage(source="MagenticOneOrchestrator", content="Plan: step 1 → agent_a, step 2 → agent_b"),
                    TextMessage(source="agent_a", content="Done step 1."),
                    TextMessage(source="agent_b", content="Done step 2."),
                    TaskResult(messages=[], stop_reason="complete"),
                ])

        await mw.run(MockMagenticOne(), "Complex task")

        assert len(mw.agent_middlewares["agent_a"].get_entries()) == 1
        assert len(mw.agent_middlewares["agent_b"].get_entries()) == 1

        # Orchestrator messages go to coordinator
        coord_entries = mw.coordinator.get_entries()
        assert len(coord_entries) == 1
        assert "MagenticOneOrchestrator" in coord_entries[0].action_summary


# ---------------------------------------------------------------------------
# TestWrapTools
# ---------------------------------------------------------------------------


class TestTeamWrapTools:
    """Tests for team-level tool wrapping."""

    def test_wrap_tools_for_known_agent(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str,
    ) -> None:
        mw = AgentCertTeamMiddleware(
            creator_keys=creator_keys,
            team_name="test_team",
            agents={"agent_a": {"keys": agent_keys}},
            storage_dir=tmp_storage_dir,
        )
        wrapped = mw.wrap_tools("agent_a", [search_web])
        assert len(wrapped) == 1
        assert wrapped[0].__name__ == "search_web"

    def test_wrap_tools_unknown_agent_raises(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str,
    ) -> None:
        mw = AgentCertTeamMiddleware(
            creator_keys=creator_keys,
            team_name="test_team",
            agents={"agent_a": {"keys": agent_keys}},
            storage_dir=tmp_storage_dir,
        )
        with pytest.raises(ValueError, match="Unknown agent"):
            mw.wrap_tools("nonexistent", [search_web])


# ---------------------------------------------------------------------------
# TestVerifyAll
# ---------------------------------------------------------------------------


class TestVerifyAll:
    """Tests for verify_all()."""

    def test_verify_all_agents_and_coordinator(
        self, creator_keys: KeyPair, agent_keys: KeyPair, second_agent_keys: KeyPair,
        tmp_storage_dir: str,
    ) -> None:
        mw = AgentCertTeamMiddleware(
            creator_keys=creator_keys,
            team_name="test_team",
            agents={
                "agent_a": {"keys": agent_keys},
                "agent_b": {"keys": second_agent_keys},
            },
            storage_dir=tmp_storage_dir,
        )
        # Add entries so trails are non-empty (empty trails are INVALID)
        mw.agent_middlewares["agent_a"]._log_action(ActionType.DECISION, "step 1")
        mw.agent_middlewares["agent_b"]._log_action(ActionType.DECISION, "step 2")
        mw.coordinator._log_action(ActionType.DECISION, "coordination")

        results = mw.verify_all()
        assert "agent_a" in results
        assert "agent_b" in results
        assert "coordinator" in results
        assert all(r.status == "VALID" for r in results.values())


# ---------------------------------------------------------------------------
# TestSave
# ---------------------------------------------------------------------------


class TestTeamSave:
    """Tests for team save."""

    @pytest.mark.asyncio
    async def test_save_all_trails(
        self, creator_keys: KeyPair, agent_keys: KeyPair, second_agent_keys: KeyPair,
        tmp_storage_dir: str,
    ) -> None:
        mw = AgentCertTeamMiddleware(
            creator_keys=creator_keys,
            team_name="save_team",
            agents={
                "agent_a": {"keys": agent_keys},
                "agent_b": {"keys": second_agent_keys},
            },
            storage_dir=tmp_storage_dir,
        )
        # Add entries
        mw.agent_middlewares["agent_a"]._log_action(ActionType.DECISION, "step 1")
        mw.agent_middlewares["agent_b"]._log_action(ActionType.DECISION, "step 2")
        mw.coordinator._log_action(ActionType.DECISION, "coordination")

        await mw.save(directory=tmp_storage_dir)

        # Check files exist
        for name in ("agent_a", "agent_b", "save_team-coordinator"):
            agent_dir = os.path.join(tmp_storage_dir, name)
            assert os.path.exists(os.path.join(agent_dir, "trail.json")), f"Missing trail for {name}"
            assert os.path.exists(os.path.join(agent_dir, "cert.json")), f"Missing cert for {name}"


# ---------------------------------------------------------------------------
# TestGetVerifyTool
# ---------------------------------------------------------------------------


class TestTeamGetVerifyTool:
    """Tests for team-level verification tool."""

    def test_get_verify_tool_for_known_agent(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str,
    ) -> None:
        mw = AgentCertTeamMiddleware(
            creator_keys=creator_keys,
            team_name="test_team",
            agents={"agent_a": {"keys": agent_keys}},
            storage_dir=tmp_storage_dir,
        )
        tool = mw.get_verify_tool("agent_a")
        assert asyncio.iscoroutinefunction(tool)

    def test_get_verify_tool_unknown_agent_raises(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str,
    ) -> None:
        mw = AgentCertTeamMiddleware(
            creator_keys=creator_keys,
            team_name="test_team",
            agents={"agent_a": {"keys": agent_keys}},
            storage_dir=tmp_storage_dir,
        )
        with pytest.raises(ValueError, match="Unknown agent"):
            mw.get_verify_tool("nonexistent")
