"""Tests for AgentCertCrewMiddleware (multi-agent crew)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

import agentcert
from agentcert.types import ActionType, KeyPair
from agentcert_middleware import BaseMiddleware

from agentcert_crewai.crew_middleware import AgentCertCrewMiddleware
from agentcert_crewai.middleware import AgentCertCrewAIMiddleware
from agentcert_crewai.tool import AgentCertVerifyTool

from conftest import FakeAgentAction, FakeAgentFinish, FakeTaskOutput


class TestCrewMiddlewareInit:
    """Tests for AgentCertCrewMiddleware initialization."""

    def test_creates_agent_middlewares(
        self,
        creator_keys: KeyPair,
        agent_keys: KeyPair,
        second_agent_keys: KeyPair,
        tmp_storage_dir: str,
    ):
        """Init creates a middleware for each agent in the dict."""
        crew_mw = AgentCertCrewMiddleware(
            creator_keys=creator_keys,
            crew_name="test-crew",
            agents={
                "researcher": {
                    "keys": agent_keys,
                    "capabilities": ["search"],
                    "risk_tier": 2,
                },
                "writer": {
                    "keys": second_agent_keys,
                    "capabilities": ["writing"],
                    "risk_tier": 1,
                },
            },
            storage_dir=tmp_storage_dir,
        )

        assert "researcher" in crew_mw._agent_middlewares
        assert "writer" in crew_mw._agent_middlewares
        assert isinstance(
            crew_mw._agent_middlewares["researcher"],
            AgentCertCrewAIMiddleware,
        )

    def test_agent_certs_are_independent(
        self,
        creator_keys: KeyPair,
        agent_keys: KeyPair,
        second_agent_keys: KeyPair,
        tmp_storage_dir: str,
    ):
        """Each agent has its own independent certificate."""
        crew_mw = AgentCertCrewMiddleware(
            creator_keys=creator_keys,
            crew_name="test-crew",
            agents={
                "agent-a": {"keys": agent_keys, "risk_tier": 2},
                "agent-b": {"keys": second_agent_keys, "risk_tier": 1},
            },
            storage_dir=tmp_storage_dir,
        )

        cert_a = crew_mw.get_agent_middleware("agent-a").certificate
        cert_b = crew_mw.get_agent_middleware("agent-b").certificate
        coord_cert = crew_mw.coordinator_certificate

        assert cert_a.cert_id != cert_b.cert_id
        assert cert_a.cert_id != coord_cert.cert_id
        assert cert_b.cert_id != coord_cert.cert_id


class TestCoordinatorIdentity:
    """Tests for coordinator auto-generation and persistence."""

    def test_auto_generates_coordinator(
        self,
        creator_keys: KeyPair,
        agent_keys: KeyPair,
        tmp_storage_dir: str,
    ):
        """Coordinator keys and cert are auto-generated."""
        crew_mw = AgentCertCrewMiddleware(
            creator_keys=creator_keys,
            crew_name="test-crew",
            agents={"agent": {"keys": agent_keys}},
            storage_dir=tmp_storage_dir,
        )

        coord_cert = crew_mw.coordinator_certificate
        assert coord_cert is not None
        assert "orchestration" in coord_cert.agent_metadata.capabilities
        assert "task_delegation" in coord_cert.agent_metadata.capabilities

    def test_coordinator_persisted_and_reloaded(
        self,
        creator_keys: KeyPair,
        agent_keys: KeyPair,
        tmp_storage_dir: str,
    ):
        """Second init loads the same coordinator from disk."""
        crew_mw1 = AgentCertCrewMiddleware(
            creator_keys=creator_keys,
            crew_name="persist-crew",
            agents={"agent": {"keys": agent_keys}},
            storage_dir=tmp_storage_dir,
        )
        cert_id_1 = crew_mw1.coordinator_certificate.cert_id

        crew_mw2 = AgentCertCrewMiddleware(
            creator_keys=creator_keys,
            crew_name="persist-crew",
            agents={"agent": {"keys": agent_keys}},
            storage_dir=tmp_storage_dir,
        )
        cert_id_2 = crew_mw2.coordinator_certificate.cert_id

        assert cert_id_1 == cert_id_2

    def test_coordinator_override(
        self,
        creator_keys: KeyPair,
        agent_keys: KeyPair,
        tmp_storage_dir: str,
    ):
        """Explicit coordinator_keys overrides auto-generation."""
        explicit_keys = agentcert.generate_keys()
        crew_mw = AgentCertCrewMiddleware(
            creator_keys=creator_keys,
            crew_name="override-crew",
            agents={"agent": {"keys": agent_keys}},
            coordinator_keys=explicit_keys,
            storage_dir=tmp_storage_dir,
        )

        coord_cert = crew_mw.coordinator_certificate
        assert coord_cert.agent_public_key == explicit_keys.public_key_hex

    def test_coordinator_independent_of_agent_certs(
        self,
        creator_keys: KeyPair,
        agent_keys: KeyPair,
        tmp_storage_dir: str,
    ):
        """Coordinator certificate is independent from agent certificates.

        Coordinator revocation would not affect agents, and vice versa —
        separate certs, separate trails.
        """
        crew_mw = AgentCertCrewMiddleware(
            creator_keys=creator_keys,
            crew_name="independence-crew",
            agents={"agent": {"keys": agent_keys}},
            storage_dir=tmp_storage_dir,
        )

        agent_cert = crew_mw.get_agent_middleware("agent").certificate
        coord_cert = crew_mw.coordinator_certificate

        # Different certs
        assert agent_cert.cert_id != coord_cert.cert_id
        # Different agent keys
        assert agent_cert.agent_public_key != coord_cert.agent_public_key
        # Different trails
        assert (
            crew_mw.get_agent_middleware("agent").trail.trail_id
            != crew_mw._coordinator_middleware.trail.trail_id
        )


class TestGetStepCallback:
    """Tests for get_step_callback routing."""

    def test_routes_to_correct_agent(
        self,
        creator_keys: KeyPair,
        agent_keys: KeyPair,
        second_agent_keys: KeyPair,
        tmp_storage_dir: str,
    ):
        """get_step_callback returns the callback for the specified agent."""
        crew_mw = AgentCertCrewMiddleware(
            creator_keys=creator_keys,
            crew_name="route-crew",
            agents={
                "agent-a": {"keys": agent_keys},
                "agent-b": {"keys": second_agent_keys},
            },
            storage_dir=tmp_storage_dir,
        )

        cb_a = crew_mw.get_step_callback("agent-a")
        cb_b = crew_mw.get_step_callback("agent-b")

        action = FakeAgentAction(
            thought="Test", tool="search", tool_input="{}", text=""
        )

        cb_a(action)
        cb_b(action)

        # Each agent's trail has exactly 1 entry
        assert len(crew_mw.get_agent_middleware("agent-a").trail.entries) == 1
        assert len(crew_mw.get_agent_middleware("agent-b").trail.entries) == 1

    def test_unknown_agent_raises(
        self,
        creator_keys: KeyPair,
        agent_keys: KeyPair,
        tmp_storage_dir: str,
    ):
        """get_step_callback raises ValueError for unknown agent."""
        crew_mw = AgentCertCrewMiddleware(
            creator_keys=creator_keys,
            crew_name="crew",
            agents={"agent": {"keys": agent_keys}},
            storage_dir=tmp_storage_dir,
        )

        with pytest.raises(ValueError, match="Unknown agent"):
            crew_mw.get_step_callback("nonexistent")


class TestGetTaskCallback:
    """Tests for get_task_callback (coordinator trail)."""

    def test_task_callback_logs_to_coordinator(
        self,
        creator_keys: KeyPair,
        agent_keys: KeyPair,
        tmp_storage_dir: str,
    ):
        """Task callback logs a DECISION entry to the coordinator trail."""
        crew_mw = AgentCertCrewMiddleware(
            creator_keys=creator_keys,
            crew_name="task-crew",
            agents={"researcher": {"keys": agent_keys}},
            storage_dir=tmp_storage_dir,
        )

        task_cb = crew_mw.get_task_callback()
        task_output = FakeTaskOutput(
            description="Research AI trust frameworks",
            name="research-task",
            raw="AI trust frameworks include...",
            agent="researcher",
        )

        task_cb(task_output)

        coord_entries = crew_mw._coordinator_middleware.trail.entries
        assert len(coord_entries) == 1
        assert coord_entries[0].action_type == ActionType.DECISION
        assert "researcher" in coord_entries[0].action_summary
        assert "Research AI trust" in coord_entries[0].action_summary

    def test_task_callback_does_not_log_to_agent(
        self,
        creator_keys: KeyPair,
        agent_keys: KeyPair,
        tmp_storage_dir: str,
    ):
        """Task callback only writes to coordinator trail, not agent trail."""
        crew_mw = AgentCertCrewMiddleware(
            creator_keys=creator_keys,
            crew_name="task-crew",
            agents={"researcher": {"keys": agent_keys}},
            storage_dir=tmp_storage_dir,
        )

        task_cb = crew_mw.get_task_callback()
        task_cb(FakeTaskOutput(
            description="Test", name="test", raw="output", agent="researcher"
        ))

        # Agent trail should still be empty
        assert len(crew_mw.get_agent_middleware("researcher").trail.entries) == 0
        # Coordinator trail should have 1 entry
        assert len(crew_mw._coordinator_middleware.trail.entries) == 1

    def test_task_callback_non_interference(
        self,
        creator_keys: KeyPair,
        agent_keys: KeyPair,
        tmp_storage_dir: str,
    ):
        """Task callback catches errors and doesn't raise."""
        crew_mw = AgentCertCrewMiddleware(
            creator_keys=creator_keys,
            crew_name="crew",
            agents={"agent": {"keys": agent_keys}},
            storage_dir=tmp_storage_dir,
        )

        task_cb = crew_mw.get_task_callback()
        # Pass unexpected object — should not raise
        task_cb("not a TaskOutput")
        task_cb(None)

    def test_multiple_tasks_logged_to_coordinator(
        self,
        creator_keys: KeyPair,
        agent_keys: KeyPair,
        second_agent_keys: KeyPair,
        tmp_storage_dir: str,
    ):
        """Multiple task completions are sequentially logged to coordinator."""
        crew_mw = AgentCertCrewMiddleware(
            creator_keys=creator_keys,
            crew_name="multi-task-crew",
            agents={
                "researcher": {"keys": agent_keys},
                "writer": {"keys": second_agent_keys},
            },
            storage_dir=tmp_storage_dir,
        )

        task_cb = crew_mw.get_task_callback()

        task_cb(FakeTaskOutput(
            description="Research task", name="t1", raw="research output",
            agent="researcher",
        ))
        task_cb(FakeTaskOutput(
            description="Write task", name="t2", raw="writing output",
            agent="writer",
        ))

        coord_entries = crew_mw._coordinator_middleware.trail.entries
        assert len(coord_entries) == 2
        assert "researcher" in coord_entries[0].action_summary
        assert "writer" in coord_entries[1].action_summary


class TestTwoTierObservation:
    """Tests for combined agent-level and crew-level observation."""

    def test_both_tiers_populated(
        self,
        creator_keys: KeyPair,
        agent_keys: KeyPair,
        tmp_storage_dir: str,
    ):
        """Agent-level steps and crew-level tasks both logged."""
        crew_mw = AgentCertCrewMiddleware(
            creator_keys=creator_keys,
            crew_name="two-tier-crew",
            agents={"researcher": {"keys": agent_keys}},
            storage_dir=tmp_storage_dir,
        )

        # Agent-level: step callback
        step_cb = crew_mw.get_step_callback("researcher")
        step_cb(FakeAgentAction(
            thought="Searching", tool="search", tool_input="{}", text=""
        ))
        step_cb(FakeAgentFinish(
            thought="Done", output="Result", text=""
        ))

        # Crew-level: task callback
        task_cb = crew_mw.get_task_callback()
        task_cb(FakeTaskOutput(
            description="Research task", name="t1", raw="output",
            agent="researcher",
        ))

        # Agent trail has 2 entries
        agent_trail = crew_mw.get_agent_middleware("researcher").trail
        assert len(agent_trail.entries) == 2

        # Coordinator trail has 1 entry
        coord_trail = crew_mw._coordinator_middleware.trail
        assert len(coord_trail.entries) == 1


class TestVerifyAll:
    """Tests for verify_all method."""

    def test_returns_all_results(
        self,
        creator_keys: KeyPair,
        agent_keys: KeyPair,
        second_agent_keys: KeyPair,
        tmp_storage_dir: str,
    ):
        """verify_all returns results for all agents + coordinator."""
        crew_mw = AgentCertCrewMiddleware(
            creator_keys=creator_keys,
            crew_name="verify-crew",
            agents={
                "agent-a": {"keys": agent_keys},
                "agent-b": {"keys": second_agent_keys},
            },
            storage_dir=tmp_storage_dir,
        )

        # Add entries so trails are non-empty (verify needs at least 1)
        crew_mw.get_step_callback("agent-a")(
            FakeAgentAction(thought="", tool="t", tool_input="{}", text="")
        )
        crew_mw.get_step_callback("agent-b")(
            FakeAgentAction(thought="", tool="t", tool_input="{}", text="")
        )
        crew_mw.get_task_callback()(
            FakeTaskOutput(description="d", name="n", raw="r", agent="a")
        )

        results = crew_mw.verify_all()

        assert "agent-a" in results
        assert "agent-b" in results
        assert "coordinator" in results
        assert results["agent-a"].valid is True
        assert results["agent-b"].valid is True
        assert results["coordinator"].valid is True


class TestSave:
    """Tests for save method."""

    def test_saves_all_trails(
        self,
        creator_keys: KeyPair,
        agent_keys: KeyPair,
        second_agent_keys: KeyPair,
        tmp_storage_dir: str,
    ):
        """save() persists all agent trails + coordinator trail."""
        crew_mw = AgentCertCrewMiddleware(
            creator_keys=creator_keys,
            crew_name="save-crew",
            agents={
                "researcher": {"keys": agent_keys},
                "writer": {"keys": second_agent_keys},
            },
            storage_dir=tmp_storage_dir,
        )

        # Add some entries
        crew_mw.get_step_callback("researcher")(
            FakeAgentAction(thought="", tool="t", tool_input="{}", text="")
        )
        crew_mw.get_task_callback()(
            FakeTaskOutput(description="d", name="n", raw="r", agent="a")
        )

        crew_mw.save()

        # All trails should be persisted
        base = Path(tmp_storage_dir)
        assert (base / "researcher" / "trail.json").exists()
        assert (base / "researcher" / "cert.json").exists()
        assert (base / "writer" / "trail.json").exists()
        assert (base / "writer" / "cert.json").exists()
        assert (base / "save-crew-coordinator" / "trail.json").exists()
        assert (base / "save-crew-coordinator" / "cert.json").exists()


class TestGetVerifyTool:
    """Tests for get_verify_tool from crew middleware."""

    def test_returns_tool_for_agent(
        self,
        creator_keys: KeyPair,
        agent_keys: KeyPair,
        tmp_storage_dir: str,
    ):
        """get_verify_tool returns an AgentCertVerifyTool for the agent."""
        crew_mw = AgentCertCrewMiddleware(
            creator_keys=creator_keys,
            crew_name="tool-crew",
            agents={"researcher": {"keys": agent_keys}},
            storage_dir=tmp_storage_dir,
        )

        tool = crew_mw.get_verify_tool("researcher")
        assert isinstance(tool, AgentCertVerifyTool)

    def test_unknown_agent_raises(
        self,
        creator_keys: KeyPair,
        agent_keys: KeyPair,
        tmp_storage_dir: str,
    ):
        """get_verify_tool raises ValueError for unknown agent."""
        crew_mw = AgentCertCrewMiddleware(
            creator_keys=creator_keys,
            crew_name="crew",
            agents={"agent": {"keys": agent_keys}},
            storage_dir=tmp_storage_dir,
        )

        with pytest.raises(ValueError, match="Unknown agent"):
            crew_mw.get_verify_tool("nonexistent")


class TestCrewName:
    """Tests for crew_name property."""

    def test_crew_name_property(
        self,
        creator_keys: KeyPair,
        agent_keys: KeyPair,
        tmp_storage_dir: str,
    ):
        """crew_name property returns the configured name."""
        crew_mw = AgentCertCrewMiddleware(
            creator_keys=creator_keys,
            crew_name="my-crew",
            agents={"agent": {"keys": agent_keys}},
            storage_dir=tmp_storage_dir,
        )
        assert crew_mw.crew_name == "my-crew"
