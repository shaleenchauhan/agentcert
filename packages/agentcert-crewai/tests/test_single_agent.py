"""Tests for AgentCertCrewAIMiddleware (single-agent)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

import agentcert
from agentcert.types import ActionType, KeyPair

from agentcert_crewai.middleware import AgentCertCrewAIMiddleware
from agentcert_crewai.tool import AgentCertVerifyTool

from conftest import FakeAgentAction, FakeAgentFinish, FakeToolResult


class TestMiddlewareInit:
    """Tests for AgentCertCrewAIMiddleware initialization."""

    def test_creates_certificate(
        self, creator_keys: KeyPair, agent_keys: KeyPair
    ):
        """Init creates a valid certificate with platform='crewai'."""
        mw = AgentCertCrewAIMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test-agent",
        )
        assert mw.certificate is not None
        assert mw.certificate.agent_metadata.platform == "crewai"
        assert mw.certificate.agent_metadata.name == "test-agent"

    def test_creates_empty_trail(
        self, creator_keys: KeyPair, agent_keys: KeyPair
    ):
        """Init creates an empty audit trail."""
        mw = AgentCertCrewAIMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test-agent",
        )
        assert mw.trail is not None
        assert len(mw.trail.entries) == 0

    def test_agent_name(self, creator_keys: KeyPair, agent_keys: KeyPair):
        """agent_name property returns the configured name."""
        mw = AgentCertCrewAIMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="my-agent",
        )
        assert mw.agent_name == "my-agent"

    def test_capabilities_in_cert(
        self, creator_keys: KeyPair, agent_keys: KeyPair
    ):
        """Capabilities are set on the certificate."""
        mw = AgentCertCrewAIMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="cap-agent",
            capabilities=["web_search", "analysis"],
            risk_tier=2,
        )
        assert "web_search" in mw.certificate.agent_metadata.capabilities
        assert mw.certificate.agent_metadata.risk_tier == 2

    def test_storage_modes(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str
    ):
        """Middleware accepts different storage modes."""
        mw = AgentCertCrewAIMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test-agent",
            storage="local",
            storage_dir=tmp_storage_dir,
        )
        assert mw._storage_mode == "local"


class TestStepCallbackToolUse:
    """Tests for step_callback with tool invocations (AgentAction)."""

    def test_agent_action_creates_tool_use_entry(
        self, creator_keys: KeyPair, agent_keys: KeyPair
    ):
        """AgentAction step → TOOL_USE entry."""
        mw = AgentCertCrewAIMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test-agent",
        )
        action = FakeAgentAction(
            thought="I need to search for AI trust frameworks",
            tool="web_search",
            tool_input='{"query": "AI trust frameworks"}',
            text="Thought: ... Action: web_search",
        )

        mw.step_callback(action)

        assert len(mw.trail.entries) == 1
        entry = mw.trail.entries[0]
        assert entry.action_type == ActionType.TOOL_USE
        assert "web_search" in entry.action_summary

    def test_agent_action_detail_has_tool_name(
        self, creator_keys: KeyPair, agent_keys: KeyPair
    ):
        """AgentAction detail dict includes tool name and input hash."""
        mw = AgentCertCrewAIMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test-agent",
        )
        action = FakeAgentAction(
            thought="Searching",
            tool="calculator",
            tool_input='{"expression": "2+2"}',
            text="Action: calculator",
        )

        mw.step_callback(action)

        entry = mw.trail.entries[0]
        assert entry.action_detail["tool"] == "calculator"
        assert "input_hash" in entry.action_detail

    def test_tool_result_creates_tool_use_entry(
        self, creator_keys: KeyPair, agent_keys: KeyPair
    ):
        """ToolResult step → TOOL_USE entry."""
        mw = AgentCertCrewAIMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test-agent",
        )
        result = FakeToolResult(result="The answer is 42")

        mw.step_callback(result)

        assert len(mw.trail.entries) == 1
        entry = mw.trail.entries[0]
        assert entry.action_type == ActionType.TOOL_USE
        assert "result" in entry.action_summary.lower()


class TestStepCallbackDecision:
    """Tests for step_callback with LLM reasoning (AgentFinish)."""

    def test_agent_finish_creates_decision_entry(
        self, creator_keys: KeyPair, agent_keys: KeyPair
    ):
        """AgentFinish step → DECISION entry."""
        mw = AgentCertCrewAIMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test-agent",
        )
        finish = FakeAgentFinish(
            thought="Based on my research, AI trust frameworks include...",
            output="AI trust frameworks summary: ...",
            text="Final Answer: ...",
        )

        mw.step_callback(finish)

        assert len(mw.trail.entries) == 1
        entry = mw.trail.entries[0]
        assert entry.action_type == ActionType.DECISION
        assert "finished" in entry.action_summary.lower()

    def test_agent_finish_detail_has_output_hash(
        self, creator_keys: KeyPair, agent_keys: KeyPair
    ):
        """AgentFinish detail dict includes output hash."""
        mw = AgentCertCrewAIMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test-agent",
        )
        finish = FakeAgentFinish(
            thought="Concluding",
            output="Final report on AI trust",
            text="Final Answer: ...",
        )

        mw.step_callback(finish)

        entry = mw.trail.entries[0]
        assert "output_hash" in entry.action_detail


class TestStepCallbackNonInterference:
    """Tests for non-interference principle in step_callback."""

    def test_callback_does_not_raise(
        self, creator_keys: KeyPair, agent_keys: KeyPair
    ):
        """step_callback never raises, even with unexpected input."""
        mw = AgentCertCrewAIMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test-agent",
        )

        # Pass completely unexpected type — should not raise
        mw.step_callback("unexpected string")
        mw.step_callback(42)
        mw.step_callback(None)

    def test_callback_survives_storage_failure(
        self, creator_keys: KeyPair, agent_keys: KeyPair
    ):
        """step_callback continues even when storage fails."""
        mw = AgentCertCrewAIMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test-agent",
            auto_save=True,
            auto_save_interval=1,
        )
        mw._storage = MagicMock()
        mw._storage.persist_entry.side_effect = IOError("disk full")

        action = FakeAgentAction(
            thought="Test", tool="test_tool", tool_input="{}", text="Test"
        )
        mw.step_callback(action)

        # Entry is still in the trail (in-memory)
        assert len(mw.trail.entries) == 1


class TestStepCallbackMultipleSteps:
    """Tests for multiple sequential steps."""

    def test_multiple_steps_create_ordered_entries(
        self, creator_keys: KeyPair, agent_keys: KeyPair
    ):
        """Multiple step_callback calls create properly ordered entries."""
        mw = AgentCertCrewAIMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test-agent",
        )

        # Step 1: Tool use
        mw.step_callback(FakeAgentAction(
            thought="Need to search", tool="search", tool_input="{}", text=""
        ))
        # Step 2: Tool result
        mw.step_callback(FakeToolResult(result="Search results..."))
        # Step 3: Final answer
        mw.step_callback(FakeAgentFinish(
            thought="Done", output="Summary", text=""
        ))

        assert len(mw.trail.entries) == 3
        assert mw.trail.entries[0].action_type == ActionType.TOOL_USE
        assert mw.trail.entries[1].action_type == ActionType.TOOL_USE
        assert mw.trail.entries[2].action_type == ActionType.DECISION
        # Sequence is correct
        assert mw.trail.entries[0].sequence == 0
        assert mw.trail.entries[1].sequence == 1
        assert mw.trail.entries[2].sequence == 2

    def test_unknown_step_type_creates_custom_entry(
        self, creator_keys: KeyPair, agent_keys: KeyPair
    ):
        """Unrecognized step type → CUSTOM entry."""
        mw = AgentCertCrewAIMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test-agent",
        )

        class UnknownStep:
            pass

        mw.step_callback(UnknownStep())

        assert len(mw.trail.entries) == 1
        assert mw.trail.entries[0].action_type == ActionType.CUSTOM
        assert "UnknownStep" in mw.trail.entries[0].action_summary


class TestVerifyAndSave:
    """Tests for verify and save methods."""

    def test_verify_valid_trail(
        self, creator_keys: KeyPair, agent_keys: KeyPair
    ):
        """verify() returns valid for a well-formed trail."""
        mw = AgentCertCrewAIMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test-agent",
        )
        mw.step_callback(FakeAgentAction(
            thought="Test", tool="test", tool_input="{}", text=""
        ))
        result = mw.verify()
        assert result.valid is True

    def test_save_creates_files(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str
    ):
        """save() writes trail and cert to disk."""
        mw = AgentCertCrewAIMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test-agent",
            storage="local",
            storage_dir=tmp_storage_dir,
        )
        mw.step_callback(FakeAgentAction(
            thought="Test", tool="test", tool_input="{}", text=""
        ))
        mw.save()

        agent_dir = Path(tmp_storage_dir) / "test-agent"
        assert (agent_dir / "trail.json").exists()
        assert (agent_dir / "cert.json").exists()


class TestGetVerifyTool:
    """Tests for get_verify_tool method."""

    def test_returns_verify_tool(
        self, creator_keys: KeyPair, agent_keys: KeyPair
    ):
        """get_verify_tool() returns an AgentCertVerifyTool."""
        mw = AgentCertCrewAIMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test-agent",
        )
        tool = mw.get_verify_tool()
        assert isinstance(tool, AgentCertVerifyTool)
        assert tool.name == "verify_agent_certificate"

    def test_verify_tool_with_valid_cert(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_path
    ):
        """Verify tool returns TRUSTED for a valid certificate file."""
        mw = AgentCertCrewAIMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test-agent",
        )
        tool = mw.get_verify_tool()

        # Create a peer cert file
        peer_keys = agentcert.generate_keys()
        peer_cert = agentcert.create_certificate(
            creator_keys=creator_keys,
            agent_keys=peer_keys,
            name="peer",
            platform="test",
            model_hash="sha256:peer",
            capabilities=[],
            constraints=[],
            risk_tier=1,
            expires_days=90,
        )
        cert_path = str(tmp_path / "peer_cert.json")
        agentcert.save_certificate(peer_cert, cert_path)

        result = tool._run(cert_path=cert_path)
        assert "TRUSTED" in result
        # Verify tool logged a DECISION
        assert len(mw.trail.entries) == 1
        assert mw.trail.entries[0].action_type == ActionType.DECISION

    def test_verify_tool_missing_file(
        self, creator_keys: KeyPair, agent_keys: KeyPair
    ):
        """Verify tool returns error for missing cert file."""
        mw = AgentCertCrewAIMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test-agent",
        )
        tool = mw.get_verify_tool()
        result = tool._run(cert_path="/nonexistent/cert.json")
        assert "Error" in result
