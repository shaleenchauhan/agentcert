"""Tests for agentcert.integrations.langchain — callback handler and middleware."""

import json
from uuid import uuid4

import pytest

from agentcert.keys import generate_keys
from agentcert.certificate import create_certificate
from agentcert.audit import AuditTrail, create_audit_trail
from agentcert.types import ActionType, AuditEntry, AuditTrailVerificationResult
from agentcert.exceptions import AuditError
from agentcert.integrations.langchain import (
    AgentCertCallbackHandler,
    AgentCertMiddleware,
    MINIMAL,
    STANDARD,
    VERBOSE,
    _sha256_hash,
    _extract_model_name,
    _extract_tool_name,
)


# ── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture
def creator():
    return generate_keys()


@pytest.fixture
def agent():
    return generate_keys()


@pytest.fixture
def cert(creator, agent):
    return create_certificate(
        creator_keys=creator, agent_keys=agent,
        name="lc-test", platform="langchain", model_hash="sha256:test",
        capabilities=["search"], constraints=["none"],
        risk_tier=1, expires_days=30,
    )


@pytest.fixture
def trail(cert, agent):
    return create_audit_trail(cert, agent, timestamp=1000)


@pytest.fixture
def handler(trail, agent):
    return AgentCertCallbackHandler(trail, agent)


@pytest.fixture
def handler_minimal(trail, agent):
    return AgentCertCallbackHandler(trail, agent, log_level=MINIMAL)


@pytest.fixture
def handler_verbose(trail, agent):
    return AgentCertCallbackHandler(trail, agent, log_level=VERBOSE)


# ── Mock objects ────────────────────────────────────────────────────────────


class MockAgentAction:
    def __init__(self, tool="web_search", tool_input=None, log=""):
        self.tool = tool
        self.tool_input = tool_input or {"query": "test"}
        self.log = log


class MockAgentFinish:
    def __init__(self, return_values=None, log=""):
        self.return_values = return_values or {"output": "done"}
        self.log = log


class MockGeneration:
    def __init__(self, text="response text"):
        self.text = text


class MockLLMResult:
    def __init__(self, text="response text"):
        self.generations = [[MockGeneration(text)]]


class MockExecutor:
    """Mock LangChain AgentExecutor with callbacks attribute."""
    def __init__(self, callbacks=None):
        self.callbacks = callbacks


class MockNoCallbacks:
    """Object with no callbacks attribute."""
    pass


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════


class TestHelpers:
    def test_sha256_hash(self):
        h = _sha256_hash("hello")
        assert len(h) == 64
        assert h == _sha256_hash("hello")
        assert h != _sha256_hash("world")

    def test_extract_model_name_from_kwargs(self):
        s = {"kwargs": {"model_name": "gpt-4o"}}
        assert _extract_model_name(s) == "gpt-4o"

    def test_extract_model_name_from_model_key(self):
        s = {"kwargs": {"model": "claude-3"}}
        assert _extract_model_name(s) == "claude-3"

    def test_extract_model_name_from_name(self):
        s = {"name": "ChatOpenAI"}
        assert _extract_model_name(s) == "ChatOpenAI"

    def test_extract_model_name_from_id(self):
        s = {"id": ["langchain", "llms", "openai", "ChatOpenAI"]}
        assert _extract_model_name(s) == "ChatOpenAI"

    def test_extract_model_name_unknown(self):
        assert _extract_model_name({}) == "unknown"

    def test_extract_tool_name_from_name(self):
        assert _extract_tool_name({"name": "calculator"}) == "calculator"

    def test_extract_tool_name_from_id(self):
        s = {"id": ["langchain", "tools", "calculator"]}
        assert _extract_tool_name(s) == "calculator"

    def test_extract_tool_name_unknown(self):
        assert _extract_tool_name({}) == "unknown"


# ═══════════════════════════════════════════════════════════════════════════
# AgentCertCallbackHandler — Construction
# ═══════════════════════════════════════════════════════════════════════════


class TestCallbackHandlerInit:
    def test_creates_handler(self, handler):
        assert isinstance(handler, AgentCertCallbackHandler)

    def test_trail_property(self, handler, trail):
        assert handler.trail is trail

    def test_entries_property_empty(self, handler):
        assert handler.entries == []

    def test_invalid_log_level(self, trail, agent):
        with pytest.raises(ValueError, match="Invalid log_level"):
            AgentCertCallbackHandler(trail, agent, log_level="invalid")

    def test_all_log_levels_accepted(self, trail, agent):
        for level in (MINIMAL, STANDARD, VERBOSE):
            h = AgentCertCallbackHandler(trail, agent, log_level=level)
            assert h._log_level == level


# ═══════════════════════════════════════════════════════════════════════════
# AgentCertCallbackHandler — Tool events
# ═══════════════════════════════════════════════════════════════════════════


class TestToolEvents:
    def test_tool_start_end_creates_entry(self, handler):
        rid = uuid4()
        handler.on_tool_start({"name": "calculator"}, "2+2", run_id=rid)
        handler.on_tool_end("4", run_id=rid)

        assert len(handler.entries) == 1
        entry = handler.entries[0]
        assert entry.action_type == ActionType.TOOL_USE
        assert entry.action_summary == "Tool call: calculator"
        assert entry.action_detail["tool"] == "calculator"
        assert entry.action_detail["input"] == "2+2"
        assert "output_hash" in entry.action_detail
        assert "duration_ms" in entry.action_detail

    def test_tool_end_without_start_ignored(self, handler):
        handler.on_tool_end("output", run_id=uuid4())
        assert len(handler.entries) == 0

    def test_tool_name_from_id_list(self, handler):
        rid = uuid4()
        handler.on_tool_start(
            {"id": ["langchain", "tools", "web_search"]}, "query", run_id=rid,
        )
        handler.on_tool_end("results", run_id=rid)
        assert handler.entries[0].action_detail["tool"] == "web_search"

    def test_tool_error_creates_error_entry(self, handler):
        rid = uuid4()
        handler.on_tool_start({"name": "api_tool"}, "input", run_id=rid)
        handler.on_tool_error(ConnectionError("timeout"), run_id=rid)

        assert len(handler.entries) == 1
        entry = handler.entries[0]
        assert entry.action_type == ActionType.ERROR
        assert "Tool error" in entry.action_summary
        assert entry.action_detail["error_type"] == "ConnectionError"
        assert entry.action_detail["tool"] == "api_tool"

    def test_tool_error_without_start(self, handler):
        handler.on_tool_error(ValueError("bad"), run_id=uuid4())
        assert len(handler.entries) == 1
        assert handler.entries[0].action_detail["tool"] == "unknown"

    def test_multiple_tools_tracked_by_run_id(self, handler):
        rid1, rid2 = uuid4(), uuid4()
        handler.on_tool_start({"name": "search"}, "q1", run_id=rid1)
        handler.on_tool_start({"name": "calc"}, "2+2", run_id=rid2)
        handler.on_tool_end("4", run_id=rid2)
        handler.on_tool_end("results", run_id=rid1)

        assert len(handler.entries) == 2
        assert handler.entries[0].action_detail["tool"] == "calc"
        assert handler.entries[1].action_detail["tool"] == "search"

    def test_tool_output_is_hashed(self, handler):
        rid = uuid4()
        handler.on_tool_start({"name": "t"}, "in", run_id=rid)
        handler.on_tool_end("sensitive output data", run_id=rid)

        output_hash = handler.entries[0].action_detail["output_hash"]
        assert output_hash == _sha256_hash("sensitive output data")

    def test_tool_logged_in_minimal_mode(self, handler_minimal):
        rid = uuid4()
        handler_minimal.on_tool_start({"name": "t"}, "in", run_id=rid)
        handler_minimal.on_tool_end("out", run_id=rid)
        assert len(handler_minimal.entries) == 1


# ═══════════════════════════════════════════════════════════════════════════
# AgentCertCallbackHandler — LLM events
# ═══════════════════════════════════════════════════════════════════════════


class TestLLMEvents:
    def test_llm_start_end_creates_entry(self, handler):
        rid = uuid4()
        handler.on_llm_start(
            {"kwargs": {"model_name": "gpt-4o"}}, ["Hello"], run_id=rid,
        )
        handler.on_llm_end(MockLLMResult(), run_id=rid)

        assert len(handler.entries) == 1
        entry = handler.entries[0]
        assert entry.action_type == ActionType.API_CALL
        assert entry.action_summary == "LLM call: gpt-4o"
        assert entry.action_detail["model"] == "gpt-4o"
        assert "prompt_hash" in entry.action_detail
        assert "output_hash" in entry.action_detail
        assert "duration_ms" in entry.action_detail

    def test_llm_end_without_start_ignored(self, handler):
        handler.on_llm_end(MockLLMResult(), run_id=uuid4())
        assert len(handler.entries) == 0

    def test_llm_prompt_is_hashed(self, handler):
        rid = uuid4()
        handler.on_llm_start({"name": "m"}, ["secret prompt"], run_id=rid)
        handler.on_llm_end(MockLLMResult(), run_id=rid)

        prompt_hash = handler.entries[0].action_detail["prompt_hash"]
        assert prompt_hash == _sha256_hash("secret prompt")

    def test_llm_response_is_hashed(self, handler):
        rid = uuid4()
        handler.on_llm_start({"name": "m"}, ["hi"], run_id=rid)
        handler.on_llm_end(MockLLMResult("secret response"), run_id=rid)

        output_hash = handler.entries[0].action_detail["output_hash"]
        assert output_hash == _sha256_hash("secret response")

    def test_llm_error_creates_error_entry(self, handler):
        rid = uuid4()
        handler.on_llm_start(
            {"kwargs": {"model_name": "gpt-4o"}}, ["hi"], run_id=rid,
        )
        handler.on_llm_error(RuntimeError("rate limit"), run_id=rid)

        assert len(handler.entries) == 1
        entry = handler.entries[0]
        assert entry.action_type == ActionType.ERROR
        assert "LLM error" in entry.action_summary
        assert entry.action_detail["model"] == "gpt-4o"
        assert entry.action_detail["error_type"] == "RuntimeError"

    def test_llm_error_without_start(self, handler):
        handler.on_llm_error(ValueError("bad"), run_id=uuid4())
        assert len(handler.entries) == 1
        assert handler.entries[0].action_detail["model"] == "unknown"

    def test_llm_skipped_in_minimal_mode(self, handler_minimal):
        rid = uuid4()
        handler_minimal.on_llm_start({"name": "m"}, ["hi"], run_id=rid)
        handler_minimal.on_llm_end(MockLLMResult(), run_id=rid)
        assert len(handler_minimal.entries) == 0

    def test_chat_model_start_end(self, handler):
        rid = uuid4()
        handler.on_chat_model_start(
            {"kwargs": {"model_name": "claude-3"}},
            [[{"role": "user", "content": "hello"}]],
            run_id=rid,
        )
        handler.on_llm_end(MockLLMResult(), run_id=rid)

        assert len(handler.entries) == 1
        assert handler.entries[0].action_summary == "LLM call: claude-3"

    def test_chat_model_skipped_in_minimal(self, handler_minimal):
        rid = uuid4()
        handler_minimal.on_chat_model_start({"name": "m"}, [[]], run_id=rid)
        handler_minimal.on_llm_end(MockLLMResult(), run_id=rid)
        assert len(handler_minimal.entries) == 0

    def test_llm_end_fallback_for_non_standard_response(self, handler):
        rid = uuid4()
        handler.on_llm_start({"name": "m"}, ["hi"], run_id=rid)
        handler.on_llm_end("plain string response", run_id=rid)

        assert len(handler.entries) == 1
        assert handler.entries[0].action_detail["output_hash"] == _sha256_hash(
            "plain string response"
        )


# ═══════════════════════════════════════════════════════════════════════════
# AgentCertCallbackHandler — Agent events
# ═══════════════════════════════════════════════════════════════════════════


class TestAgentEvents:
    def test_agent_action(self, handler):
        action = MockAgentAction(tool="search", log="Thought: searching")
        handler.on_agent_action(action, run_id=uuid4())

        assert len(handler.entries) == 1
        entry = handler.entries[0]
        assert entry.action_type == ActionType.DECISION
        assert entry.action_summary == "Agent action: search"
        assert entry.action_detail["tool"] == "search"

    def test_agent_finish(self, handler):
        finish = MockAgentFinish(return_values={"output": "42"}, log="Final")
        handler.on_agent_finish(finish, run_id=uuid4())

        assert len(handler.entries) == 1
        entry = handler.entries[0]
        assert entry.action_type == ActionType.DECISION
        assert entry.action_summary == "Agent finished"
        assert "output_hash" in entry.action_detail

    def test_agent_action_logged_in_minimal(self, handler_minimal):
        handler_minimal.on_agent_action(MockAgentAction(), run_id=uuid4())
        assert len(handler_minimal.entries) == 1

    def test_agent_finish_logged_in_minimal(self, handler_minimal):
        handler_minimal.on_agent_finish(MockAgentFinish(), run_id=uuid4())
        assert len(handler_minimal.entries) == 1


# ═══════════════════════════════════════════════════════════════════════════
# AgentCertCallbackHandler — Chain events
# ═══════════════════════════════════════════════════════════════════════════


class TestChainEvents:
    def test_chain_ignored_in_standard(self, handler):
        rid = uuid4()
        handler.on_chain_start({"name": "AgentExecutor"}, {"input": "q"}, run_id=rid)
        handler.on_chain_end({"output": "a"}, run_id=rid)
        assert len(handler.entries) == 0

    def test_chain_ignored_in_minimal(self, handler_minimal):
        rid = uuid4()
        handler_minimal.on_chain_start(
            {"name": "AgentExecutor"}, {"input": "q"}, run_id=rid,
        )
        handler_minimal.on_chain_end({"output": "a"}, run_id=rid)
        assert len(handler_minimal.entries) == 0

    def test_chain_logged_in_verbose(self, handler_verbose):
        rid = uuid4()
        handler_verbose.on_chain_start(
            {"name": "AgentExecutor"}, {"input": "q"}, run_id=rid,
        )
        handler_verbose.on_chain_end({"output": "a"}, run_id=rid)
        assert len(handler_verbose.entries) == 1
        assert handler_verbose.entries[0].action_summary == "Chain: AgentExecutor"

    def test_nested_chain_ignored_in_verbose(self, handler_verbose):
        parent_rid = uuid4()
        child_rid = uuid4()
        handler_verbose.on_chain_start(
            {"name": "outer"}, {}, run_id=parent_rid,
        )
        handler_verbose.on_chain_start(
            {"name": "inner"}, {}, run_id=child_rid, parent_run_id=parent_rid,
        )
        handler_verbose.on_chain_end({}, run_id=child_rid, parent_run_id=parent_rid)
        handler_verbose.on_chain_end({}, run_id=parent_rid)

        assert len(handler_verbose.entries) == 1
        assert handler_verbose.entries[0].action_summary == "Chain: outer"

    def test_chain_error_in_verbose(self, handler_verbose):
        rid = uuid4()
        handler_verbose.on_chain_start(
            {"name": "FailChain"}, {}, run_id=rid,
        )
        handler_verbose.on_chain_error(RuntimeError("boom"), run_id=rid)

        assert len(handler_verbose.entries) == 1
        entry = handler_verbose.entries[0]
        assert entry.action_type == ActionType.ERROR
        assert "Chain error" in entry.action_summary

    def test_chain_error_ignored_in_standard(self, handler):
        rid = uuid4()
        handler.on_chain_start({"name": "C"}, {}, run_id=rid)
        handler.on_chain_error(RuntimeError("boom"), run_id=rid)
        assert len(handler.entries) == 0

    def test_chain_name_from_id_list(self, handler_verbose):
        rid = uuid4()
        handler_verbose.on_chain_start(
            {"id": ["langchain", "chains", "RetrievalQA"]}, {}, run_id=rid,
        )
        handler_verbose.on_chain_end({}, run_id=rid)
        assert handler_verbose.entries[0].action_detail["chain"] == "RetrievalQA"


# ═══════════════════════════════════════════════════════════════════════════
# AgentCertCallbackHandler — Trail verification
# ═══════════════════════════════════════════════════════════════════════════


class TestCallbackTrailVerification:
    def test_entries_form_valid_trail(self, handler, cert):
        # Simulate a realistic sequence
        rid1 = uuid4()
        handler.on_llm_start({"name": "gpt-4o"}, ["plan"], run_id=rid1)
        handler.on_llm_end(MockLLMResult("use search"), run_id=rid1)

        handler.on_agent_action(
            MockAgentAction(tool="search", log="I should search"), run_id=uuid4(),
        )

        rid2 = uuid4()
        handler.on_tool_start({"name": "search"}, "query", run_id=rid2)
        handler.on_tool_end("result data", run_id=rid2)

        handler.on_agent_finish(MockAgentFinish(), run_id=uuid4())

        from agentcert.audit_verify import verify_audit_trail

        result = verify_audit_trail(handler.trail, cert)
        assert result.valid
        assert result.entry_count == 4

    def test_chain_is_intact(self, handler):
        for i in range(5):
            rid = uuid4()
            handler.on_tool_start({"name": f"tool_{i}"}, f"input_{i}", run_id=rid)
            handler.on_tool_end(f"output_{i}", run_id=rid)

        entries = handler.entries
        assert entries[0].previous_entry_id is None
        for i in range(1, len(entries)):
            assert entries[i].previous_entry_id == entries[i - 1].entry_id


# ═══════════════════════════════════════════════════════════════════════════
# AgentCertMiddleware — Construction
# ═══════════════════════════════════════════════════════════════════════════


class TestMiddlewareInit:
    def test_creates_cert_and_trail(self, creator, agent):
        mw = AgentCertMiddleware(
            creator_keys=creator, agent_keys=agent,
            agent_name="test-agent",
        )
        assert mw.get_certificate().agent_metadata.name == "test-agent"
        assert mw.get_certificate().agent_metadata.platform == "langchain"
        assert mw.get_trail().entries == []

    def test_custom_metadata(self, creator, agent):
        mw = AgentCertMiddleware(
            creator_keys=creator, agent_keys=agent,
            agent_name="custom",
            platform="crewai",
            model_hash="sha256:abc",
            capabilities=["a", "b"],
            constraints=["c"],
            risk_tier=3,
            expires_days=7,
        )
        meta = mw.get_certificate().agent_metadata
        assert meta.platform == "crewai"
        assert meta.model_hash == "sha256:abc"
        assert meta.capabilities == ("a", "b")
        assert meta.constraints == ("c",)
        assert meta.risk_tier == 3

    def test_with_existing_certificate(self, creator, agent, cert):
        mw = AgentCertMiddleware(
            creator_keys=creator, agent_keys=agent,
            agent_name="ignored",
            certificate=cert,
        )
        assert mw.get_certificate().cert_id == cert.cert_id

    def test_keys_from_file(self, creator, agent, tmp_path):
        from agentcert.keys import save_keys

        save_keys(creator, tmp_path / "creator.json")
        save_keys(agent, tmp_path / "agent.json")

        mw = AgentCertMiddleware(
            creator_keys=str(tmp_path / "creator.json"),
            agent_keys=str(tmp_path / "agent.json"),
            agent_name="from-files",
        )
        assert mw.get_certificate().agent_metadata.name == "from-files"


# ═══════════════════════════════════════════════════════════════════════════
# AgentCertMiddleware — wrap()
# ═══════════════════════════════════════════════════════════════════════════


class TestMiddlewareWrap:
    def test_wrap_adds_callback(self, creator, agent):
        mw = AgentCertMiddleware(
            creator_keys=creator, agent_keys=agent, agent_name="test",
        )
        executor = MockExecutor(callbacks=[])
        result = mw.wrap(executor)

        assert result is executor
        assert len(executor.callbacks) == 1
        assert isinstance(executor.callbacks[0], AgentCertCallbackHandler)

    def test_wrap_initializes_none_callbacks(self, creator, agent):
        mw = AgentCertMiddleware(
            creator_keys=creator, agent_keys=agent, agent_name="test",
        )
        executor = MockExecutor(callbacks=None)
        mw.wrap(executor)

        assert executor.callbacks is not None
        assert len(executor.callbacks) == 1

    def test_wrap_preserves_existing_callbacks(self, creator, agent):
        mw = AgentCertMiddleware(
            creator_keys=creator, agent_keys=agent, agent_name="test",
        )
        existing = object()
        executor = MockExecutor(callbacks=[existing])
        mw.wrap(executor)

        assert len(executor.callbacks) == 2
        assert executor.callbacks[0] is existing

    def test_wrap_rejects_no_callbacks_attr(self, creator, agent):
        mw = AgentCertMiddleware(
            creator_keys=creator, agent_keys=agent, agent_name="test",
        )
        with pytest.raises(AuditError, match="no 'callbacks' attribute"):
            mw.wrap(MockNoCallbacks())


# ═══════════════════════════════════════════════════════════════════════════
# AgentCertMiddleware — Accessors
# ═══════════════════════════════════════════════════════════════════════════


class TestMiddlewareAccessors:
    def test_get_entries_empty(self, creator, agent):
        mw = AgentCertMiddleware(
            creator_keys=creator, agent_keys=agent, agent_name="test",
        )
        assert mw.get_entries() == []

    def test_get_entries_after_events(self, creator, agent):
        mw = AgentCertMiddleware(
            creator_keys=creator, agent_keys=agent, agent_name="test",
        )
        h = mw.get_handler()
        rid = uuid4()
        h.on_tool_start({"name": "t"}, "in", run_id=rid)
        h.on_tool_end("out", run_id=rid)

        entries = mw.get_entries()
        assert len(entries) == 1
        assert entries[0].action_type == ActionType.TOOL_USE

    def test_get_entries_filtered(self, creator, agent):
        mw = AgentCertMiddleware(
            creator_keys=creator, agent_keys=agent, agent_name="test",
        )
        h = mw.get_handler()

        rid = uuid4()
        h.on_tool_start({"name": "t"}, "in", run_id=rid)
        h.on_tool_end("out", run_id=rid)
        h.on_agent_action(MockAgentAction(), run_id=uuid4())

        tools = mw.get_entries(action_type=ActionType.TOOL_USE)
        assert len(tools) == 1
        decisions = mw.get_entries(action_type=ActionType.DECISION)
        assert len(decisions) == 1

    def test_verify_valid(self, creator, agent):
        mw = AgentCertMiddleware(
            creator_keys=creator, agent_keys=agent, agent_name="test",
        )
        h = mw.get_handler()
        rid = uuid4()
        h.on_tool_start({"name": "t"}, "in", run_id=rid)
        h.on_tool_end("out", run_id=rid)

        result = mw.verify()
        assert isinstance(result, AuditTrailVerificationResult)
        assert result.valid
        assert result.status == "VALID"

    def test_get_handler_returns_same_instance(self, creator, agent):
        mw = AgentCertMiddleware(
            creator_keys=creator, agent_keys=agent, agent_name="test",
        )
        assert mw.get_handler() is mw.get_handler()


# ═══════════════════════════════════════════════════════════════════════════
# AgentCertMiddleware — Save / Load
# ═══════════════════════════════════════════════════════════════════════════


class TestMiddlewareSaveLoad:
    def test_save_creates_files(self, creator, agent, tmp_path):
        mw = AgentCertMiddleware(
            creator_keys=creator, agent_keys=agent, agent_name="save-test",
        )
        h = mw.get_handler()
        rid = uuid4()
        h.on_tool_start({"name": "t"}, "in", run_id=rid)
        h.on_tool_end("out", run_id=rid)

        outdir = tmp_path / "saved"
        mw.save(outdir)

        assert (outdir / "certificate.json").exists()
        assert (outdir / "trail.json").exists()

    def test_saved_files_are_valid_json(self, creator, agent, tmp_path):
        mw = AgentCertMiddleware(
            creator_keys=creator, agent_keys=agent, agent_name="json-test",
        )
        outdir = tmp_path / "saved"
        mw.save(outdir)

        cert_data = json.loads((outdir / "certificate.json").read_text())
        assert cert_data["agent_metadata"]["name"] == "json-test"
        trail_data = json.loads((outdir / "trail.json").read_text())
        assert "trail_id" in trail_data

    def test_load_roundtrip(self, creator, agent, tmp_path):
        mw = AgentCertMiddleware(
            creator_keys=creator, agent_keys=agent, agent_name="roundtrip",
        )
        h = mw.get_handler()
        rid = uuid4()
        h.on_tool_start({"name": "search"}, "query", run_id=rid)
        h.on_tool_end("results", run_id=rid)
        h.on_agent_finish(MockAgentFinish(), run_id=uuid4())

        outdir = tmp_path / "saved"
        mw.save(outdir)

        loaded = AgentCertMiddleware.load(outdir, agent)
        assert loaded.get_certificate().cert_id == mw.get_certificate().cert_id
        assert loaded.get_trail().trail_id == mw.get_trail().trail_id
        assert len(loaded.get_entries()) == 2

    def test_load_and_verify(self, creator, agent, tmp_path):
        mw = AgentCertMiddleware(
            creator_keys=creator, agent_keys=agent, agent_name="verify-load",
        )
        h = mw.get_handler()
        rid = uuid4()
        h.on_tool_start({"name": "t"}, "in", run_id=rid)
        h.on_tool_end("out", run_id=rid)

        outdir = tmp_path / "saved"
        mw.save(outdir)

        loaded = AgentCertMiddleware.load(outdir, agent)
        result = loaded.verify()
        assert result.valid

    def test_load_and_continue_logging(self, creator, agent, tmp_path):
        mw = AgentCertMiddleware(
            creator_keys=creator, agent_keys=agent, agent_name="continue",
        )
        h = mw.get_handler()
        rid = uuid4()
        h.on_tool_start({"name": "t1"}, "in", run_id=rid)
        h.on_tool_end("out", run_id=rid)

        outdir = tmp_path / "saved"
        mw.save(outdir)

        loaded = AgentCertMiddleware.load(outdir, agent)
        lh = loaded.get_handler()
        rid2 = uuid4()
        lh.on_tool_start({"name": "t2"}, "in2", run_id=rid2)
        lh.on_tool_end("out2", run_id=rid2)

        assert len(loaded.get_entries()) == 2
        assert loaded.get_entries()[1].action_detail["tool"] == "t2"
        assert loaded.verify().valid

    def test_load_keys_from_file(self, creator, agent, tmp_path):
        from agentcert.keys import save_keys

        mw = AgentCertMiddleware(
            creator_keys=creator, agent_keys=agent, agent_name="key-file",
        )
        outdir = tmp_path / "saved"
        mw.save(outdir)
        save_keys(agent, tmp_path / "agent.json")

        loaded = AgentCertMiddleware.load(outdir, str(tmp_path / "agent.json"))
        assert loaded.get_certificate().cert_id == mw.get_certificate().cert_id

    def test_load_nonexistent_raises(self, agent, tmp_path):
        with pytest.raises(AuditError, match="Failed to load"):
            AgentCertMiddleware.load(tmp_path / "nonexistent", agent)

    def test_save_creates_nested_dirs(self, creator, agent, tmp_path):
        mw = AgentCertMiddleware(
            creator_keys=creator, agent_keys=agent, agent_name="nested",
        )
        outdir = tmp_path / "a" / "b" / "c"
        mw.save(outdir)
        assert (outdir / "certificate.json").exists()


# ═══════════════════════════════════════════════════════════════════════════
# AgentCertMiddleware — Full lifecycle
# ═══════════════════════════════════════════════════════════════════════════


class TestMiddlewareLifecycle:
    def test_full_lifecycle(self, creator, agent):
        """Simulate: create middleware → wrap executor → run events → verify → save."""
        mw = AgentCertMiddleware(
            creator_keys=creator, agent_keys=agent,
            agent_name="lifecycle-agent",
            capabilities=["search", "compute"],
            risk_tier=2,
        )

        # Wrap
        executor = MockExecutor()
        mw.wrap(executor)
        handler = executor.callbacks[0]

        # Simulate an agent run
        rid1 = uuid4()
        handler.on_llm_start(
            {"kwargs": {"model_name": "gpt-4o"}}, ["Find suppliers"], run_id=rid1,
        )
        handler.on_llm_end(MockLLMResult("I'll search"), run_id=rid1)

        handler.on_agent_action(
            MockAgentAction(tool="search", log="Searching"), run_id=uuid4(),
        )

        rid2 = uuid4()
        handler.on_tool_start({"name": "search"}, "suppliers", run_id=rid2)
        handler.on_tool_end("Acme Corp, Widgets Inc", run_id=rid2)

        rid3 = uuid4()
        handler.on_llm_start(
            {"kwargs": {"model_name": "gpt-4o"}}, ["Analyze results"], run_id=rid3,
        )
        handler.on_llm_end(MockLLMResult("Acme is cheapest"), run_id=rid3)

        handler.on_agent_finish(
            MockAgentFinish(return_values={"output": "Acme Corp"}), run_id=uuid4(),
        )

        # Check results
        entries = mw.get_entries()
        assert len(entries) == 5

        tools = mw.get_entries(action_type=ActionType.TOOL_USE)
        assert len(tools) == 1

        llm_calls = mw.get_entries(action_type=ActionType.API_CALL)
        assert len(llm_calls) == 2

        decisions = mw.get_entries(action_type=ActionType.DECISION)
        assert len(decisions) == 2

        # Verify
        result = mw.verify()
        assert result.valid
        assert result.entry_count == 5
