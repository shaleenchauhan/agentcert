"""Tests for agentcert-langchain — handler, middleware, tool, and shim."""

import json
from pathlib import Path
from uuid import uuid4

import pytest

import agentcert
from agentcert.types import ActionType, AuditEntry, AuditTrailVerificationResult
from agentcert.exceptions import AuditError

from agentcert_langchain import (
    AgentCertCallbackHandler,
    AgentCertLangChainMiddleware,
    AgentCertVerifyTool,
    MINIMAL,
    STANDARD,
    VERBOSE,
    _sha256_hash,
    _extract_model_name,
    _extract_tool_name,
)

from conftest import (
    MockAgentAction,
    MockAgentFinish,
    MockExecutor,
    MockLLMResult,
    MockNoCallbacks,
)


# ═══════════════════════════════════════════════════════════════════════════
# Middleware — Construction
# ═══════════════════════════════════════════════════════════════════════════


class TestMiddlewareInit:
    def test_creates_cert_and_trail(self, creator_keys, agent_keys):
        mw = AgentCertLangChainMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test-agent",
        )
        assert mw.get_certificate().agent_metadata.name == "test-agent"
        assert mw.get_certificate().agent_metadata.platform == "langchain"
        assert mw.get_trail().entries == []

    def test_custom_metadata(self, creator_keys, agent_keys):
        mw = AgentCertLangChainMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
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

    def test_with_existing_certificate(
        self, creator_keys, agent_keys, certificate
    ):
        mw = AgentCertLangChainMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="ignored",
            certificate=certificate,
        )
        assert mw.get_certificate().cert_id == certificate.cert_id

    def test_storage_modes(self, creator_keys, agent_keys):
        mw = AgentCertLangChainMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="storage-test",
            storage="local",
        )
        assert mw._storage_mode == "local"


# ═══════════════════════════════════════════════════════════════════════════
# Middleware — Handler via middleware mode
# ═══════════════════════════════════════════════════════════════════════════


class TestMiddlewareHandler:
    def test_get_handler_returns_handler(self, creator_keys, agent_keys):
        mw = AgentCertLangChainMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test",
        )
        handler = mw.get_handler()
        assert isinstance(handler, AgentCertCallbackHandler)

    def test_get_handler_returns_same_instance(self, creator_keys, agent_keys):
        mw = AgentCertLangChainMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test",
        )
        assert mw.get_handler() is mw.get_handler()

    def test_handler_llm_creates_entry(self, creator_keys, agent_keys):
        mw = AgentCertLangChainMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test",
        )
        h = mw.get_handler()
        rid = uuid4()
        h.on_llm_start(
            {"kwargs": {"model_name": "gpt-4o"}}, ["Hello"], run_id=rid,
        )
        h.on_llm_end(MockLLMResult(), run_id=rid)

        entries = mw.get_entries()
        assert len(entries) == 1
        assert entries[0].action_type == ActionType.API_CALL
        assert entries[0].action_summary == "LLM call: gpt-4o"

    def test_handler_tool_creates_entry(self, creator_keys, agent_keys):
        mw = AgentCertLangChainMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test",
        )
        h = mw.get_handler()
        rid = uuid4()
        h.on_tool_start({"name": "calculator"}, "2+2", run_id=rid)
        h.on_tool_end("4", run_id=rid)

        entries = mw.get_entries()
        assert len(entries) == 1
        assert entries[0].action_type == ActionType.TOOL_USE
        assert entries[0].action_detail["tool"] == "calculator"


# ═══════════════════════════════════════════════════════════════════════════
# Middleware — Log levels
# ═══════════════════════════════════════════════════════════════════════════


class TestMiddlewareLogLevels:
    def test_minimal_skips_llm(self, creator_keys, agent_keys):
        mw = AgentCertLangChainMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test",
            log_level=MINIMAL,
        )
        h = mw.get_handler()
        rid = uuid4()
        h.on_llm_start({"name": "m"}, ["hi"], run_id=rid)
        h.on_llm_end(MockLLMResult(), run_id=rid)
        assert len(mw.get_entries()) == 0

    def test_minimal_logs_tools(self, creator_keys, agent_keys):
        mw = AgentCertLangChainMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test",
            log_level=MINIMAL,
        )
        h = mw.get_handler()
        rid = uuid4()
        h.on_tool_start({"name": "t"}, "in", run_id=rid)
        h.on_tool_end("out", run_id=rid)
        assert len(mw.get_entries()) == 1

    def test_verbose_logs_chains(self, creator_keys, agent_keys):
        mw = AgentCertLangChainMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test",
            log_level=VERBOSE,
        )
        h = mw.get_handler()
        rid = uuid4()
        h.on_chain_start({"name": "AgentExecutor"}, {"input": "q"}, run_id=rid)
        h.on_chain_end({"output": "a"}, run_id=rid)
        assert len(mw.get_entries()) == 1

    def test_standard_skips_chains(self, creator_keys, agent_keys):
        mw = AgentCertLangChainMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test",
            log_level=STANDARD,
        )
        h = mw.get_handler()
        rid = uuid4()
        h.on_chain_start({"name": "AgentExecutor"}, {"input": "q"}, run_id=rid)
        h.on_chain_end({"output": "a"}, run_id=rid)
        assert len(mw.get_entries()) == 0


# ═══════════════════════════════════════════════════════════════════════════
# Middleware — Storage modes
# ═══════════════════════════════════════════════════════════════════════════


class TestMiddlewareStorage:
    def test_local_save(self, creator_keys, agent_keys, tmp_path):
        mw = AgentCertLangChainMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="save-test",
            storage="local",
        )
        h = mw.get_handler()
        rid = uuid4()
        h.on_tool_start({"name": "t"}, "in", run_id=rid)
        h.on_tool_end("out", run_id=rid)

        outdir = tmp_path / "saved"
        mw.save(outdir)
        assert (outdir / "certificate.json").exists()
        assert (outdir / "trail.json").exists()

    def test_auto_save(self, creator_keys, agent_keys, tmp_path):
        mw = AgentCertLangChainMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="auto-test",
            storage="local",
            storage_dir=str(tmp_path / "audit"),
            auto_save=True,
            auto_save_interval=1,
        )
        h = mw.get_handler()
        rid = uuid4()
        h.on_tool_start({"name": "t"}, "in", run_id=rid)
        h.on_tool_end("out", run_id=rid)

        # auto_save should have persisted via storage backend
        trail_path = tmp_path / "audit" / "auto-test" / "trail.json"
        assert trail_path.exists()


# ═══════════════════════════════════════════════════════════════════════════
# Middleware — Verify
# ═══════════════════════════════════════════════════════════════════════════


class TestMiddlewareVerify:
    def test_verify_valid(self, creator_keys, agent_keys):
        mw = AgentCertLangChainMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test",
        )
        h = mw.get_handler()
        rid = uuid4()
        h.on_tool_start({"name": "t"}, "in", run_id=rid)
        h.on_tool_end("out", run_id=rid)

        result = mw.verify()
        assert isinstance(result, AuditTrailVerificationResult)
        assert result.valid
        assert result.status == "VALID"


# ═══════════════════════════════════════════════════════════════════════════
# Middleware — Wrap
# ═══════════════════════════════════════════════════════════════════════════


class TestMiddlewareWrap:
    def test_wrap_adds_callback(self, creator_keys, agent_keys):
        mw = AgentCertLangChainMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test",
        )
        executor = MockExecutor(callbacks=[])
        result = mw.wrap(executor)

        assert result is executor
        assert len(executor.callbacks) == 1
        assert isinstance(executor.callbacks[0], AgentCertCallbackHandler)

    def test_wrap_initializes_none_callbacks(self, creator_keys, agent_keys):
        mw = AgentCertLangChainMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test",
        )
        executor = MockExecutor(callbacks=None)
        mw.wrap(executor)
        assert executor.callbacks is not None
        assert len(executor.callbacks) == 1

    def test_wrap_rejects_no_callbacks_attr(self, creator_keys, agent_keys):
        mw = AgentCertLangChainMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test",
        )
        with pytest.raises(AuditError, match="no 'callbacks' attribute"):
            mw.wrap(MockNoCallbacks())


# ═══════════════════════════════════════════════════════════════════════════
# Middleware — Save / Load roundtrip
# ═══════════════════════════════════════════════════════════════════════════


class TestMiddlewareSaveLoad:
    def test_save_creates_files(self, creator_keys, agent_keys, tmp_path):
        mw = AgentCertLangChainMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="save-test",
        )
        outdir = tmp_path / "saved"
        mw.save(outdir)
        assert (outdir / "certificate.json").exists()
        assert (outdir / "trail.json").exists()

    def test_load_roundtrip(self, creator_keys, agent_keys, tmp_path):
        mw = AgentCertLangChainMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="roundtrip",
        )
        h = mw.get_handler()
        rid = uuid4()
        h.on_tool_start({"name": "search"}, "query", run_id=rid)
        h.on_tool_end("results", run_id=rid)
        h.on_agent_finish(MockAgentFinish(), run_id=uuid4())

        outdir = tmp_path / "saved"
        mw.save(outdir)

        loaded = AgentCertLangChainMiddleware.load(outdir, agent_keys)
        assert loaded.get_certificate().cert_id == mw.get_certificate().cert_id
        assert loaded.get_trail().trail_id == mw.get_trail().trail_id
        assert len(loaded.get_entries()) == 2

    def test_load_and_verify(self, creator_keys, agent_keys, tmp_path):
        mw = AgentCertLangChainMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="verify-load",
        )
        h = mw.get_handler()
        rid = uuid4()
        h.on_tool_start({"name": "t"}, "in", run_id=rid)
        h.on_tool_end("out", run_id=rid)

        outdir = tmp_path / "saved"
        mw.save(outdir)

        loaded = AgentCertLangChainMiddleware.load(outdir, agent_keys)
        assert loaded.verify().valid

    def test_load_and_continue_logging(
        self, creator_keys, agent_keys, tmp_path
    ):
        mw = AgentCertLangChainMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="continue",
        )
        h = mw.get_handler()
        rid = uuid4()
        h.on_tool_start({"name": "t1"}, "in", run_id=rid)
        h.on_tool_end("out", run_id=rid)

        outdir = tmp_path / "saved"
        mw.save(outdir)

        loaded = AgentCertLangChainMiddleware.load(outdir, agent_keys)
        lh = loaded.get_handler()
        rid2 = uuid4()
        lh.on_tool_start({"name": "t2"}, "in2", run_id=rid2)
        lh.on_tool_end("out2", run_id=rid2)

        assert len(loaded.get_entries()) == 2
        assert loaded.get_entries()[1].action_detail["tool"] == "t2"
        assert loaded.verify().valid

    def test_load_nonexistent_raises(self, agent_keys, tmp_path):
        with pytest.raises(AuditError, match="Failed to load"):
            AgentCertLangChainMiddleware.load(
                tmp_path / "nonexistent", agent_keys
            )


# ═══════════════════════════════════════════════════════════════════════════
# AgentCertVerifyTool
# ═══════════════════════════════════════════════════════════════════════════


class TestVerifyTool:
    def test_verify_from_file(
        self,
        creator_keys,
        agent_keys,
        peer_certificate,
        tmp_path,
    ):
        mw = AgentCertLangChainMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="verifier",
        )
        tool = mw.get_verify_tool()
        assert isinstance(tool, AgentCertVerifyTool)
        assert tool.name == "verify_agent_certificate"

        # Save peer cert to file
        cert_path = tmp_path / "peer_cert.json"
        agentcert.save_certificate(peer_certificate, cert_path)

        # Verify
        result = tool._run(str(cert_path))
        assert "VALID" in result
        assert "peer-agent" in result

        # Check that a DECISION entry was logged
        entries = mw.get_entries(action_type=ActionType.DECISION)
        assert len(entries) == 1
        assert "Verified agent" in entries[0].action_summary

    def test_verify_from_json_string(
        self,
        creator_keys,
        agent_keys,
        peer_certificate,
    ):
        mw = AgentCertLangChainMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="verifier",
        )
        tool = mw.get_verify_tool()

        cert_json = json.dumps(peer_certificate.to_dict())
        result = tool._run(cert_json)
        assert "VALID" in result
        assert "peer-agent" in result

    def test_verify_logs_decision_entry(
        self,
        creator_keys,
        agent_keys,
        peer_certificate,
    ):
        mw = AgentCertLangChainMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="verifier",
        )
        tool = mw.get_verify_tool()
        cert_json = json.dumps(peer_certificate.to_dict())
        tool._run(cert_json)

        entries = mw.get_entries(action_type=ActionType.DECISION)
        assert len(entries) == 1
        detail = entries[0].action_detail
        assert detail["peer_cert_id"] == peer_certificate.cert_id
        assert detail["valid"] is True
        assert detail["signature_valid"] is True


# ═══════════════════════════════════════════════════════════════════════════
# Backward-compat shim
# ═══════════════════════════════════════════════════════════════════════════


class TestBackwardCompatShim:
    def test_import_middleware_from_shim(self):
        from agentcert.integrations.langchain import AgentCertMiddleware

        assert AgentCertMiddleware is AgentCertLangChainMiddleware

    def test_import_handler_from_shim(self):
        from agentcert.integrations.langchain import AgentCertCallbackHandler as H

        assert H is AgentCertCallbackHandler

    def test_import_constants_from_shim(self):
        from agentcert.integrations.langchain import MINIMAL as M
        from agentcert.integrations.langchain import STANDARD as S
        from agentcert.integrations.langchain import VERBOSE as V

        assert M == "minimal"
        assert S == "standard"
        assert V == "verbose"

    def test_import_helpers_from_shim(self):
        from agentcert.integrations.langchain import (
            _sha256_hash as h,
            _extract_model_name as m,
            _extract_tool_name as t,
        )

        assert h("hello") == _sha256_hash("hello")
        assert m({"name": "foo"}) == "foo"
        assert t({"name": "bar"}) == "bar"

    def test_shim_middleware_works(self, creator_keys, agent_keys):
        from agentcert.integrations.langchain import AgentCertMiddleware

        mw = AgentCertMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="shim-test",
        )
        h = mw.get_handler()
        rid = uuid4()
        h.on_tool_start({"name": "t"}, "in", run_id=rid)
        h.on_tool_end("out", run_id=rid)
        assert len(mw.get_entries()) == 1
        assert mw.verify().valid


# ═══════════════════════════════════════════════════════════════════════════
# Handler — Legacy mode (direct trail + agent_keys)
# ═══════════════════════════════════════════════════════════════════════════


class TestHandlerLegacyMode:
    def test_legacy_init(self, certificate, agent_keys):
        from agentcert.audit import create_audit_trail

        trail = create_audit_trail(certificate, agent_keys, timestamp=1000)
        handler = AgentCertCallbackHandler(trail, agent_keys)
        assert handler.trail is trail
        assert handler.entries == []

    def test_legacy_tool_event(self, certificate, agent_keys):
        from agentcert.audit import create_audit_trail

        trail = create_audit_trail(certificate, agent_keys, timestamp=1000)
        handler = AgentCertCallbackHandler(trail, agent_keys)
        rid = uuid4()
        handler.on_tool_start({"name": "calc"}, "2+2", run_id=rid)
        handler.on_tool_end("4", run_id=rid)

        assert len(handler.entries) == 1
        assert handler.entries[0].action_type == ActionType.TOOL_USE

    def test_legacy_llm_event(self, certificate, agent_keys):
        from agentcert.audit import create_audit_trail

        trail = create_audit_trail(certificate, agent_keys, timestamp=1000)
        handler = AgentCertCallbackHandler(trail, agent_keys)
        rid = uuid4()
        handler.on_llm_start({"name": "m"}, ["hi"], run_id=rid)
        handler.on_llm_end(MockLLMResult(), run_id=rid)

        assert len(handler.entries) == 1
        assert handler.entries[0].action_type == ActionType.API_CALL

    def test_invalid_log_level(self, certificate, agent_keys):
        from agentcert.audit import create_audit_trail

        trail = create_audit_trail(certificate, agent_keys, timestamp=1000)
        with pytest.raises(ValueError, match="Invalid log_level"):
            AgentCertCallbackHandler(trail, agent_keys, log_level="invalid")

    def test_invalid_init_no_args(self):
        with pytest.raises(ValueError, match="Either middleware"):
            AgentCertCallbackHandler()


# ═══════════════════════════════════════════════════════════════════════════
# Full lifecycle
# ═══════════════════════════════════════════════════════════════════════════


class TestFullLifecycle:
    def test_full_lifecycle(self, creator_keys, agent_keys):
        mw = AgentCertLangChainMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="lifecycle-agent",
            capabilities=["search", "compute"],
            risk_tier=2,
        )

        executor = MockExecutor()
        mw.wrap(executor)
        handler = executor.callbacks[0]

        # Simulate an agent run
        rid1 = uuid4()
        handler.on_llm_start(
            {"kwargs": {"model_name": "gpt-4o"}},
            ["Find suppliers"],
            run_id=rid1,
        )
        handler.on_llm_end(MockLLMResult("I'll search"), run_id=rid1)

        handler.on_agent_action(
            MockAgentAction(tool="search", log="Searching"),
            run_id=uuid4(),
        )

        rid2 = uuid4()
        handler.on_tool_start({"name": "search"}, "suppliers", run_id=rid2)
        handler.on_tool_end("Acme Corp, Widgets Inc", run_id=rid2)

        handler.on_agent_finish(
            MockAgentFinish(return_values={"output": "Acme Corp"}),
            run_id=uuid4(),
        )

        entries = mw.get_entries()
        assert len(entries) == 4

        tools = mw.get_entries(action_type=ActionType.TOOL_USE)
        assert len(tools) == 1

        llm_calls = mw.get_entries(action_type=ActionType.API_CALL)
        assert len(llm_calls) == 1

        decisions = mw.get_entries(action_type=ActionType.DECISION)
        assert len(decisions) == 2

        result = mw.verify()
        assert result.valid
        assert result.entry_count == 4
