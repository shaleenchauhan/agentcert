"""Tests for BaseMiddleware."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import agentcert
from agentcert.types import ActionType, KeyPair

from agentcert_middleware.base import BaseMiddleware
from agentcert_middleware.storage import LocalStorage
from agentcert_middleware.trust import TrustVerifier


class TestBaseMiddlewareInit:
    """Tests for BaseMiddleware initialization."""

    def test_creates_certificate(self, creator_keys: KeyPair, agent_keys: KeyPair):
        """Init creates a valid certificate."""
        mw = BaseMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test-agent",
        )

        assert mw.certificate is not None
        assert mw.certificate.agent_metadata.name == "test-agent"
        assert mw.certificate.agent_public_key == agent_keys.public_key_hex

    def test_creates_empty_trail(self, creator_keys: KeyPair, agent_keys: KeyPair):
        """Init creates an empty audit trail bound to the certificate."""
        mw = BaseMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test-agent",
        )

        assert mw.trail is not None
        assert mw.trail.cert_id == mw.certificate.cert_id
        assert len(mw.trail.entries) == 0

    def test_creates_storage_backend(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str
    ):
        """Init creates the storage backend matching the storage mode."""
        mw = BaseMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test-agent",
            storage="local",
            storage_dir=tmp_storage_dir,
        )

        assert isinstance(mw._storage, LocalStorage)

    def test_agent_name_property(self, creator_keys: KeyPair, agent_keys: KeyPair):
        """agent_name property returns the configured name."""
        mw = BaseMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="my-agent",
        )

        assert mw.agent_name == "my-agent"

    def test_keys_from_path(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_path
    ):
        """Init accepts key paths as strings."""
        creator_path = str(tmp_path / "creator.json")
        agent_path = str(tmp_path / "agent.json")
        agentcert.save_keys(creator_keys, creator_path)
        agentcert.save_keys(agent_keys, agent_path)

        mw = BaseMiddleware(
            creator_keys=creator_path,
            agent_keys=agent_path,
            agent_name="path-agent",
        )

        assert mw.certificate.agent_public_key == agent_keys.public_key_hex
        assert mw.certificate.creator_public_key == creator_keys.public_key_hex

    def test_custom_capabilities(self, creator_keys: KeyPair, agent_keys: KeyPair):
        """Certificate includes custom capabilities and constraints."""
        mw = BaseMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="cap-agent",
            capabilities=["search", "compute"],
            constraints=["max-cost-100"],
            risk_tier=2,
        )

        assert "search" in mw.certificate.agent_metadata.capabilities
        assert "compute" in mw.certificate.agent_metadata.capabilities
        assert "max-cost-100" in mw.certificate.agent_metadata.constraints
        assert mw.certificate.agent_metadata.risk_tier == 2


class TestLogAction:
    """Tests for _log_action method."""

    def test_creates_entry(self, creator_keys: KeyPair, agent_keys: KeyPair):
        """_log_action creates an entry that appears in the trail."""
        mw = BaseMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test-agent",
        )

        entry = mw._log_action(ActionType.API_CALL, "Called API")

        assert entry is not None
        assert len(mw.trail.entries) == 1
        assert mw.trail.entries[0].action_summary == "Called API"
        assert mw.trail.entries[0].action_type == ActionType.API_CALL

    def test_correct_action_type(self, creator_keys: KeyPair, agent_keys: KeyPair):
        """_log_action records the correct ActionType."""
        mw = BaseMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test-agent",
        )

        mw._log_action(ActionType.TOOL_USE, "Used tool")
        mw._log_action(ActionType.DECISION, "Made decision")

        assert mw.trail.entries[0].action_type == ActionType.TOOL_USE
        assert mw.trail.entries[1].action_type == ActionType.DECISION

    def test_non_interference_on_storage_failure(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str
    ):
        """_log_action never raises even when storage fails."""
        mw = BaseMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test-agent",
            storage="local",
            storage_dir=tmp_storage_dir,
            auto_save=True,
            auto_save_interval=1,
        )

        # Make storage fail
        mw._storage = MagicMock()
        mw._storage.persist_entry.side_effect = IOError("disk full")

        # Should NOT raise — non-interference principle
        entry = mw._log_action(ActionType.API_CALL, "Called API")

        assert entry is not None
        assert len(mw.trail.entries) == 1

    def test_entry_still_in_trail_on_storage_failure(
        self, creator_keys: KeyPair, agent_keys: KeyPair
    ):
        """Entry is in the in-memory trail even when storage fails."""
        mw = BaseMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test-agent",
            auto_save=True,
            auto_save_interval=1,
        )

        mw._storage = MagicMock()
        mw._storage.persist_entry.side_effect = IOError("disk full")

        mw._log_action(ActionType.API_CALL, "Entry 1")
        mw._log_action(ActionType.TOOL_USE, "Entry 2")

        assert len(mw.trail.entries) == 2

    def test_action_detail(self, creator_keys: KeyPair, agent_keys: KeyPair):
        """_log_action passes action_detail correctly."""
        mw = BaseMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test-agent",
        )

        entry = mw._log_action(
            ActionType.API_CALL,
            "Called API",
            action_detail={"url": "https://example.com"},
        )

        assert entry is not None
        assert "url" in entry.action_detail
        assert entry.action_detail["url"] == "https://example.com"


class TestAutoSave:
    """Tests for auto-save functionality."""

    def test_auto_save_calls_persist_entry(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str
    ):
        """Auto-save calls persist_entry after auto_save_interval entries."""
        mw = BaseMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test-agent",
            storage="local",
            storage_dir=tmp_storage_dir,
            auto_save=True,
            auto_save_interval=2,
        )

        mock_storage = MagicMock()
        mw._storage = mock_storage

        # First entry: not yet at interval
        mw._log_action(ActionType.API_CALL, "Entry 1")
        mock_storage.persist_entry.assert_not_called()

        # Second entry: at interval, should trigger persist
        mw._log_action(ActionType.API_CALL, "Entry 2")
        mock_storage.persist_entry.assert_called_once()

    def test_auto_save_disabled_by_default(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str
    ):
        """Auto-save is disabled by default."""
        mw = BaseMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test-agent",
            storage="local",
            storage_dir=tmp_storage_dir,
        )

        mock_storage = MagicMock()
        mw._storage = mock_storage

        mw._log_action(ActionType.API_CALL, "Entry 1")
        mw._log_action(ActionType.API_CALL, "Entry 2")

        mock_storage.persist_entry.assert_not_called()


class TestVerify:
    """Tests for the verify method."""

    def test_valid_trail(self, creator_keys: KeyPair, agent_keys: KeyPair):
        """verify() returns valid for a well-formed trail."""
        mw = BaseMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test-agent",
        )

        mw._log_action(ActionType.API_CALL, "Entry 1")
        mw._log_action(ActionType.TOOL_USE, "Entry 2")

        result = mw.verify()
        assert result.valid is True
        assert result.status == "VALID"


class TestSave:
    """Tests for the save method."""

    def test_save_calls_persist_trail(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_storage_dir: str
    ):
        """save() calls storage.persist_trail."""
        mw = BaseMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test-agent",
            storage="local",
            storage_dir=tmp_storage_dir,
        )

        mw._log_action(ActionType.API_CALL, "Entry 1")
        mw.save()

        agent_dir = Path(tmp_storage_dir) / "test-agent"
        assert (agent_dir / "trail.json").exists()
        assert (agent_dir / "cert.json").exists()

    def test_save_with_directory_override(
        self, creator_keys: KeyPair, agent_keys: KeyPair, tmp_path
    ):
        """save(directory=...) overrides the storage directory."""
        mw = BaseMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test-agent",
        )

        mw._log_action(ActionType.API_CALL, "Entry 1")

        override_dir = str(tmp_path / "override")
        mw.save(directory=override_dir)

        assert (Path(override_dir) / "test-agent" / "trail.json").exists()

    def test_save_can_raise(
        self, creator_keys: KeyPair, agent_keys: KeyPair
    ):
        """save() CAN raise exceptions (unlike _log_action)."""
        mw = BaseMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test-agent",
        )

        mw._storage = MagicMock()
        mw._storage.persist_trail.side_effect = IOError("disk full")

        with pytest.raises(IOError, match="disk full"):
            mw.save()


class TestGetEntries:
    """Tests for get_entries method."""

    def test_returns_all_entries(self, creator_keys: KeyPair, agent_keys: KeyPair):
        """get_entries() returns all entries when no filter is given."""
        mw = BaseMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test-agent",
        )

        mw._log_action(ActionType.API_CALL, "Entry 1")
        mw._log_action(ActionType.TOOL_USE, "Entry 2")
        mw._log_action(ActionType.DECISION, "Entry 3")

        entries = mw.get_entries()
        assert len(entries) == 3

    def test_filters_by_action_type(
        self, creator_keys: KeyPair, agent_keys: KeyPair
    ):
        """get_entries(action_type=...) filters correctly."""
        mw = BaseMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test-agent",
        )

        mw._log_action(ActionType.API_CALL, "API 1")
        mw._log_action(ActionType.TOOL_USE, "Tool 1")
        mw._log_action(ActionType.API_CALL, "API 2")

        api_entries = mw.get_entries(action_type=ActionType.API_CALL)
        assert len(api_entries) == 2
        assert all(e.action_type == ActionType.API_CALL for e in api_entries)

        tool_entries = mw.get_entries(action_type=ActionType.TOOL_USE)
        assert len(tool_entries) == 1

    def test_empty_when_no_entries(self, creator_keys: KeyPair, agent_keys: KeyPair):
        """get_entries() returns empty list when no entries exist."""
        mw = BaseMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test-agent",
        )

        assert mw.get_entries() == []


class TestGetTrustVerifier:
    """Tests for get_trust_verifier method."""

    def test_returns_trust_verifier(
        self, creator_keys: KeyPair, agent_keys: KeyPair
    ):
        """get_trust_verifier() returns a TrustVerifier instance."""
        mw = BaseMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test-agent",
        )

        verifier = mw.get_trust_verifier()
        assert isinstance(verifier, TrustVerifier)

    def test_trust_verifier_with_service_url(
        self, creator_keys: KeyPair, agent_keys: KeyPair
    ):
        """TrustVerifier has service_url when configured."""
        mw = BaseMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="test-agent",
            service_url="http://localhost:8932",
        )

        verifier = mw.get_trust_verifier()
        assert verifier.service_url == "http://localhost:8932"


class TestLoad:
    """Tests for the load classmethod."""

    def test_load_not_implemented(
        self, creator_keys: KeyPair, agent_keys: KeyPair
    ):
        """load() raises NotImplementedError."""
        with pytest.raises(NotImplementedError, match="resume support"):
            BaseMiddleware.load("./some/dir", agent_keys)
