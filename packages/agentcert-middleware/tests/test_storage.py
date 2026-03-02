"""Tests for storage backends."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agentcert.audit import AuditTrail, create_audit_trail, log_action
from agentcert.exceptions import ClientError
from agentcert.types import ActionType

from agentcert_middleware.retry import RetryPolicy
from agentcert_middleware.storage import (
    BothStorage,
    LocalStorage,
    ServiceStorage,
    create_storage,
)


class TestLocalStorage:
    """Tests for LocalStorage backend."""

    def test_persist_trail_creates_files(
        self, tmp_storage_dir, certificate, agent_keys, trail_with_entries
    ):
        """persist_trail writes cert.json and trail.json to disk."""
        trail, entries = trail_with_entries
        storage = LocalStorage(tmp_storage_dir, "test-agent")
        storage.persist_trail(trail, certificate)

        agent_dir = Path(tmp_storage_dir) / "test-agent"
        assert (agent_dir / "trail.json").exists()
        assert (agent_dir / "cert.json").exists()

    def test_persist_trail_roundtrip(
        self, tmp_storage_dir, certificate, agent_keys, trail_with_entries
    ):
        """persist_trail + load_trail round-trips correctly."""
        trail, entries = trail_with_entries
        storage = LocalStorage(tmp_storage_dir, "test-agent")
        storage.persist_trail(trail, certificate)

        loaded_trail, loaded_cert = storage.load_trail(trail.trail_id)
        assert loaded_trail.trail_id == trail.trail_id
        assert len(loaded_trail.entries) == len(trail.entries)
        assert loaded_cert is not None
        assert loaded_cert.cert_id == certificate.cert_id

    def test_persist_entry_writes_trail(
        self, tmp_storage_dir, certificate, agent_keys, trail_with_entries
    ):
        """persist_entry writes the full trail to disk."""
        trail, entries = trail_with_entries
        storage = LocalStorage(tmp_storage_dir, "test-agent")
        storage.persist_entry(entries[0], trail, certificate)

        agent_dir = Path(tmp_storage_dir) / "test-agent"
        assert (agent_dir / "trail.json").exists()

    def test_file_structure(
        self, tmp_storage_dir, certificate, agent_keys, trail_with_entries
    ):
        """Files are created in {storage_dir}/{agent_name}/ structure."""
        trail, _ = trail_with_entries
        storage = LocalStorage(tmp_storage_dir, "my-agent")
        storage.persist_trail(trail, certificate)

        agent_dir = Path(tmp_storage_dir) / "my-agent"
        assert agent_dir.is_dir()

        cert_data = json.loads((agent_dir / "cert.json").read_text())
        assert cert_data["cert_id"] == certificate.cert_id

        trail_data = json.loads((agent_dir / "trail.json").read_text())
        assert trail_data["trail_id"] == trail.trail_id
        assert len(trail_data["entries"]) == 3

    def test_creates_directories(self, tmp_storage_dir, certificate, trail_with_entries):
        """persist_trail creates directories if they don't exist."""
        trail, _ = trail_with_entries
        deep_dir = str(Path(tmp_storage_dir) / "deep" / "nested")
        storage = LocalStorage(deep_dir, "agent")
        storage.persist_trail(trail, certificate)
        assert (Path(deep_dir) / "agent" / "trail.json").exists()


class TestServiceStorage:
    """Tests for ServiceStorage backend.

    Mocks AgentCertClient directly since it uses httpx (not requests).
    """

    def test_persist_trail_registers_cert_and_submits(
        self, certificate, agent_keys, trail_with_entries
    ):
        """persist_trail registers certificate and submits entries."""
        trail, entries = trail_with_entries
        base_url = "http://localhost:8932"

        storage = ServiceStorage(base_url)
        mock_client = MagicMock()
        mock_client.register_certificate.return_value = {
            "cert_id": certificate.cert_id,
            "status": "registered",
        }
        mock_client.submit_entries.return_value = {
            "accepted": 3, "rejected": 0, "errors": [], "entry_ids": [],
        }
        storage._client = mock_client

        storage.persist_trail(trail, certificate)

        mock_client.register_certificate.assert_called_once_with(certificate)
        mock_client.submit_entries.assert_called_once_with(trail.entries)

    def test_persist_entry_submits_single(
        self, certificate, agent_keys, trail_with_entries
    ):
        """persist_entry submits a single entry via submit_entries."""
        trail, entries = trail_with_entries
        base_url = "http://localhost:8932"

        storage = ServiceStorage(base_url)
        mock_client = MagicMock()
        mock_client.submit_entries.return_value = {
            "accepted": 1, "rejected": 0, "errors": [], "entry_ids": [],
        }
        storage._client = mock_client

        storage.persist_entry(entries[0], trail, certificate)

        mock_client.submit_entries.assert_called_once()
        submitted_entries = mock_client.submit_entries.call_args[0][0]
        assert len(submitted_entries) == 1
        assert submitted_entries[0].entry_id == entries[0].entry_id

    def test_persist_trail_skips_duplicate_cert_registration(
        self, certificate, agent_keys, trail_with_entries
    ):
        """persist_trail only registers cert once across multiple calls."""
        trail, entries = trail_with_entries
        base_url = "http://localhost:8932"

        storage = ServiceStorage(base_url)
        mock_client = MagicMock()
        mock_client.register_certificate.return_value = {
            "cert_id": certificate.cert_id,
            "status": "registered",
        }
        mock_client.submit_entries.return_value = {
            "accepted": 3, "rejected": 0, "errors": [], "entry_ids": [],
        }
        storage._client = mock_client

        storage.persist_trail(trail, certificate)
        storage.persist_trail(trail, certificate)

        # Cert registered only once, entries submitted twice
        assert mock_client.register_certificate.call_count == 1
        assert mock_client.submit_entries.call_count == 2

    def test_persist_entry_with_retry(
        self, certificate, agent_keys, trail_with_entries
    ):
        """persist_entry retries on failure when retry_policy is configured."""
        trail, entries = trail_with_entries
        base_url = "http://localhost:8932"

        retry = RetryPolicy(max_attempts=2, backoff_multiplier=0.01, max_delay=0.01)
        storage = ServiceStorage(base_url, retry_policy=retry)
        mock_client = MagicMock()
        # First call fails, second succeeds
        mock_client.submit_entries.side_effect = [
            ClientError("server error"),
            {"accepted": 1, "rejected": 0, "errors": [], "entry_ids": []},
        ]
        storage._client = mock_client

        storage.persist_entry(entries[0], trail, certificate)

        assert mock_client.submit_entries.call_count == 2

    def test_persist_trail_empty_entries(self, certificate, agent_keys):
        """persist_trail with empty trail only registers cert, no entry submission."""
        from agentcert.audit import create_audit_trail

        trail = create_audit_trail(certificate, agent_keys)
        base_url = "http://localhost:8932"

        storage = ServiceStorage(base_url)
        mock_client = MagicMock()
        mock_client.register_certificate.return_value = {
            "cert_id": certificate.cert_id,
            "status": "registered",
        }
        storage._client = mock_client

        storage.persist_trail(trail, certificate)

        mock_client.register_certificate.assert_called_once()
        mock_client.submit_entries.assert_not_called()


class TestBothStorage:
    """Tests for BothStorage backend."""

    def test_local_write_succeeds_when_service_fails(
        self, tmp_storage_dir, certificate, agent_keys, trail_with_entries
    ):
        """Local write happens even when service submission fails."""
        trail, entries = trail_with_entries
        local = LocalStorage(tmp_storage_dir, "test-agent")
        service = MagicMock(spec=ServiceStorage)
        service.persist_entry.side_effect = ConnectionError("Service down")

        both = BothStorage(local, service)
        both.persist_entry(entries[0], trail, certificate)

        # Local write should succeed
        agent_dir = Path(tmp_storage_dir) / "test-agent"
        assert (agent_dir / "trail.json").exists()

    def test_both_called_when_service_succeeds(
        self, tmp_storage_dir, certificate, agent_keys, trail_with_entries
    ):
        """Both local and service are called when service is healthy."""
        trail, entries = trail_with_entries
        local = LocalStorage(tmp_storage_dir, "test-agent")
        service = MagicMock(spec=ServiceStorage)

        both = BothStorage(local, service)
        both.persist_entry(entries[0], trail, certificate)

        # Both should be called
        agent_dir = Path(tmp_storage_dir) / "test-agent"
        assert (agent_dir / "trail.json").exists()
        service.persist_entry.assert_called_once()

    def test_persist_trail_local_and_service(
        self, tmp_storage_dir, certificate, agent_keys, trail_with_entries
    ):
        """persist_trail writes to both local and service."""
        trail, _ = trail_with_entries
        local = LocalStorage(tmp_storage_dir, "test-agent")
        service = MagicMock(spec=ServiceStorage)

        both = BothStorage(local, service)
        both.persist_trail(trail, certificate)

        agent_dir = Path(tmp_storage_dir) / "test-agent"
        assert (agent_dir / "trail.json").exists()
        assert (agent_dir / "cert.json").exists()
        service.persist_trail.assert_called_once()

    def test_persist_trail_local_succeeds_when_service_fails(
        self, tmp_storage_dir, certificate, agent_keys, trail_with_entries
    ):
        """persist_trail writes locally even when service fails."""
        trail, _ = trail_with_entries
        local = LocalStorage(tmp_storage_dir, "test-agent")
        service = MagicMock(spec=ServiceStorage)
        service.persist_trail.side_effect = ConnectionError("Service down")

        both = BothStorage(local, service)
        both.persist_trail(trail, certificate)

        agent_dir = Path(tmp_storage_dir) / "test-agent"
        assert (agent_dir / "trail.json").exists()


class TestCreateStorageFactory:
    """Tests for the create_storage factory function."""

    def test_local_mode(self, tmp_storage_dir):
        """create_storage('local') returns LocalStorage."""
        storage = create_storage(storage="local", storage_dir=tmp_storage_dir)
        assert isinstance(storage, LocalStorage)

    def test_service_mode(self):
        """create_storage('service') returns ServiceStorage."""
        storage = create_storage(
            storage="service", service_url="http://localhost:8932"
        )
        assert isinstance(storage, ServiceStorage)

    def test_both_mode(self, tmp_storage_dir):
        """create_storage('both') returns BothStorage."""
        storage = create_storage(
            storage="both",
            storage_dir=tmp_storage_dir,
            service_url="http://localhost:8932",
        )
        assert isinstance(storage, BothStorage)

    def test_service_requires_url(self):
        """create_storage('service') raises ValueError without service_url."""
        with pytest.raises(ValueError, match="service_url required"):
            create_storage(storage="service")

    def test_both_requires_url(self):
        """create_storage('both') raises ValueError without service_url."""
        with pytest.raises(ValueError, match="service_url required"):
            create_storage(storage="both")

    def test_invalid_mode(self):
        """create_storage with invalid mode raises ValueError."""
        with pytest.raises(ValueError, match="Invalid storage mode"):
            create_storage(storage="invalid")
