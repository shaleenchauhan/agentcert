"""Tests for the AgentCert SDK client.

Uses httpx mock transport — no real server needed.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import patch

import httpx
import pytest

from agentcert.client import AgentCertClient
from agentcert.exceptions import ClientError
from agentcert.keys import generate_keys
from agentcert.certificate import create_certificate
from agentcert.audit import AuditTrail, create_audit_trail, log_action
from agentcert.types import ActionType, AuditEntry, MerkleProof


# ── Helpers ─────────────────────────────────────────────────────────────────


def _mock_transport(handler):
    """Create an httpx MockTransport from a handler function."""
    return httpx.MockTransport(handler)


def _json_response(data: dict, status_code: int = 200) -> httpx.Response:
    """Create an httpx Response with JSON content."""
    return httpx.Response(
        status_code=status_code,
        json=data,
    )


# ── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture()
def cert_and_keys():
    creator_keys = generate_keys()
    agent_keys = generate_keys()
    cert = create_certificate(
        creator_keys=creator_keys, agent_keys=agent_keys,
        name="client-test-agent", platform="test",
        model_hash="sha256:test", capabilities=["search"],
        constraints=["read-only"], risk_tier=1, expires_days=90,
    )
    return cert, creator_keys, agent_keys


@pytest.fixture()
def trail_with_entries(cert_and_keys):
    cert, creator_keys, agent_keys = cert_and_keys
    trail = create_audit_trail(cert, agent_keys)
    for i in range(3):
        log_action(trail, agent_keys,
                   action_type=ActionType.TOOL_USE,
                   action_summary=f"Client test action {i}")
    return trail, cert, creator_keys, agent_keys


# ═══════════════════════════════════════════════════════════════════════════════
# Client Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestRegisterCertificate:
    def test_register_success(self, cert_and_keys):
        cert, _, _ = cert_and_keys

        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response({"cert_id": cert.cert_id, "status": "registered"})

        transport = _mock_transport(handler)
        client = AgentCertClient.__new__(AgentCertClient)
        client._base = "http://test"
        client._client = httpx.Client(transport=transport, base_url="http://test")

        result = client.register_certificate(cert)
        assert result["cert_id"] == cert.cert_id
        assert result["status"] == "registered"
        client.close()

    def test_register_conflict(self, cert_and_keys):
        cert, _, _ = cert_and_keys

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                status_code=409,
                json={"detail": "Already registered"},
            )

        transport = _mock_transport(handler)
        client = AgentCertClient.__new__(AgentCertClient)
        client._base = "http://test"
        client._client = httpx.Client(transport=transport, base_url="http://test")

        with pytest.raises(ClientError, match="409"):
            client.register_certificate(cert)
        client.close()


class TestSubmitEntries:
    def test_submit_entries_success(self, trail_with_entries):
        trail, _, _, _ = trail_with_entries
        entry_ids = [e.entry_id for e in trail.entries]

        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response({
                "accepted": 3, "rejected": 0, "errors": [],
                "entry_ids": entry_ids,
            })

        transport = _mock_transport(handler)
        client = AgentCertClient.__new__(AgentCertClient)
        client._base = "http://test"
        client._client = httpx.Client(transport=transport, base_url="http://test")

        result = client.submit_entries(trail.entries)
        assert result["accepted"] == 3
        assert len(result["entry_ids"]) == 3
        client.close()

    def test_submit_trail(self, trail_with_entries):
        trail, _, _, _ = trail_with_entries

        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            return _json_response({
                "accepted": len(body["entries"]),
                "rejected": 0, "errors": [],
                "entry_ids": [e["entry_id"] for e in body["entries"]],
            })

        transport = _mock_transport(handler)
        client = AgentCertClient.__new__(AgentCertClient)
        client._base = "http://test"
        client._client = httpx.Client(transport=transport, base_url="http://test")

        result = client.submit_trail(trail)
        assert result["accepted"] == 3
        client.close()


class TestGetProof:
    def test_get_proof_pending(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response({
                "entry_id": "abc123",
                "status": "pending",
                "message": "Entry received but not yet included in a batch",
            })

        transport = _mock_transport(handler)
        client = AgentCertClient.__new__(AgentCertClient)
        client._base = "http://test"
        client._client = httpx.Client(transport=transport, base_url="http://test")

        result = client.get_proof("abc123")
        assert result is None
        client.close()

    def test_get_proof_available(self):
        proof_data = {
            "leaf_hash": "aa" * 32,
            "leaf_index": 0,
            "siblings": ["bb" * 32],
            "directions": ["right"],
            "root": "cc" * 32,
        }

        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response({
                "entry_id": "aa" * 32,
                "batch_id": "dd" * 32,
                "merkle_root": "cc" * 32,
                "proof": proof_data,
                "anchor": None,
            })

        transport = _mock_transport(handler)
        client = AgentCertClient.__new__(AgentCertClient)
        client._base = "http://test"
        client._client = httpx.Client(transport=transport, base_url="http://test")

        result = client.get_proof("aa" * 32)
        assert isinstance(result, MerkleProof)
        assert result.leaf_hash == "aa" * 32
        client.close()

    def test_get_proof_raw(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response({"entry_id": "abc", "status": "pending"})

        transport = _mock_transport(handler)
        client = AgentCertClient.__new__(AgentCertClient)
        client._base = "http://test"
        client._client = httpx.Client(transport=transport, base_url="http://test")

        result = client.get_proof_raw("abc")
        assert result["status"] == "pending"
        client.close()


class TestVerifyEntry:
    def test_verify_entry(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response({
                "entry_id": "abc",
                "status": "VALID",
                "checks": {
                    "entry_integrity": True,
                    "agent_signature": True,
                    "cert_binding": True,
                    "merkle_proof": True,
                    "anchor_on_chain": True,
                },
            })

        transport = _mock_transport(handler)
        client = AgentCertClient.__new__(AgentCertClient)
        client._base = "http://test"
        client._client = httpx.Client(transport=transport, base_url="http://test")

        result = client.verify_entry("abc")
        assert result["status"] == "VALID"
        assert result["checks"]["merkle_proof"] is True
        client.close()


class TestGetBatch:
    def test_get_batch(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response({
                "batch_id": "bb" * 32,
                "merkle_root": "cc" * 32,
                "item_count": 5,
            })

        transport = _mock_transport(handler)
        client = AgentCertClient.__new__(AgentCertClient)
        client._base = "http://test"
        client._client = httpx.Client(transport=transport, base_url="http://test")

        result = client.get_batch("bb" * 32)
        assert result["item_count"] == 5
        client.close()

    def test_get_latest_batch(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response({"batch_id": "latest", "item_count": 10})

        transport = _mock_transport(handler)
        client = AgentCertClient.__new__(AgentCertClient)
        client._base = "http://test"
        client._client = httpx.Client(transport=transport, base_url="http://test")

        result = client.get_latest_batch()
        assert result["batch_id"] == "latest"
        client.close()


class TestForceBatch:
    def test_force_batch(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response({"status": "batched", "batch_id": "bb", "item_count": 5})

        transport = _mock_transport(handler)
        client = AgentCertClient.__new__(AgentCertClient)
        client._base = "http://test"
        client._client = httpx.Client(transport=transport, base_url="http://test")

        result = client.force_batch()
        assert result["status"] == "batched"
        client.close()


class TestHealthAndStats:
    def test_health(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response({"status": "healthy", "version": "0.3.0"})

        transport = _mock_transport(handler)
        client = AgentCertClient.__new__(AgentCertClient)
        client._base = "http://test"
        client._client = httpx.Client(transport=transport, base_url="http://test")

        result = client.health()
        assert result["status"] == "healthy"
        client.close()

    def test_stats(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response({"entries_total": 100, "batches_total": 5})

        transport = _mock_transport(handler)
        client = AgentCertClient.__new__(AgentCertClient)
        client._base = "http://test"
        client._client = httpx.Client(transport=transport, base_url="http://test")

        result = client.stats()
        assert result["entries_total"] == 100
        client.close()


class TestErrorHandling:
    def test_404_raises_client_error(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(status_code=404, json={"detail": "Not found"})

        transport = _mock_transport(handler)
        client = AgentCertClient.__new__(AgentCertClient)
        client._base = "http://test"
        client._client = httpx.Client(transport=transport, base_url="http://test")

        with pytest.raises(ClientError, match="404"):
            client.get_entry("nonexistent")
        client.close()

    def test_connection_error_raises_client_error(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("Connection refused")

        transport = _mock_transport(handler)
        client = AgentCertClient.__new__(AgentCertClient)
        client._base = "http://test"
        client._client = httpx.Client(transport=transport, base_url="http://test")

        with pytest.raises(ClientError, match="Request failed"):
            client.health()
        client.close()


class TestContextManager:
    def test_context_manager(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response({"status": "healthy"})

        transport = _mock_transport(handler)
        with AgentCertClient.__new__(AgentCertClient) as client:
            client._base = "http://test"
            client._client = httpx.Client(transport=transport, base_url="http://test")
            result = client.health()
            assert result["status"] == "healthy"


class TestGetCertificate:
    def test_get_certificate(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response({"cert_id": "abc", "agent_metadata": {}})

        transport = _mock_transport(handler)
        client = AgentCertClient.__new__(AgentCertClient)
        client._base = "http://test"
        client._client = httpx.Client(transport=transport, base_url="http://test")

        result = client.get_certificate("abc")
        assert result["cert_id"] == "abc"
        client.close()


class TestGetEntry:
    def test_get_entry(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response({"entry_id": "abc", "trail_id": "def"})

        transport = _mock_transport(handler)
        client = AgentCertClient.__new__(AgentCertClient)
        client._base = "http://test"
        client._client = httpx.Client(transport=transport, base_url="http://test")

        result = client.get_entry("abc")
        assert result["entry_id"] == "abc"
        client.close()


class TestGetTrail:
    def test_get_trail(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response({
                "trail_id": "abc", "entries": [], "entry_count": 0,
            })

        transport = _mock_transport(handler)
        client = AgentCertClient.__new__(AgentCertClient)
        client._base = "http://test"
        client._client = httpx.Client(transport=transport, base_url="http://test")

        result = client.get_trail("abc")
        assert result["trail_id"] == "abc"
        client.close()
