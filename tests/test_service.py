"""Tests for the AgentCert anchoring service endpoints.

Uses FastAPI TestClient (Starlette) — no real server needed.
"""

from __future__ import annotations

import json
import hashlib
import time

import pytest
from fastapi.testclient import TestClient

from agentcert.keys import generate_keys
from agentcert.certificate import create_certificate
from agentcert.audit import create_audit_trail, log_action
from agentcert.types import ActionType, AuditEntry
from agentcert.service.app import create_app
from agentcert.service.config import ServiceConfig


# ── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture()
def config():
    """Create an in-memory service config for testing."""
    return ServiceConfig(
        db_path=":memory:",
        batch_interval_seconds=99999,  # disable auto-batching
        batch_min_entries=1,
    )


@pytest.fixture()
def app(config):
    """Create a fresh FastAPI app with in-memory DB."""
    return create_app(config)


@pytest.fixture()
def client(app):
    """Create a TestClient for the app."""
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def cert_and_keys():
    """Create a certificate and associated keys."""
    creator_keys = generate_keys()
    agent_keys = generate_keys()
    cert = create_certificate(
        creator_keys=creator_keys,
        agent_keys=agent_keys,
        name="test-agent",
        platform="test",
        model_hash="sha256:test",
        capabilities=["search"],
        constraints=["read-only"],
        risk_tier=1,
        expires_days=90,
    )
    return cert, creator_keys, agent_keys


@pytest.fixture()
def registered_cert(client, cert_and_keys):
    """Register a certificate and return it along with keys."""
    cert, creator_keys, agent_keys = cert_and_keys
    resp = client.post(
        "/api/v1/certificates",
        json={"certificate": cert.to_dict()},
    )
    assert resp.status_code == 200
    return cert, creator_keys, agent_keys


@pytest.fixture()
def trail_with_entries(registered_cert):
    """Create a trail with 5 entries."""
    cert, creator_keys, agent_keys = registered_cert
    trail = create_audit_trail(cert, agent_keys)
    for i in range(5):
        log_action(
            trail, agent_keys,
            action_type=ActionType.TOOL_USE,
            action_summary=f"Action {i}",
        )
    return trail, cert, creator_keys, agent_keys


# ═══════════════════════════════════════════════════════════════════════════════
# Health / Stats
# ═══════════════════════════════════════════════════════════════════════════════


class TestHealth:
    def test_health(self, client):
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert "version" in data

    def test_stats_empty(self, client):
        resp = client.get("/api/v1/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["entries_total"] == 0
        assert data["batches_total"] == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Certificate Endpoints
# ═══════════════════════════════════════════════════════════════════════════════


class TestCertificates:
    def test_register_certificate(self, client, cert_and_keys):
        cert, _, _ = cert_and_keys
        resp = client.post(
            "/api/v1/certificates",
            json={"certificate": cert.to_dict()},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["cert_id"] == cert.cert_id
        assert data["status"] == "registered"

    def test_register_duplicate(self, client, cert_and_keys):
        cert, _, _ = cert_and_keys
        body = {"certificate": cert.to_dict()}
        client.post("/api/v1/certificates", json=body)
        resp = client.post("/api/v1/certificates", json=body)
        assert resp.status_code == 409

    def test_register_invalid_cert_id(self, client, cert_and_keys):
        cert, _, _ = cert_and_keys
        d = cert.to_dict()
        d["cert_id"] = "0" * 64  # tampered
        resp = client.post("/api/v1/certificates", json={"certificate": d})
        assert resp.status_code == 400

    def test_register_invalid_signature(self, client, cert_and_keys):
        cert, _, _ = cert_and_keys
        d = cert.to_dict()
        d["creator_signature"] = "00" * 64  # tampered
        # Need to recompute cert_id for the tampered body
        resp = client.post("/api/v1/certificates", json={"certificate": d})
        assert resp.status_code == 400

    def test_register_missing_certificate_field(self, client):
        resp = client.post("/api/v1/certificates", json={})
        assert resp.status_code == 400

    def test_get_certificate(self, client, registered_cert):
        cert, _, _ = registered_cert
        resp = client.get(f"/api/v1/certificates/{cert.cert_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["cert_id"] == cert.cert_id

    def test_get_certificate_not_found(self, client):
        resp = client.get("/api/v1/certificates/nonexistent")
        assert resp.status_code == 404


# ═══════════════════════════════════════════════════════════════════════════════
# Entry Endpoints
# ═══════════════════════════════════════════════════════════════════════════════


class TestEntries:
    def test_submit_entries(self, client, trail_with_entries):
        trail, cert, _, _ = trail_with_entries
        entries = [e.to_dict() for e in trail.entries]
        resp = client.post("/api/v1/entries", json={"entries": entries})
        assert resp.status_code == 200
        data = resp.json()
        assert data["accepted"] == 5
        assert data["rejected"] == 0
        assert len(data["entry_ids"]) == 5

    def test_submit_entries_duplicate(self, client, trail_with_entries):
        trail, cert, _, _ = trail_with_entries
        entries = [e.to_dict() for e in trail.entries]
        client.post("/api/v1/entries", json={"entries": entries})
        # Submit again — duplicates silently skipped
        resp = client.post("/api/v1/entries", json={"entries": entries})
        data = resp.json()
        assert data["accepted"] == 0  # all duplicates

    def test_submit_entries_invalid_signature(self, client, registered_cert):
        cert, creator_keys, agent_keys = registered_cert
        trail = create_audit_trail(cert, agent_keys)
        log_action(trail, agent_keys, action_type=ActionType.TOOL_USE,
                   action_summary="test action")
        entry_dict = trail.entries[0].to_dict()
        entry_dict["agent_signature"] = "00" * 64  # tampered
        resp = client.post("/api/v1/entries", json={"entries": [entry_dict]})
        data = resp.json()
        assert data["rejected"] == 1
        assert "signature" in data["errors"][0].lower()

    def test_submit_entries_unregistered_cert(self, client):
        # Create a cert but don't register it
        ck = generate_keys()
        ak = generate_keys()
        cert = create_certificate(
            creator_keys=ck, agent_keys=ak, name="unreg",
            platform="test", model_hash="sha256:t", capabilities=["x"],
            constraints=["y"], risk_tier=1, expires_days=30,
        )
        trail = create_audit_trail(cert, ak)
        log_action(trail, ak, action_type=ActionType.TOOL_USE,
                   action_summary="test")
        entries = [e.to_dict() for e in trail.entries]
        resp = client.post("/api/v1/entries", json={"entries": entries})
        data = resp.json()
        assert data["rejected"] == 1
        assert "not registered" in data["errors"][0]

    def test_submit_entries_wrong_agent(self, client, registered_cert):
        cert, creator_keys, agent_keys = registered_cert
        # Create trail with different agent keys
        other_ak = generate_keys()
        other_cert = create_certificate(
            creator_keys=creator_keys, agent_keys=other_ak,
            name="other", platform="test", model_hash="sha256:t",
            capabilities=["x"], constraints=["y"], risk_tier=1, expires_days=30,
        )
        trail = create_audit_trail(other_cert, other_ak)
        log_action(trail, other_ak, action_type=ActionType.TOOL_USE,
                   action_summary="test")
        # Tamper: set cert_id to the registered cert
        entry_dict = trail.entries[0].to_dict()
        entry_dict["cert_id"] = cert.cert_id
        resp = client.post("/api/v1/entries", json={"entries": [entry_dict]})
        data = resp.json()
        assert data["rejected"] >= 1

    def test_submit_entries_missing_field(self, client):
        resp = client.post("/api/v1/entries", json={})
        assert resp.status_code == 400

    def test_get_entry(self, client, trail_with_entries):
        trail, _, _, _ = trail_with_entries
        entries = [e.to_dict() for e in trail.entries]
        client.post("/api/v1/entries", json={"entries": entries})
        entry_id = trail.entries[0].entry_id
        resp = client.get(f"/api/v1/entries/{entry_id}")
        assert resp.status_code == 200
        assert resp.json()["entry_id"] == entry_id

    def test_get_entry_not_found(self, client):
        resp = client.get("/api/v1/entries/nonexistent")
        assert resp.status_code == 404


# ═══════════════════════════════════════════════════════════════════════════════
# Trail Endpoints
# ═══════════════════════════════════════════════════════════════════════════════


class TestTrails:
    def test_get_trail(self, client, trail_with_entries):
        trail, _, _, _ = trail_with_entries
        entries = [e.to_dict() for e in trail.entries]
        client.post("/api/v1/entries", json={"entries": entries})
        resp = client.get(f"/api/v1/trails/{trail.trail_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["trail_id"] == trail.trail_id
        assert data["entry_count"] == 5

    def test_get_trail_not_found(self, client):
        resp = client.get("/api/v1/trails/nonexistent")
        assert resp.status_code == 404


# ═══════════════════════════════════════════════════════════════════════════════
# Proof Endpoints
# ═══════════════════════════════════════════════════════════════════════════════


class TestProofs:
    def test_get_proof_pending(self, client, trail_with_entries):
        trail, _, _, _ = trail_with_entries
        entries = [e.to_dict() for e in trail.entries]
        client.post("/api/v1/entries", json={"entries": entries})
        entry_id = trail.entries[0].entry_id
        resp = client.get(f"/api/v1/proofs/{entry_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "pending"

    def test_get_proof_after_batch(self, client, app, trail_with_entries):
        trail, _, _, _ = trail_with_entries
        entries = [e.to_dict() for e in trail.entries]
        client.post("/api/v1/entries", json={"entries": entries})

        # Force a batch
        resp = client.post("/api/v1/admin/force-batch")
        assert resp.status_code == 200
        batch_data = resp.json()
        assert batch_data["status"] == "batched"

        # Now get proof
        entry_id = trail.entries[2].entry_id
        resp = client.get(f"/api/v1/proofs/{entry_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert "proof" in data
        assert data["batch_id"] == batch_data["batch_id"]

    def test_get_proof_not_found(self, client):
        resp = client.get("/api/v1/proofs/nonexistent")
        assert resp.status_code == 404


# ═══════════════════════════════════════════════════════════════════════════════
# Verify Endpoint
# ═══════════════════════════════════════════════════════════════════════════════


class TestVerify:
    def test_verify_entry_pending(self, client, trail_with_entries):
        trail, _, _, _ = trail_with_entries
        entries = [e.to_dict() for e in trail.entries]
        client.post("/api/v1/entries", json={"entries": entries})
        entry_id = trail.entries[0].entry_id
        resp = client.get(f"/api/v1/verify/{entry_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "PENDING"
        assert data["checks"]["entry_integrity"] is True
        assert data["checks"]["agent_signature"] is True

    def test_verify_entry_after_batch(self, client, app, trail_with_entries):
        trail, _, _, _ = trail_with_entries
        entries = [e.to_dict() for e in trail.entries]
        client.post("/api/v1/entries", json={"entries": entries})
        client.post("/api/v1/admin/force-batch")

        entry_id = trail.entries[1].entry_id
        resp = client.get(f"/api/v1/verify/{entry_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "NOT_ANCHORED"
        assert data["checks"]["entry_integrity"] is True
        assert data["checks"]["agent_signature"] is True
        assert data["checks"]["cert_binding"] is True
        assert data["checks"]["merkle_proof"] is True
        assert data["checks"]["anchor_on_chain"] is False
        assert "batch" in data

    def test_verify_not_found(self, client):
        resp = client.get("/api/v1/verify/nonexistent")
        assert resp.status_code == 404


# ═══════════════════════════════════════════════════════════════════════════════
# Batch Endpoints
# ═══════════════════════════════════════════════════════════════════════════════


class TestBatches:
    def test_force_batch_no_entries(self, client):
        resp = client.post("/api/v1/admin/force-batch")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "no_entries"

    def test_force_batch_with_entries(self, client, trail_with_entries):
        trail, _, _, _ = trail_with_entries
        entries = [e.to_dict() for e in trail.entries]
        client.post("/api/v1/entries", json={"entries": entries})

        resp = client.post("/api/v1/admin/force-batch")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "batched"
        assert data["item_count"] == 5
        assert data["anchored"] is False

    def test_get_batch(self, client, trail_with_entries):
        trail, _, _, _ = trail_with_entries
        entries = [e.to_dict() for e in trail.entries]
        client.post("/api/v1/entries", json={"entries": entries})
        batch_resp = client.post("/api/v1/admin/force-batch")
        batch_id = batch_resp.json()["batch_id"]

        resp = client.get(f"/api/v1/batches/{batch_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["batch_id"] == batch_id
        assert data["item_count"] == 5

    def test_get_batch_not_found(self, client):
        resp = client.get("/api/v1/batches/nonexistent")
        assert resp.status_code == 404

    def test_get_latest_batch(self, client, trail_with_entries):
        trail, _, _, _ = trail_with_entries
        entries = [e.to_dict() for e in trail.entries]
        client.post("/api/v1/entries", json={"entries": entries})
        client.post("/api/v1/admin/force-batch")

        resp = client.get("/api/v1/batches/latest")
        assert resp.status_code == 200
        data = resp.json()
        assert data["item_count"] == 5

    def test_get_latest_batch_empty(self, client):
        resp = client.get("/api/v1/batches/latest")
        assert resp.status_code == 404


# ═══════════════════════════════════════════════════════════════════════════════
# Integration: Full Flow
# ═══════════════════════════════════════════════════════════════════════════════


class TestFullFlow:
    def test_register_submit_batch_proof_verify(self, client, app):
        """Full integration: register cert → submit entries → batch → proof → verify."""
        # Create identity
        creator_keys = generate_keys()
        agent_keys = generate_keys()
        cert = create_certificate(
            creator_keys=creator_keys, agent_keys=agent_keys,
            name="flow-agent", platform="test",
            model_hash="sha256:flow", capabilities=["compute"],
            constraints=["budget-1000"], risk_tier=2, expires_days=30,
        )

        # Register
        resp = client.post("/api/v1/certificates", json={"certificate": cert.to_dict()})
        assert resp.status_code == 200

        # Create trail and log actions
        trail = create_audit_trail(cert, agent_keys)
        for i in range(3):
            log_action(trail, agent_keys,
                       action_type=ActionType.TOOL_USE,
                       action_summary=f"Flow action {i}")

        # Submit
        entries = [e.to_dict() for e in trail.entries]
        resp = client.post("/api/v1/entries", json={"entries": entries})
        assert resp.json()["accepted"] == 3

        # Verify pending
        resp = client.get(f"/api/v1/verify/{trail.entries[0].entry_id}")
        assert resp.json()["status"] == "PENDING"

        # Force batch
        resp = client.post("/api/v1/admin/force-batch")
        assert resp.json()["status"] == "batched"

        # Get proof
        resp = client.get(f"/api/v1/proofs/{trail.entries[1].entry_id}")
        data = resp.json()
        assert "proof" in data
        assert data["proof"]["root"] == data["merkle_root"]

        # Verify with batch (NOT_ANCHORED because no Bitcoin wallet configured)
        resp = client.get(f"/api/v1/verify/{trail.entries[1].entry_id}")
        data = resp.json()
        assert data["status"] == "NOT_ANCHORED"
        assert data["checks"]["entry_integrity"] is True
        assert data["checks"]["agent_signature"] is True
        assert data["checks"]["cert_binding"] is True
        assert data["checks"]["merkle_proof"] is True
        assert data["checks"]["anchor_on_chain"] is False

        # Check stats
        resp = client.get("/api/v1/stats")
        stats = resp.json()
        assert stats["entries_total"] == 3
        assert stats["entries_pending"] == 0
        assert stats["batches_total"] == 1


# ═══════════════════════════════════════════════════════════════════════════════
# Config Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestConfig:
    def test_default_config(self):
        cfg = ServiceConfig()
        assert cfg.port == 8932
        assert cfg.network == "testnet"
        assert cfg.batch_interval_seconds == 600

    def test_from_env(self, monkeypatch):
        monkeypatch.setenv("AGENTCERT_PORT", "9999")
        monkeypatch.setenv("AGENTCERT_NETWORK", "mainnet")
        monkeypatch.setenv("AGENTCERT_BATCH_INTERVAL", "120")
        cfg = ServiceConfig.from_env()
        assert cfg.port == 9999
        assert cfg.network == "mainnet"
        assert cfg.batch_interval_seconds == 120

    def test_from_file(self, tmp_path):
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "port": 7777,
            "network": "mainnet",
            "batch_min_entries": 10,
            "unknown_key": "ignored",
        }))
        cfg = ServiceConfig.from_file(str(config_file))
        assert cfg.port == 7777
        assert cfg.network == "mainnet"
        assert cfg.batch_min_entries == 10


# ═══════════════════════════════════════════════════════════════════════════════
# Database Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestDatabase:
    def test_register_and_get_certificate(self, app):
        db = app.state.db
        ck = generate_keys()
        ak = generate_keys()
        cert = create_certificate(
            creator_keys=ck, agent_keys=ak, name="db-test",
            platform="test", model_hash="sha256:db", capabilities=["x"],
            constraints=["y"], risk_tier=1, expires_days=30,
        )
        cert_dict = cert.to_dict()
        db.register_certificate(cert_dict)
        result = db.get_certificate(cert.cert_id)
        assert result is not None
        assert result["cert_id"] == cert.cert_id

    def test_get_certificate_not_found(self, app):
        db = app.state.db
        assert db.get_certificate("nonexistent") is None

    def test_store_and_get_entries(self, app):
        db = app.state.db
        ck = generate_keys()
        ak = generate_keys()
        cert = create_certificate(
            creator_keys=ck, agent_keys=ak, name="db-test",
            platform="test", model_hash="sha256:db", capabilities=["x"],
            constraints=["y"], risk_tier=1, expires_days=30,
        )
        db.register_certificate(cert.to_dict())
        trail = create_audit_trail(cert, ak)
        log_action(trail, ak, action_type=ActionType.TOOL_USE, action_summary="test")
        entries = [e.to_dict() for e in trail.entries]
        inserted = db.store_entries(entries)
        assert len(inserted) == 1

        result = db.get_entry(trail.entries[0].entry_id)
        assert result is not None
        assert result["entry_id"] == trail.entries[0].entry_id

    def test_get_unbatched_entries(self, app):
        db = app.state.db
        ck = generate_keys()
        ak = generate_keys()
        cert = create_certificate(
            creator_keys=ck, agent_keys=ak, name="db-test",
            platform="test", model_hash="sha256:db", capabilities=["x"],
            constraints=["y"], risk_tier=1, expires_days=30,
        )
        db.register_certificate(cert.to_dict())
        trail = create_audit_trail(cert, ak)
        for i in range(3):
            log_action(trail, ak, action_type=ActionType.TOOL_USE,
                       action_summary=f"test {i}")
        db.store_entries([e.to_dict() for e in trail.entries])
        unbatched = db.get_unbatched_entries()
        assert len(unbatched) == 3

    def test_stats(self, app):
        db = app.state.db
        stats = db.get_stats()
        assert stats["entries_total"] == 0
        assert stats["batches_total"] == 0
