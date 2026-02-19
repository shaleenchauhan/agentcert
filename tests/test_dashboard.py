"""Tests for the AgentCert dashboard routes.

Verifies all dashboard pages return 200, contain expected data,
and handle empty state gracefully.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from agentcert.keys import generate_keys
from agentcert.certificate import create_certificate
from agentcert.audit import create_audit_trail, log_action
from agentcert.types import ActionType
from agentcert.service.app import create_app
from agentcert.service.config import ServiceConfig


# ── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture()
def config():
    return ServiceConfig(
        db_path=":memory:",
        batch_interval_seconds=99999,
        batch_min_entries=1,
    )


@pytest.fixture()
def app(config):
    return create_app(config)


@pytest.fixture()
def client(app):
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def seeded_client(app):
    """Client with seeded data: 1 cert, 5 entries, 1 batch."""
    with TestClient(app) as c:
        ck = generate_keys()
        ak = generate_keys()
        cert = create_certificate(
            creator_keys=ck, agent_keys=ak,
            name="dashboard-test-agent", platform="langchain",
            model_hash="sha256:abc123", capabilities=["search", "compute"],
            constraints=["budget-1000"], risk_tier=2, expires_days=90,
        )
        c.post("/api/v1/certificates", json={"certificate": cert.to_dict()})

        trail = create_audit_trail(cert, ak)
        for i in range(5):
            log_action(trail, ak, action_type=ActionType.TOOL_USE,
                       action_summary=f"Dashboard action {i}")

        entries = [e.to_dict() for e in trail.entries]
        c.post("/api/v1/entries", json={"entries": entries})
        c.post("/api/v1/admin/force-batch")

        c._test_cert = cert
        c._test_trail = trail
        yield c


# ═══════════════════════════════════════════════════════════════════════════════
# Empty State Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestEmptyState:
    def test_overview_empty(self, client):
        resp = client.get("/dashboard")
        assert resp.status_code == 200, resp.text
        assert "AgentCert" in resp.text
        assert "No entries yet" in resp.text

    def test_agents_empty(self, client):
        resp = client.get("/dashboard/agents")
        assert resp.status_code == 200
        assert "No agents registered" in resp.text

    def test_batches_empty(self, client):
        resp = client.get("/dashboard/batches")
        assert resp.status_code == 200
        assert "No batches yet" in resp.text

    def test_verify_page(self, client):
        resp = client.get("/dashboard/verify")
        assert resp.status_code == 200
        assert "Verification Tool" in resp.text
        assert "entry-id-input" in resp.text


# ═══════════════════════════════════════════════════════════════════════════════
# Overview Page
# ═══════════════════════════════════════════════════════════════════════════════


class TestOverview:
    def test_overview_with_data(self, seeded_client):
        resp = seeded_client.get("/dashboard")
        assert resp.status_code == 200
        assert "dashboard-test-agent" in resp.text
        assert "Dashboard action" in resp.text

    def test_overview_stats(self, seeded_client):
        resp = seeded_client.get("/dashboard")
        assert resp.status_code == 200
        # Should show stats cards
        assert "Agents" in resp.text
        assert "Entries" in resp.text
        assert "Batches" in resp.text
        assert "Pending" in resp.text


# ═══════════════════════════════════════════════════════════════════════════════
# Agents Pages
# ═══════════════════════════════════════════════════════════════════════════════


class TestAgents:
    def test_agents_list(self, seeded_client):
        resp = seeded_client.get("/dashboard/agents")
        assert resp.status_code == 200
        assert "dashboard-test-agent" in resp.text
        assert "langchain" in resp.text

    def test_agent_detail(self, seeded_client):
        cert = seeded_client._test_cert
        resp = seeded_client.get(f"/dashboard/agents/{cert.cert_id}")
        assert resp.status_code == 200
        assert "dashboard-test-agent" in resp.text
        assert "langchain" in resp.text
        assert "search" in resp.text  # capability
        assert "budget-1000" in resp.text  # constraint
        # Should have entries table
        assert "Dashboard action" in resp.text

    def test_agent_detail_not_found(self, client):
        resp = client.get("/dashboard/agents/nonexistent")
        assert resp.status_code == 404


# ═══════════════════════════════════════════════════════════════════════════════
# Entry Detail Page
# ═══════════════════════════════════════════════════════════════════════════════


class TestEntryDetail:
    def test_entry_detail(self, seeded_client):
        trail = seeded_client._test_trail
        entry_id = trail.entries[2].entry_id
        resp = seeded_client.get(f"/dashboard/entries/{entry_id}")
        assert resp.status_code == 200
        assert entry_id in resp.text
        assert "Dashboard action 2" in resp.text
        assert "Verification" in resp.text

    def test_entry_detail_has_proof(self, seeded_client):
        trail = seeded_client._test_trail
        entry_id = trail.entries[0].entry_id
        resp = seeded_client.get(f"/dashboard/entries/{entry_id}")
        assert resp.status_code == 200
        assert "Merkle Proof" in resp.text
        assert "Leaf Index" in resp.text

    def test_entry_detail_not_found(self, client):
        resp = client.get("/dashboard/entries/nonexistent")
        assert resp.status_code == 404


# ═══════════════════════════════════════════════════════════════════════════════
# Batches Pages
# ═══════════════════════════════════════════════════════════════════════════════


class TestBatches:
    def test_batches_list(self, seeded_client):
        resp = seeded_client.get("/dashboard/batches")
        assert resp.status_code == 200
        assert "Pending" in resp.text  # anchor status badge

    def test_batch_detail(self, seeded_client):
        # Get the batch ID from the API
        batch_resp = seeded_client.get("/api/v1/batches/latest")
        batch_id = batch_resp.json()["batch_id"]

        resp = seeded_client.get(f"/dashboard/batches/{batch_id}")
        assert resp.status_code == 200
        assert batch_id[:16] in resp.text
        assert "Dashboard action" in resp.text
        assert "5" in resp.text  # entry count

    def test_batch_detail_not_found(self, client):
        resp = client.get("/dashboard/batches/nonexistent")
        assert resp.status_code == 404


# ═══════════════════════════════════════════════════════════════════════════════
# Static Files
# ═══════════════════════════════════════════════════════════════════════════════


class TestStaticFiles:
    def test_css(self, client):
        resp = client.get("/dashboard/static/style.css")
        assert resp.status_code == 200
        assert "AgentCert" in resp.text

    def test_js(self, client):
        resp = client.get("/dashboard/static/main.js")
        assert resp.status_code == 200
        assert "copyToClipboard" in resp.text


# ═══════════════════════════════════════════════════════════════════════════════
# Navigation Links
# ═══════════════════════════════════════════════════════════════════════════════


class TestNavigation:
    def test_nav_links_present(self, client):
        resp = client.get("/dashboard")
        assert resp.status_code == 200
        assert "/dashboard/agents" in resp.text
        assert "/dashboard/batches" in resp.text
        assert "/dashboard/verify" in resp.text

    def test_agent_links_to_entries(self, seeded_client):
        cert = seeded_client._test_cert
        resp = seeded_client.get(f"/dashboard/agents/{cert.cert_id}")
        trail = seeded_client._test_trail
        entry_id = trail.entries[0].entry_id
        assert f"/dashboard/entries/{entry_id}" in resp.text


# ═══════════════════════════════════════════════════════════════════════════════
# Database Query Methods
# ═══════════════════════════════════════════════════════════════════════════════


class TestDashboardQueries:
    def test_get_all_certificates(self, seeded_client):
        db = seeded_client.app.state.db
        certs = db.get_all_certificates()
        assert len(certs) == 1
        assert certs[0]["agent_metadata"]["name"] == "dashboard-test-agent"

    def test_get_recent_entries(self, seeded_client):
        db = seeded_client.app.state.db
        entries = db.get_recent_entries(limit=3)
        assert len(entries) == 3
        assert "_batch_id" in entries[0]

    def test_get_recent_batches(self, seeded_client):
        db = seeded_client.app.state.db
        batches = db.get_recent_batches(limit=5)
        assert len(batches) == 1
        assert batches[0]["item_count"] == 5

    def test_get_entries_by_cert(self, seeded_client):
        db = seeded_client.app.state.db
        cert = seeded_client._test_cert
        entries = db.get_entries_by_cert(cert.cert_id)
        assert len(entries) == 5

    def test_get_entry_count_by_cert(self, seeded_client):
        db = seeded_client.app.state.db
        cert = seeded_client._test_cert
        count = db.get_entry_count_by_cert(cert.cert_id)
        assert count == 5

    def test_get_entries_by_batch(self, seeded_client):
        db = seeded_client.app.state.db
        batches = db.get_all_batches()
        entries = db.get_entries_by_batch(batches[0]["batch_id"])
        assert len(entries) == 5

    def test_get_all_batches(self, seeded_client):
        db = seeded_client.app.state.db
        batches = db.get_all_batches()
        assert len(batches) == 1

    def test_get_last_active_by_cert(self, seeded_client):
        db = seeded_client.app.state.db
        cert = seeded_client._test_cert
        ts = db.get_last_active_by_cert(cert.cert_id)
        assert ts is not None

    def test_get_last_active_no_entries(self, client):
        db = client.app.state.db
        ts = db.get_last_active_by_cert("nonexistent")
        assert ts is None
