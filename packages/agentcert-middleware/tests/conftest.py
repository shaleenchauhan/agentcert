"""Shared test fixtures for agentcert-middleware tests."""

from __future__ import annotations

import pytest

import agentcert
from agentcert.audit import create_audit_trail, log_action
from agentcert.types import ActionType, AuditEntry, Certificate, KeyPair


@pytest.fixture
def creator_keys() -> KeyPair:
    """Generate a fresh creator key pair."""
    return agentcert.generate_keys()


@pytest.fixture
def agent_keys() -> KeyPair:
    """Generate a fresh agent key pair."""
    return agentcert.generate_keys()


@pytest.fixture
def certificate(creator_keys: KeyPair, agent_keys: KeyPair) -> Certificate:
    """Create a signed certificate."""
    return agentcert.create_certificate(
        creator_keys=creator_keys,
        agent_keys=agent_keys,
        name="test-agent",
        platform="test",
        model_hash="sha256:test",
        capabilities=["test"],
        constraints=[],
        risk_tier=3,
        expires_days=90,
    )


@pytest.fixture
def trail_with_entries(
    certificate: Certificate, agent_keys: KeyPair
) -> tuple[agentcert.AuditTrail, list[AuditEntry]]:
    """Create a trail with 3 sample entries."""
    trail = create_audit_trail(certificate, agent_keys)
    entries = []
    for i, (action_type, summary) in enumerate(
        [
            (ActionType.API_CALL, "Called external API"),
            (ActionType.TOOL_USE, "Used search tool"),
            (ActionType.DECISION, "Decided next step"),
        ]
    ):
        entry = log_action(
            trail=trail,
            agent_keys=agent_keys,
            action_type=action_type,
            action_summary=summary,
            action_detail={"step": i},
        )
        entries.append(entry)
    return (trail, entries)


@pytest.fixture
def tmp_storage_dir(tmp_path):
    """Temporary directory for storage tests."""
    return str(tmp_path / "agentcert-audit")
