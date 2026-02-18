"""Tests for agentcert.audit_verify — audit entry and trail verification."""

import copy
import dataclasses

import pytest

from agentcert.keys import generate_keys
from agentcert.certificate import create_certificate
from agentcert.audit import (
    AuditTrail,
    create_audit_trail,
    log_action,
)
from agentcert.audit_verify import verify_audit_entry, verify_audit_trail
from agentcert.types import (
    ActionType,
    AuditEntry,
    AuditVerificationCheck,
    AuditVerificationResult,
    AuditTrailVerificationResult,
)


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
        name="verify-test", platform="pytest", model_hash="sha256:test",
        capabilities=["test"], constraints=["none"],
        risk_tier=1, expires_days=30,
    )


@pytest.fixture
def other_cert(creator, agent):
    return create_certificate(
        creator_keys=creator, agent_keys=agent,
        name="other", platform="pytest", model_hash="sha256:other",
        capabilities=[], constraints=[],
        risk_tier=1, expires_days=1,
    )


@pytest.fixture
def trail(cert, agent):
    return create_audit_trail(cert, agent, timestamp=1000)


@pytest.fixture
def trail_with_entries(trail, agent):
    log_action(trail, agent, action_type=ActionType.API_CALL,
               action_summary="Called API", timestamp=1001)
    log_action(trail, agent, action_type=ActionType.DECISION,
               action_summary="Made decision", timestamp=1002)
    log_action(trail, agent, action_type=ActionType.TRANSACTION,
               action_summary="Placed order", timestamp=1003)
    return trail


# ═══════════════════════════════════════════════════════════════════════════════
# verify_audit_entry
# ═══════════════════════════════════════════════════════════════════════════════


class TestVerifyAuditEntryValid:
    def test_valid_with_cert(self, trail_with_entries, cert):
        entry = trail_with_entries.entries[0]
        result = verify_audit_entry(entry, cert)
        assert isinstance(result, AuditVerificationResult)
        assert result.valid
        assert result.status == "VALID"
        assert result.entry_id == entry.entry_id
        assert len(result.checks) == 6

    def test_valid_without_cert(self, trail_with_entries):
        entry = trail_with_entries.entries[0]
        result = verify_audit_entry(entry)
        assert result.valid
        assert any("skipped" in c.detail for c in result.checks)

    def test_all_check_names(self, trail_with_entries, cert):
        entry = trail_with_entries.entries[0]
        result = verify_audit_entry(entry, cert)
        names = [c.name for c in result.checks]
        assert names == [
            "entry_id_integrity",
            "agent_id_derivation",
            "agent_signature",
            "sequence_validity",
            "timestamp_validity",
            "cert_binding",
        ]

    def test_all_entries_valid(self, trail_with_entries, cert):
        for entry in trail_with_entries.entries:
            result = verify_audit_entry(entry, cert)
            assert result.valid, f"Entry {entry.sequence} failed"


class TestVerifyAuditEntryInvalid:
    def test_tampered_entry_id(self, trail_with_entries):
        entry = trail_with_entries.entries[0]
        tampered = dataclasses.replace(entry, entry_id="0" * 64)
        result = verify_audit_entry(tampered)
        assert not result.valid
        failed = [c for c in result.checks if not c.passed]
        assert any(c.name == "entry_id_integrity" for c in failed)

    def test_tampered_agent_id(self, trail_with_entries):
        entry = trail_with_entries.entries[0]
        tampered = dataclasses.replace(entry, agent_id="0" * 64)
        result = verify_audit_entry(tampered)
        assert not result.valid
        failed = [c for c in result.checks if not c.passed]
        assert any(c.name == "agent_id_derivation" for c in failed)

    def test_tampered_signature(self, trail_with_entries):
        entry = trail_with_entries.entries[0]
        # Flip a byte in the signature
        bad_sig = "00" + entry.agent_signature[2:]
        tampered = dataclasses.replace(entry, agent_signature=bad_sig)
        result = verify_audit_entry(tampered)
        assert not result.valid
        failed = [c for c in result.checks if not c.passed]
        assert any(c.name == "agent_signature" for c in failed)

    def test_negative_sequence(self, trail_with_entries):
        entry = trail_with_entries.entries[0]
        tampered = dataclasses.replace(entry, sequence=-1)
        result = verify_audit_entry(tampered)
        assert not result.valid
        failed = [c for c in result.checks if not c.passed]
        assert any(c.name == "sequence_validity" for c in failed)

    def test_zero_timestamp(self, trail_with_entries):
        entry = trail_with_entries.entries[0]
        tampered = dataclasses.replace(entry, timestamp=0)
        result = verify_audit_entry(tampered)
        assert not result.valid
        failed = [c for c in result.checks if not c.passed]
        assert any(c.name == "timestamp_validity" for c in failed)

    def test_wrong_cert_binding(self, trail_with_entries, other_cert):
        entry = trail_with_entries.entries[0]
        result = verify_audit_entry(entry, other_cert)
        assert not result.valid
        failed = [c for c in result.checks if not c.passed]
        assert any(c.name == "cert_binding" for c in failed)


# ═══════════════════════════════════════════════════════════════════════════════
# verify_audit_trail
# ═══════════════════════════════════════════════════════════════════════════════


class TestVerifyAuditTrailValid:
    def test_valid_with_cert(self, trail_with_entries, cert):
        result = verify_audit_trail(trail_with_entries, cert)
        assert isinstance(result, AuditTrailVerificationResult)
        assert result.valid
        assert result.status == "VALID"
        assert result.trail_id == trail_with_entries.trail_id
        assert result.entry_count == 3
        assert len(result.checks) == 11

    def test_valid_without_cert(self, trail_with_entries):
        result = verify_audit_trail(trail_with_entries)
        assert result.valid
        assert any("skipped" in c.detail for c in result.checks)

    def test_single_entry(self, trail, agent, cert):
        log_action(trail, agent, action_type=ActionType.API_CALL,
                   action_summary="only entry", timestamp=1001)
        result = verify_audit_trail(trail, cert)
        assert result.valid
        assert result.entry_count == 1

    def test_all_check_names(self, trail_with_entries, cert):
        result = verify_audit_trail(trail_with_entries, cert)
        names = [c.name for c in result.checks]
        assert names == [
            "trail_non_empty",
            "trail_id_consistency",
            "cert_id_consistency",
            "agent_consistency",
            "first_entry_linkage",
            "chain_integrity",
            "sequence_continuity",
            "timestamp_ordering",
            "all_entry_ids",
            "all_signatures",
            "cert_binding",
        ]


class TestVerifyAuditTrailEmpty:
    def test_empty_trail(self):
        empty = AuditTrail(
            trail_id="a" * 64, cert_id="b" * 64, agent_id="c" * 64,
            agent_public_key="d" * 66, created=1000,
        )
        result = verify_audit_trail(empty)
        assert not result.valid
        assert result.entry_count == 0
        assert len(result.checks) == 1
        assert result.checks[0].name == "trail_non_empty"
        assert not result.checks[0].passed


class TestVerifyAuditTrailBrokenChain:
    def test_broken_linkage(self, trail_with_entries):
        trail = copy.deepcopy(trail_with_entries)
        trail.entries[2] = dataclasses.replace(
            trail.entries[2], previous_entry_id="0" * 64
        )
        result = verify_audit_trail(trail)
        assert not result.valid
        chain_check = [c for c in result.checks if c.name == "chain_integrity"][0]
        assert not chain_check.passed
        assert "entry 2" in chain_check.detail

    def test_first_entry_has_previous(self, trail_with_entries):
        trail = copy.deepcopy(trail_with_entries)
        trail.entries[0] = dataclasses.replace(
            trail.entries[0], previous_entry_id="0" * 64
        )
        result = verify_audit_trail(trail)
        assert not result.valid
        linkage_check = [c for c in result.checks if c.name == "first_entry_linkage"][0]
        assert not linkage_check.passed


class TestVerifyAuditTrailSequence:
    def test_sequence_gap(self, trail_with_entries):
        trail = copy.deepcopy(trail_with_entries)
        trail.entries[1] = dataclasses.replace(trail.entries[1], sequence=5)
        result = verify_audit_trail(trail)
        assert not result.valid
        seq_check = [c for c in result.checks if c.name == "sequence_continuity"][0]
        assert not seq_check.passed
        assert "entry 1" in seq_check.detail


class TestVerifyAuditTrailTimestamp:
    def test_timestamp_regression(self, trail_with_entries):
        trail = copy.deepcopy(trail_with_entries)
        trail.entries[2] = dataclasses.replace(trail.entries[2], timestamp=999)
        result = verify_audit_trail(trail)
        assert not result.valid
        ts_check = [c for c in result.checks if c.name == "timestamp_ordering"][0]
        assert not ts_check.passed

    def test_equal_timestamps_ok(self, trail, agent, cert):
        log_action(trail, agent, action_type=ActionType.API_CALL,
                   action_summary="a", timestamp=1000)
        log_action(trail, agent, action_type=ActionType.API_CALL,
                   action_summary="b", timestamp=1000)
        result = verify_audit_trail(trail, cert)
        ts_check = [c for c in result.checks if c.name == "timestamp_ordering"][0]
        assert ts_check.passed


class TestVerifyAuditTrailConsistency:
    def test_mismatched_trail_id(self, trail_with_entries):
        trail = copy.deepcopy(trail_with_entries)
        trail.entries[1] = dataclasses.replace(trail.entries[1], trail_id="0" * 64)
        result = verify_audit_trail(trail)
        assert not result.valid
        check = [c for c in result.checks if c.name == "trail_id_consistency"][0]
        assert not check.passed

    def test_mismatched_cert_id(self, trail_with_entries):
        trail = copy.deepcopy(trail_with_entries)
        trail.entries[0] = dataclasses.replace(trail.entries[0], cert_id="0" * 64)
        result = verify_audit_trail(trail)
        assert not result.valid
        check = [c for c in result.checks if c.name == "cert_id_consistency"][0]
        assert not check.passed

    def test_mismatched_agent_id(self, trail_with_entries):
        trail = copy.deepcopy(trail_with_entries)
        trail.entries[0] = dataclasses.replace(trail.entries[0], agent_id="0" * 64)
        result = verify_audit_trail(trail)
        assert not result.valid
        check = [c for c in result.checks if c.name == "agent_consistency"][0]
        assert not check.passed

    def test_wrong_cert_binding(self, trail_with_entries, other_cert):
        result = verify_audit_trail(trail_with_entries, other_cert)
        assert not result.valid
        check = [c for c in result.checks if c.name == "cert_binding"][0]
        assert not check.passed


class TestVerifyAuditTrailSignatures:
    def test_tampered_entry_id_detected(self, trail_with_entries):
        trail = copy.deepcopy(trail_with_entries)
        trail.entries[1] = dataclasses.replace(trail.entries[1], entry_id="0" * 64)
        result = verify_audit_trail(trail)
        assert not result.valid
        check = [c for c in result.checks if c.name == "all_entry_ids"][0]
        assert not check.passed
        assert "1" in check.detail  # sequence 1

    def test_tampered_signature_detected(self, trail_with_entries):
        trail = copy.deepcopy(trail_with_entries)
        orig_sig = trail.entries[0].agent_signature
        trail.entries[0] = dataclasses.replace(
            trail.entries[0], agent_signature="00" + orig_sig[2:]
        )
        result = verify_audit_trail(trail)
        assert not result.valid
        check = [c for c in result.checks if c.name == "all_signatures"][0]
        assert not check.passed
        assert "0" in check.detail  # sequence 0
