"""Tests for agentcert.audit — audit trail creation, logging, and persistence."""

import json

import pytest

from agentcert.keys import generate_keys
from agentcert.certificate import create_certificate
from agentcert.audit import (
    AuditTrail,
    create_audit_trail,
    log_action,
    get_trail_info,
    get_trail_entries,
    save_trail,
    load_trail,
    _compute_body_bytes,
    _compute_entry_id,
    _generate_trail_id,
)
from agentcert.types import ActionType, AuditEntry, AuditTrailInfo
from agentcert.exceptions import AuditError


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
        name="audit-test", platform="pytest", model_hash="sha256:test",
        capabilities=["test"], constraints=["none"],
        risk_tier=1, expires_days=30,
    )


@pytest.fixture
def trail(cert, agent):
    return create_audit_trail(cert, agent, timestamp=1000)


@pytest.fixture
def trail_with_entries(trail, agent):
    log_action(trail, agent, action_type=ActionType.API_CALL,
               action_summary="Called API", action_detail={"url": "https://example.com"},
               timestamp=1001)
    log_action(trail, agent, action_type=ActionType.DECISION,
               action_summary="Made decision", timestamp=1002)
    log_action(trail, agent, action_type=ActionType.API_CALL,
               action_summary="Called second API", timestamp=1003)
    return trail


class TestCreateAuditTrail:
    def test_returns_audit_trail(self, cert, agent):
        trail = create_audit_trail(cert, agent)
        assert isinstance(trail, AuditTrail)

    def test_trail_id_is_64_hex(self, trail):
        assert len(trail.trail_id) == 64
        int(trail.trail_id, 16)  # valid hex

    def test_bound_to_certificate(self, trail, cert):
        assert trail.cert_id == cert.cert_id
        assert trail.agent_id == cert.agent_id
        assert trail.agent_public_key == cert.agent_public_key

    def test_starts_empty(self, trail):
        assert trail.entries == []

    def test_custom_timestamp(self, cert, agent):
        trail = create_audit_trail(cert, agent, timestamp=12345)
        assert trail.created == 12345

    def test_deterministic_trail_id(self, cert, agent):
        t1 = create_audit_trail(cert, agent, timestamp=1000)
        t2 = create_audit_trail(cert, agent, timestamp=1000)
        assert t1.trail_id == t2.trail_id

    def test_different_timestamp_different_trail_id(self, cert, agent):
        t1 = create_audit_trail(cert, agent, timestamp=1000)
        t2 = create_audit_trail(cert, agent, timestamp=2000)
        assert t1.trail_id != t2.trail_id

    def test_wrong_agent_keys_raises(self, cert):
        wrong = generate_keys()
        with pytest.raises(AuditError, match="Agent key mismatch"):
            create_audit_trail(cert, wrong)


class TestLogAction:
    def test_returns_audit_entry(self, trail, agent):
        entry = log_action(trail, agent, action_type=ActionType.API_CALL,
                           action_summary="test")
        assert isinstance(entry, AuditEntry)

    def test_appends_to_trail(self, trail, agent):
        assert len(trail.entries) == 0
        log_action(trail, agent, action_type=ActionType.API_CALL,
                   action_summary="first")
        assert len(trail.entries) == 1
        log_action(trail, agent, action_type=ActionType.DECISION,
                   action_summary="second")
        assert len(trail.entries) == 2

    def test_sequence_auto_increments(self, trail, agent):
        e0 = log_action(trail, agent, action_type=ActionType.API_CALL,
                        action_summary="first")
        e1 = log_action(trail, agent, action_type=ActionType.API_CALL,
                        action_summary="second")
        e2 = log_action(trail, agent, action_type=ActionType.API_CALL,
                        action_summary="third")
        assert e0.sequence == 0
        assert e1.sequence == 1
        assert e2.sequence == 2

    def test_first_entry_no_previous(self, trail, agent):
        entry = log_action(trail, agent, action_type=ActionType.API_CALL,
                           action_summary="first")
        assert entry.previous_entry_id is None

    def test_chain_linkage(self, trail, agent):
        e0 = log_action(trail, agent, action_type=ActionType.API_CALL,
                        action_summary="first")
        e1 = log_action(trail, agent, action_type=ActionType.API_CALL,
                        action_summary="second")
        assert e1.previous_entry_id == e0.entry_id

    def test_entry_id_is_64_hex(self, trail, agent):
        entry = log_action(trail, agent, action_type=ActionType.API_CALL,
                           action_summary="test")
        assert len(entry.entry_id) == 64
        int(entry.entry_id, 16)

    def test_entry_id_matches_body_hash(self, trail, agent):
        entry = log_action(trail, agent, action_type=ActionType.API_CALL,
                           action_summary="test", timestamp=5000)
        body_bytes = entry.body_bytes()
        expected = _compute_entry_id(body_bytes)
        assert entry.entry_id == expected

    def test_signature_is_hex(self, trail, agent):
        entry = log_action(trail, agent, action_type=ActionType.API_CALL,
                           action_summary="test")
        bytes.fromhex(entry.agent_signature)  # should not raise

    def test_metadata_preserved(self, trail, agent):
        entry = log_action(trail, agent, action_type=ActionType.TRANSACTION,
                           action_summary="Placed order",
                           action_detail={"vendor": "Acme", "amount": 42.0},
                           timestamp=9999)
        assert entry.action_type == ActionType.TRANSACTION
        assert entry.action_summary == "Placed order"
        assert entry.action_detail == {"vendor": "Acme", "amount": 42.0}
        assert entry.timestamp == 9999
        assert entry.trail_id == trail.trail_id
        assert entry.cert_id == trail.cert_id
        assert entry.agent_id == trail.agent_id

    def test_default_action_detail_is_empty_dict(self, trail, agent):
        entry = log_action(trail, agent, action_type=ActionType.API_CALL,
                           action_summary="test")
        assert entry.action_detail == {}

    def test_action_type_as_int(self, trail, agent):
        entry = log_action(trail, agent, action_type=1, action_summary="test")
        assert entry.action_type == ActionType.API_CALL

    def test_wrong_agent_keys_raises(self, trail):
        wrong = generate_keys()
        with pytest.raises(AuditError, match="Agent key mismatch"):
            log_action(trail, wrong, action_type=ActionType.API_CALL,
                       action_summary="test")

    def test_empty_summary_raises(self, trail, agent):
        with pytest.raises(AuditError, match="action_summary must not be empty"):
            log_action(trail, agent, action_type=ActionType.API_CALL,
                       action_summary="")

    def test_whitespace_summary_raises(self, trail, agent):
        with pytest.raises(AuditError, match="action_summary must not be empty"):
            log_action(trail, agent, action_type=ActionType.API_CALL,
                       action_summary="   ")


class TestGetTrailInfo:
    def test_empty_trail(self, trail):
        info = get_trail_info(trail)
        assert isinstance(info, AuditTrailInfo)
        assert info.trail_id == trail.trail_id
        assert info.cert_id == trail.cert_id
        assert info.agent_id == trail.agent_id
        assert info.entry_count == 0
        assert info.created == trail.created
        assert info.last_entry is None

    def test_with_entries(self, trail_with_entries):
        info = get_trail_info(trail_with_entries)
        assert info.entry_count == 3
        assert info.last_entry == 1003


class TestGetTrailEntries:
    def test_all_entries(self, trail_with_entries):
        entries = get_trail_entries(trail_with_entries)
        assert len(entries) == 3

    def test_filter_by_action_type(self, trail_with_entries):
        api_entries = get_trail_entries(trail_with_entries,
                                        action_type=ActionType.API_CALL)
        assert len(api_entries) == 2
        assert all(e.action_type == ActionType.API_CALL for e in api_entries)

    def test_filter_by_action_type_no_match(self, trail_with_entries):
        entries = get_trail_entries(trail_with_entries,
                                    action_type=ActionType.ERROR)
        assert len(entries) == 0

    def test_filter_by_start(self, trail_with_entries):
        entries = get_trail_entries(trail_with_entries, start=1)
        assert len(entries) == 2
        assert entries[0].sequence == 1

    def test_filter_by_end(self, trail_with_entries):
        entries = get_trail_entries(trail_with_entries, end=1)
        assert len(entries) == 2
        assert entries[-1].sequence == 1

    def test_filter_by_range(self, trail_with_entries):
        entries = get_trail_entries(trail_with_entries, start=1, end=1)
        assert len(entries) == 1
        assert entries[0].sequence == 1

    def test_combined_filters(self, trail_with_entries):
        entries = get_trail_entries(trail_with_entries,
                                    action_type=ActionType.API_CALL, start=1)
        assert len(entries) == 1
        assert entries[0].sequence == 2


class TestAuditTrailSerialization:
    def test_to_dict_roundtrip(self, trail_with_entries):
        d = trail_with_entries.to_dict()
        loaded = AuditTrail.from_dict(d)
        assert loaded.trail_id == trail_with_entries.trail_id
        assert loaded.cert_id == trail_with_entries.cert_id
        assert loaded.agent_id == trail_with_entries.agent_id
        assert loaded.created == trail_with_entries.created
        assert len(loaded.entries) == len(trail_with_entries.entries)
        for orig, copy in zip(trail_with_entries.entries, loaded.entries):
            assert orig.entry_id == copy.entry_id
            assert orig.agent_signature == copy.agent_signature

    def test_empty_trail_roundtrip(self, trail):
        d = trail.to_dict()
        loaded = AuditTrail.from_dict(d)
        assert loaded.trail_id == trail.trail_id
        assert loaded.entries == []


class TestSaveLoadTrail:
    def test_roundtrip(self, trail_with_entries, tmp_path):
        path = tmp_path / "trail.json"
        save_trail(trail_with_entries, path)
        loaded = load_trail(path)
        assert loaded.trail_id == trail_with_entries.trail_id
        assert len(loaded.entries) == 3
        for orig, copy in zip(trail_with_entries.entries, loaded.entries):
            assert orig.entry_id == copy.entry_id

    def test_file_is_valid_json(self, trail_with_entries, tmp_path):
        path = tmp_path / "trail.json"
        save_trail(trail_with_entries, path)
        data = json.loads(path.read_text())
        assert data["trail_id"] == trail_with_entries.trail_id
        assert len(data["entries"]) == 3

    def test_load_nonexistent(self, tmp_path):
        with pytest.raises(AuditError, match="Failed to load"):
            load_trail(tmp_path / "nonexistent.json")

    def test_save_invalid_path(self, trail):
        with pytest.raises(AuditError, match="Failed to save"):
            save_trail(trail, "/nonexistent/dir/trail.json")


class TestAuditEntryDataclass:
    def test_from_dict_roundtrip(self, trail_with_entries):
        entry = trail_with_entries.entries[0]
        d = entry.to_dict()
        loaded = AuditEntry.from_dict(d)
        assert loaded == entry

    def test_body_dict_excludes_id_and_sig(self, trail_with_entries):
        entry = trail_with_entries.entries[0]
        body = entry.body_dict()
        assert "entry_id" not in body
        assert "agent_signature" not in body

    def test_body_bytes_deterministic(self, trail_with_entries):
        entry = trail_with_entries.entries[0]
        assert entry.body_bytes() == entry.body_bytes()

    def test_body_bytes_is_canonical_json(self, trail_with_entries):
        entry = trail_with_entries.entries[0]
        body_bytes = entry.body_bytes()
        parsed = json.loads(body_bytes)
        # Verify sort_keys and compact separators
        re_encoded = json.dumps(parsed, sort_keys=True, separators=(",", ":")).encode("utf-8")
        assert body_bytes == re_encoded


class TestHelpers:
    def test_generate_trail_id_deterministic(self):
        id1 = _generate_trail_id("cert1", "agent1", 1000)
        id2 = _generate_trail_id("cert1", "agent1", 1000)
        assert id1 == id2

    def test_generate_trail_id_different_inputs(self):
        id1 = _generate_trail_id("cert1", "agent1", 1000)
        id2 = _generate_trail_id("cert2", "agent1", 1000)
        assert id1 != id2

    def test_compute_entry_id_length(self):
        body_bytes = _compute_body_bytes({"key": "value"})
        entry_id = _compute_entry_id(body_bytes)
        assert len(entry_id) == 64


class TestActionType:
    def test_all_members(self):
        expected = {
            "API_CALL": 1, "TOOL_USE": 2, "DECISION": 3, "DATA_ACCESS": 4,
            "TRANSACTION": 5, "COMMUNICATION": 6, "ERROR": 7, "CUSTOM": 99,
        }
        for name, value in expected.items():
            assert ActionType[name] == value

    def test_int_conversion(self):
        assert int(ActionType.API_CALL) == 1
        assert ActionType(5) == ActionType.TRANSACTION
