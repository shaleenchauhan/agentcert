"""Tests for agentcert.chain — update, revoke, and chain verification."""

import pytest

from agentcert.keys import generate_keys
from agentcert.certificate import create_certificate
from agentcert.chain import update_certificate, revoke_certificate, verify_chain
from agentcert.types import CertType
from agentcert.exceptions import ChainError


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
        name="chain-agent", platform="pytest", model_hash="sha256:chain",
        capabilities=["read", "write"], constraints=["limit-100"],
        risk_tier=2, expires_days=60,
    )


class TestUpdateCertificate:
    def test_basic_update(self, cert, creator):
        updated = update_certificate(
            previous_cert=cert, creator_keys=creator,
            capabilities=["read", "write", "execute"],
        )
        assert updated.cert_type == CertType.UPDATE
        assert updated.previous_cert_id == cert.cert_id
        assert "execute" in updated.agent_metadata.capabilities

    def test_carries_over_unchanged_fields(self, cert, creator):
        updated = update_certificate(
            previous_cert=cert, creator_keys=creator,
            capabilities=["new"],
        )
        assert updated.agent_metadata.name == cert.agent_metadata.name
        assert updated.agent_metadata.platform == cert.agent_metadata.platform
        assert updated.agent_metadata.risk_tier == cert.agent_metadata.risk_tier
        assert updated.agent_metadata.constraints == cert.agent_metadata.constraints

    def test_same_agent_and_creator(self, cert, creator):
        updated = update_certificate(
            previous_cert=cert, creator_keys=creator, name="new-name",
        )
        assert updated.agent_public_key == cert.agent_public_key
        assert updated.agent_id == cert.agent_id
        assert updated.creator_public_key == cert.creator_public_key
        assert updated.creator_id == cert.creator_id

    def test_update_all_metadata_fields(self, cert, creator):
        updated = update_certificate(
            previous_cert=cert, creator_keys=creator,
            name="v2", platform="autogen", model_hash="sha256:v2",
            capabilities=["a"], constraints=["b"], risk_tier=5,
            expires_days=10,
        )
        assert updated.agent_metadata.name == "v2"
        assert updated.agent_metadata.platform == "autogen"
        assert updated.agent_metadata.model_hash == "sha256:v2"
        assert updated.agent_metadata.capabilities == ("a",)
        assert updated.agent_metadata.constraints == ("b",)
        assert updated.agent_metadata.risk_tier == 5

    def test_wrong_creator_raises(self, cert):
        other = generate_keys()
        with pytest.raises(ChainError, match="Creator key does not match"):
            update_certificate(previous_cert=cert, creator_keys=other, name="x")

    def test_update_revoked_raises(self, cert, creator):
        revoked = revoke_certificate(
            previous_cert=cert, creator_keys=creator, reason="done",
        )
        with pytest.raises(ChainError, match="Cannot update a revoked"):
            update_certificate(previous_cert=revoked, creator_keys=creator, name="x")

    def test_invalid_risk_tier_raises(self, cert, creator):
        with pytest.raises(ChainError, match="risk_tier"):
            update_certificate(previous_cert=cert, creator_keys=creator, risk_tier=0)

    def test_default_expires_preserves_duration(self, cert, creator):
        updated = update_certificate(previous_cert=cert, creator_keys=creator, name="v2")
        original_duration = cert.expires - cert.timestamp
        actual_duration = updated.expires - updated.timestamp
        assert actual_duration == original_duration


class TestRevokeCertificate:
    def test_basic_revocation(self, cert, creator):
        rev = revoke_certificate(
            previous_cert=cert, creator_keys=creator, reason="Done",
        )
        assert rev.cert_type == CertType.REVOCATION
        assert rev.previous_cert_id == cert.cert_id
        assert rev.revocation_reason == "Done"

    def test_wrong_creator_raises(self, cert):
        other = generate_keys()
        with pytest.raises(ChainError, match="Creator key does not match"):
            revoke_certificate(previous_cert=cert, creator_keys=other, reason="x")

    def test_double_revoke_raises(self, cert, creator):
        rev = revoke_certificate(previous_cert=cert, creator_keys=creator, reason="first")
        with pytest.raises(ChainError, match="already revoked"):
            revoke_certificate(previous_cert=rev, creator_keys=creator, reason="again")

    def test_empty_reason_raises(self, cert, creator):
        with pytest.raises(ChainError, match="Revocation reason"):
            revoke_certificate(previous_cert=cert, creator_keys=creator, reason="")

    def test_whitespace_reason_raises(self, cert, creator):
        with pytest.raises(ChainError, match="Revocation reason"):
            revoke_certificate(previous_cert=cert, creator_keys=creator, reason="   ")

    def test_preserves_metadata(self, cert, creator):
        rev = revoke_certificate(previous_cert=cert, creator_keys=creator, reason="x")
        assert rev.agent_metadata == cert.agent_metadata

    def test_revocation_reason_in_dict(self, cert, creator):
        rev = revoke_certificate(previous_cert=cert, creator_keys=creator, reason="bye")
        d = rev.to_dict()
        assert d["revocation_reason"] == "bye"


class TestVerifyChain:
    def test_single_cert(self, cert):
        result = verify_chain([cert])
        assert result.status == "ACTIVE"
        assert result.chain_length == 1
        assert all(c.passed for c in result.checks)

    def test_create_update_chain(self, cert, creator):
        updated = update_certificate(previous_cert=cert, creator_keys=creator, name="v2")
        result = verify_chain([cert, updated])
        assert result.status == "ACTIVE"
        assert result.valid

    def test_full_chain_revoked(self, cert, creator):
        updated = update_certificate(previous_cert=cert, creator_keys=creator, name="v2")
        rev = revoke_certificate(previous_cert=updated, creator_keys=creator, reason="done")
        result = verify_chain([cert, updated, rev])
        assert result.status == "REVOKED"
        assert result.valid

    def test_empty_chain(self):
        result = verify_chain([])
        assert result.status == "INVALID"
        assert result.chain_length == 0

    def test_broken_linkage(self, cert, creator):
        rev = revoke_certificate(previous_cert=cert, creator_keys=creator, reason="x")
        # Skip the middle — rev doesn't link to cert2
        cert2 = create_certificate(
            creator_keys=creator, agent_keys=generate_keys(),
            name="other", platform="t", model_hash="", capabilities=[], constraints=[],
            risk_tier=1, expires_days=1,
        )
        result = verify_chain([cert, cert2])
        assert result.status == "INVALID"

    def test_different_creator_fails(self, cert, creator, agent):
        other_creator = generate_keys()
        # Manually create a cert that claims to follow but has different creator
        other_cert = create_certificate(
            creator_keys=other_creator, agent_keys=agent,
            name="other", platform="t", model_hash="", capabilities=[], constraints=[],
            risk_tier=1, expires_days=1,
        )
        result = verify_chain([cert, other_cert])
        assert result.status == "INVALID"

    def test_first_not_creation_fails(self, cert, creator):
        updated = update_certificate(previous_cert=cert, creator_keys=creator, name="v2")
        result = verify_chain([updated])
        assert result.status == "INVALID"
