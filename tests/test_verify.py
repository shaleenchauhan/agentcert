"""Tests for agentcert.verify — all 6 verification checks."""

import time

import pytest

from agentcert.keys import generate_keys
from agentcert.certificate import create_certificate
from agentcert.anchor import compute_anchor_hash, build_op_return_payload
from agentcert.verify import (
    verify,
    check_cert_id,
    check_creator_id,
    check_agent_id,
    check_signature,
    check_anchor,
    check_expiration,
)
from agentcert.types import AnchorReceipt, Certificate


@pytest.fixture
def creator():
    return generate_keys()


@pytest.fixture
def agent():
    return generate_keys()


@pytest.fixture
def now():
    return int(time.time())


@pytest.fixture
def cert(creator, agent, now):
    return create_certificate(
        creator_keys=creator, agent_keys=agent,
        name="verify-test", platform="pytest", model_hash="sha256:verify",
        capabilities=["a"], constraints=["b"],
        risk_tier=1, expires_days=30, timestamp=now,
    )


@pytest.fixture
def receipt(cert):
    return AnchorReceipt(
        txid="ab" * 32,
        network="testnet",
        anchor_hash=compute_anchor_hash(cert).hex(),
        op_return_hex=build_op_return_payload(cert).hex(),
        cert_id=cert.cert_id,
    )


class TestCheckCertId:
    def test_valid(self, cert):
        result = check_cert_id(cert)
        assert result.passed
        assert result.name == "cert_id_integrity"

    def test_tampered(self, cert):
        tampered = Certificate(
            ait_version=cert.ait_version, cert_type=cert.cert_type,
            cert_id="00" * 32,
            timestamp=cert.timestamp, expires=cert.expires,
            agent_public_key=cert.agent_public_key, agent_id=cert.agent_id,
            creator_public_key=cert.creator_public_key, creator_id=cert.creator_id,
            agent_metadata=cert.agent_metadata,
            previous_cert_id=cert.previous_cert_id,
            creator_signature=cert.creator_signature,
        )
        result = check_cert_id(tampered)
        assert not result.passed


class TestCheckCreatorId:
    def test_valid(self, cert):
        result = check_creator_id(cert)
        assert result.passed
        assert result.name == "creator_id_derivation"

    def test_tampered(self, cert):
        tampered = Certificate(
            ait_version=cert.ait_version, cert_type=cert.cert_type,
            cert_id=cert.cert_id,
            timestamp=cert.timestamp, expires=cert.expires,
            agent_public_key=cert.agent_public_key, agent_id=cert.agent_id,
            creator_public_key=cert.creator_public_key,
            creator_id="00" * 32,
            agent_metadata=cert.agent_metadata,
            previous_cert_id=cert.previous_cert_id,
            creator_signature=cert.creator_signature,
        )
        result = check_creator_id(tampered)
        assert not result.passed


class TestCheckAgentId:
    def test_valid(self, cert):
        result = check_agent_id(cert)
        assert result.passed
        assert result.name == "agent_id_derivation"

    def test_tampered(self, cert):
        tampered = Certificate(
            ait_version=cert.ait_version, cert_type=cert.cert_type,
            cert_id=cert.cert_id,
            timestamp=cert.timestamp, expires=cert.expires,
            agent_public_key=cert.agent_public_key,
            agent_id="00" * 32,
            creator_public_key=cert.creator_public_key, creator_id=cert.creator_id,
            agent_metadata=cert.agent_metadata,
            previous_cert_id=cert.previous_cert_id,
            creator_signature=cert.creator_signature,
        )
        result = check_agent_id(tampered)
        assert not result.passed


class TestCheckSignature:
    def test_valid(self, cert):
        result = check_signature(cert)
        assert result.passed
        assert result.name == "creator_signature"

    def test_invalid(self, cert):
        tampered = Certificate(
            ait_version=cert.ait_version, cert_type=cert.cert_type,
            cert_id=cert.cert_id,
            timestamp=cert.timestamp, expires=cert.expires,
            agent_public_key=cert.agent_public_key, agent_id=cert.agent_id,
            creator_public_key=cert.creator_public_key, creator_id=cert.creator_id,
            agent_metadata=cert.agent_metadata,
            previous_cert_id=cert.previous_cert_id,
            creator_signature="30" + "00" * 70,  # bogus DER
        )
        result = check_signature(tampered)
        assert not result.passed


class TestCheckAnchor:
    def test_valid(self, cert, receipt):
        result = check_anchor(cert, receipt)
        assert result.passed
        assert result.name == "anchor_integrity"

    def test_mismatched_hash(self, cert):
        bad_receipt = AnchorReceipt(
            txid="x", network="testnet",
            anchor_hash="ff" * 32,
            op_return_hex="", cert_id=cert.cert_id,
        )
        result = check_anchor(cert, bad_receipt)
        assert not result.passed


class TestCheckExpiration:
    def test_valid(self, cert, now):
        result = check_expiration(cert, now=now)
        assert result.passed
        assert "remaining" in result.detail

    def test_expired(self, cert, now):
        result = check_expiration(cert, now=now + 31 * 86400)
        assert not result.passed
        assert "expired" in result.detail

    def test_just_before_expiry(self, cert):
        result = check_expiration(cert, now=cert.expires - 1)
        assert result.passed

    def test_exactly_at_expiry(self, cert):
        result = check_expiration(cert, now=cert.expires)
        assert not result.passed


class TestVerifyFull:
    def test_valid_with_receipt(self, cert, receipt, now):
        result = verify(cert, receipt, now=now)
        assert result.status == "VALID"
        assert result.valid
        assert result.cert_id == cert.cert_id
        assert len(result.checks) == 6
        assert all(c.passed for c in result.checks)

    def test_valid_without_receipt(self, cert, now):
        result = verify(cert, now=now)
        assert result.status == "VALID"
        assert len(result.checks) == 6
        anchor_check = [c for c in result.checks if c.name == "anchor_integrity"][0]
        assert anchor_check.passed
        assert "skipped" in anchor_check.detail.lower()

    def test_invalid_expired(self, creator, agent):
        now = int(time.time())
        cert = create_certificate(
            creator_keys=creator, agent_keys=agent,
            name="old", platform="t", model_hash="", capabilities=[], constraints=[],
            risk_tier=1, expires_days=1, timestamp=now - 200000,
        )
        result = verify(cert, now=now)
        assert result.status == "INVALID"
        assert not result.valid

    def test_invalid_wrong_anchor(self, cert, now):
        bad_receipt = AnchorReceipt(
            txid="x", network="testnet",
            anchor_hash="ff" * 32,
            op_return_hex="", cert_id=cert.cert_id,
        )
        result = verify(cert, bad_receipt, now=now)
        assert result.status == "INVALID"

    def test_check_names(self, cert, receipt, now):
        result = verify(cert, receipt, now=now)
        names = [c.name for c in result.checks]
        assert names == [
            "cert_id_integrity",
            "creator_id_derivation",
            "agent_id_derivation",
            "creator_signature",
            "anchor_integrity",
            "expiration",
        ]
