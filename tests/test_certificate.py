"""Tests for agentcert.certificate — creation, signing, and serialization."""

import hashlib
import json
import time

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

from agentcert.keys import generate_keys
from agentcert.certificate import create_certificate, save_certificate, load_certificate
from agentcert.types import Certificate, CertType, AgentMetadata
from agentcert.exceptions import CertificateError, SerializationError


@pytest.fixture
def keypairs():
    return generate_keys(), generate_keys()


@pytest.fixture
def cert(keypairs):
    creator, agent = keypairs
    return create_certificate(
        creator_keys=creator,
        agent_keys=agent,
        name="test-agent",
        platform="pytest",
        model_hash="sha256:test123",
        capabilities=["cap-a", "cap-b"],
        constraints=["con-x"],
        risk_tier=2,
        expires_days=30,
    )


class TestCreateCertificate:
    def test_returns_certificate(self, cert):
        assert isinstance(cert, Certificate)

    def test_cert_type_is_creation(self, cert):
        assert cert.cert_type == CertType.CREATION

    def test_ait_version(self, cert):
        assert cert.ait_version == 1

    def test_previous_cert_id_is_none(self, cert):
        assert cert.previous_cert_id is None

    def test_metadata_preserved(self, cert):
        assert cert.agent_metadata.name == "test-agent"
        assert cert.agent_metadata.platform == "pytest"
        assert cert.agent_metadata.model_hash == "sha256:test123"
        assert cert.agent_metadata.capabilities == ("cap-a", "cap-b")
        assert cert.agent_metadata.constraints == ("con-x",)
        assert cert.agent_metadata.risk_tier == 2

    def test_keys_embedded(self, keypairs, cert):
        creator, agent = keypairs
        assert cert.creator_public_key == creator.public_key_hex
        assert cert.agent_public_key == agent.public_key_hex
        assert cert.creator_id == creator.identity
        assert cert.agent_id == agent.identity

    def test_timestamp_and_expires(self, keypairs):
        creator, agent = keypairs
        now = int(time.time())
        cert = create_certificate(
            creator_keys=creator, agent_keys=agent,
            name="t", platform="t", model_hash="", capabilities=[], constraints=[],
            risk_tier=1, expires_days=10, timestamp=now,
        )
        assert cert.timestamp == now
        assert cert.expires == now + 10 * 86400

    def test_custom_timestamp(self, keypairs):
        creator, agent = keypairs
        cert = create_certificate(
            creator_keys=creator, agent_keys=agent,
            name="t", platform="t", model_hash="", capabilities=[], constraints=[],
            risk_tier=1, expires_days=1, timestamp=1000000,
        )
        assert cert.timestamp == 1000000


class TestCertIdIntegrity:
    def test_cert_id_matches_body_hash(self, cert):
        body_bytes = cert.body_bytes()
        expected = hashlib.sha256(body_bytes).hexdigest()
        assert cert.cert_id == expected

    def test_cert_id_is_64_hex_chars(self, cert):
        assert len(cert.cert_id) == 64
        int(cert.cert_id, 16)


class TestSignature:
    def test_signature_verifies(self, cert):
        pub_key_bytes = bytes.fromhex(cert.creator_public_key)
        pub_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256K1(), pub_key_bytes
        )
        sig_bytes = bytes.fromhex(cert.creator_signature)
        body_bytes = cert.body_bytes()
        # Should not raise
        pub_key.verify(sig_bytes, body_bytes, ec.ECDSA(hashes.SHA256()))

    def test_signature_is_hex(self, cert):
        bytes.fromhex(cert.creator_signature)  # should not raise


class TestSerialization:
    def test_dict_roundtrip(self, cert):
        d = cert.to_dict()
        restored = Certificate.from_dict(d)
        assert restored == cert

    def test_canonical_bytes_deterministic(self, cert):
        b1 = cert.canonical_bytes()
        b2 = cert.canonical_bytes()
        assert b1 == b2

    def test_body_dict_excludes_cert_id_and_signature(self, cert):
        body = cert.body_dict()
        assert "cert_id" not in body
        assert "creator_signature" not in body

    def test_to_dict_matches_spec_keys(self, cert):
        d = cert.to_dict()
        expected_keys = {
            "ait_version", "cert_type", "cert_id", "timestamp", "expires",
            "agent_public_key", "agent_id", "creator_public_key", "creator_id",
            "agent_metadata", "previous_cert_id", "creator_signature",
        }
        assert set(d.keys()) == expected_keys

    def test_file_roundtrip(self, cert, tmp_path):
        path = tmp_path / "cert.json"
        save_certificate(cert, path)
        loaded = load_certificate(path)
        assert loaded == cert

    def test_load_nonexistent(self):
        with pytest.raises(SerializationError):
            load_certificate("/nonexistent.json")


class TestValidation:
    def test_risk_tier_too_low(self, keypairs):
        creator, agent = keypairs
        with pytest.raises(CertificateError, match="risk_tier"):
            create_certificate(
                creator_keys=creator, agent_keys=agent,
                name="t", platform="t", model_hash="", capabilities=[], constraints=[],
                risk_tier=0, expires_days=1,
            )

    def test_risk_tier_too_high(self, keypairs):
        creator, agent = keypairs
        with pytest.raises(CertificateError, match="risk_tier"):
            create_certificate(
                creator_keys=creator, agent_keys=agent,
                name="t", platform="t", model_hash="", capabilities=[], constraints=[],
                risk_tier=6, expires_days=1,
            )

    def test_expires_days_zero(self, keypairs):
        creator, agent = keypairs
        with pytest.raises(CertificateError, match="expires_days"):
            create_certificate(
                creator_keys=creator, agent_keys=agent,
                name="t", platform="t", model_hash="", capabilities=[], constraints=[],
                risk_tier=1, expires_days=0,
            )

    def test_expires_days_negative(self, keypairs):
        creator, agent = keypairs
        with pytest.raises(CertificateError, match="expires_days"):
            create_certificate(
                creator_keys=creator, agent_keys=agent,
                name="t", platform="t", model_hash="", capabilities=[], constraints=[],
                risk_tier=1, expires_days=-5,
            )
