"""Tests for TrustVerifier and TrustResult."""

from __future__ import annotations

import pytest

import agentcert
from agentcert.types import Certificate, KeyPair

from agentcert_middleware.trust import TrustResult, TrustVerifier


class TestTrustResult:
    """Tests for the TrustResult dataclass."""

    def test_frozen(self):
        """TrustResult is frozen (immutable)."""
        result = TrustResult(
            valid=True,
            signature_valid=True,
            chain_valid=True,
            revocation_status="unknown",
            revocation_checked=False,
        )
        with pytest.raises(AttributeError):
            result.valid = False  # type: ignore[misc]

    def test_defaults(self):
        """TrustResult defaults to empty details dict."""
        result = TrustResult(
            valid=True,
            signature_valid=True,
            chain_valid=True,
            revocation_status="unknown",
            revocation_checked=False,
        )
        assert result.details == {}


class TestTrustVerifier:
    """Tests for TrustVerifier."""

    def test_valid_certificate(self, certificate: Certificate):
        """verify_peer returns valid=True for a properly signed certificate."""
        verifier = TrustVerifier()
        result = verifier.verify_peer(certificate)

        assert result.valid is True
        assert result.signature_valid is True
        assert result.chain_valid is True

    def test_revocation_status_unknown(self, certificate: Certificate):
        """Revocation status is 'unknown' and revocation_checked is False (stub)."""
        verifier = TrustVerifier()
        result = verifier.verify_peer(certificate)

        assert result.revocation_status == "unknown"
        assert result.revocation_checked is False

    def test_revocation_stub_note_in_details(self, certificate: Certificate):
        """Details contain a note about the revocation stub."""
        verifier = TrustVerifier()
        result = verifier.verify_peer(certificate)

        assert "note" in result.details
        assert "stubbed" in result.details["note"]

    def test_invalid_certificate_signature(self, creator_keys, agent_keys):
        """verify_peer returns valid=False for a tampered certificate."""
        cert = agentcert.create_certificate(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            name="test",
            platform="test",
            model_hash="sha256:test",
            capabilities=["test"],
            constraints=[],
            risk_tier=3,
            expires_days=90,
        )

        # Tamper with the certificate by changing the signature
        tampered = Certificate(
            ait_version=cert.ait_version,
            cert_type=cert.cert_type,
            cert_id=cert.cert_id,
            timestamp=cert.timestamp,
            expires=cert.expires,
            agent_public_key=cert.agent_public_key,
            agent_id=cert.agent_id,
            creator_public_key=cert.creator_public_key,
            creator_id=cert.creator_id,
            agent_metadata=cert.agent_metadata,
            previous_cert_id=cert.previous_cert_id,
            creator_signature="00" * 64,  # Invalid signature
        )

        verifier = TrustVerifier()
        result = verifier.verify_peer(tampered)

        assert result.valid is False
        assert result.signature_valid is False

    def test_without_service_url(self, certificate: Certificate):
        """TrustVerifier works without service_url (local-only mode)."""
        verifier = TrustVerifier()
        assert verifier.service_url is None
        assert verifier._client is None

        result = verifier.verify_peer(certificate)
        assert result.valid is True

    def test_with_service_url(self, certificate: Certificate):
        """TrustVerifier creates client when service_url is provided."""
        verifier = TrustVerifier(service_url="http://localhost:8932")
        assert verifier.service_url == "http://localhost:8932"
        assert verifier._client is not None

        # Verification still works (local math only, no service call for revocation)
        result = verifier.verify_peer(certificate)
        assert result.valid is True

    def test_expired_certificate(self, creator_keys, agent_keys):
        """verify_peer returns valid=False for an expired certificate."""
        cert = agentcert.create_certificate(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            name="expired",
            platform="test",
            model_hash="sha256:test",
            capabilities=[],
            constraints=[],
            risk_tier=1,
            expires_days=1,
            timestamp=1000000,  # Very old timestamp
        )

        verifier = TrustVerifier()
        result = verifier.verify_peer(cert)

        # Should be invalid because it's expired
        assert result.valid is False
