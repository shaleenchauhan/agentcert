"""Integration tests — full lifecycle through the public API."""

import json
import subprocess
import sys
import time

import pytest

import agentcert


class TestFullLifecycle:
    """End-to-end: create → update → revoke → verify chain."""

    def test_lifecycle(self):
        now = int(time.time())

        # Generate keys
        creator = agentcert.generate_keys()
        agent = agentcert.generate_keys()

        # Create
        cert = agentcert.create_certificate(
            creator_keys=creator, agent_keys=agent,
            name="lifecycle-agent", platform="langchain",
            model_hash="sha256:lifecycle", capabilities=["a", "b"],
            constraints=["c"], risk_tier=3, expires_days=90, timestamp=now,
        )
        assert cert.cert_type == agentcert.CertType.CREATION
        assert cert.previous_cert_id is None

        # Verify creation
        result = agentcert.verify(cert, now=now)
        assert result.status == "VALID"

        # Update
        updated = agentcert.update_certificate(
            previous_cert=cert, creator_keys=creator,
            capabilities=["a", "b", "d"], risk_tier=4,
        )
        assert updated.cert_type == agentcert.CertType.UPDATE
        assert updated.previous_cert_id == cert.cert_id
        assert "d" in updated.agent_metadata.capabilities
        assert updated.agent_metadata.risk_tier == 4

        # Verify update
        result2 = agentcert.verify(updated, now=now)
        assert result2.status == "VALID"

        # Revoke
        revoked = agentcert.revoke_certificate(
            previous_cert=updated, creator_keys=creator,
            reason="Decommissioned",
        )
        assert revoked.cert_type == agentcert.CertType.REVOCATION
        assert revoked.revocation_reason == "Decommissioned"

        # Chain verify
        chain_result = agentcert.verify_chain([cert, updated, revoked])
        assert chain_result.status == "REVOKED"
        assert chain_result.valid
        assert chain_result.chain_length == 3
        assert all(c.passed for c in chain_result.checks)

    def test_anchor_payload_format(self):
        """Verify OP_RETURN payload matches the AIT-1 spec."""
        creator = agentcert.generate_keys()
        agent = agentcert.generate_keys()
        cert = agentcert.create_certificate(
            creator_keys=creator, agent_keys=agent,
            name="spec-test", platform="t", model_hash="",
            capabilities=[], constraints=[], risk_tier=1, expires_days=1,
        )

        payload = agentcert.build_op_return_payload(cert)
        assert len(payload) == 38
        assert payload[:4] == b"AIT\x00"
        assert payload[4] == 1   # version
        assert payload[5] == 2   # IDENTITY_CERT
        assert payload[6:] == agentcert.compute_anchor_hash(cert)

    def test_known_testnet_anchor_format(self):
        """Validate the known POC testnet anchor against our OP_RETURN format."""
        known_hex = "414954000102c971c18058c0c3126e2b4dc98da8069373810311a6baabe5e612a5d97da9cc84"
        known = bytes.fromhex(known_hex)
        assert known[:4] == b"AIT\x00"
        assert known[4] == 0x01
        assert known[5] == 0x02
        assert len(known) == 38


class TestFileRoundTrips:
    """Save/load round-trips for all artifact types."""

    def test_keys_roundtrip(self, tmp_path):
        keys = agentcert.generate_keys()
        path = tmp_path / "keys.json"
        agentcert.save_keys(keys, str(path))
        loaded = agentcert.load_keys(str(path))
        assert loaded.public_key_hex == keys.public_key_hex

    def test_certificate_roundtrip(self, tmp_path):
        creator = agentcert.generate_keys()
        agent = agentcert.generate_keys()
        cert = agentcert.create_certificate(
            creator_keys=creator, agent_keys=agent,
            name="rt", platform="t", model_hash="",
            capabilities=["x"], constraints=["y"],
            risk_tier=1, expires_days=1,
        )
        path = tmp_path / "cert.json"
        agentcert.save_certificate(cert, str(path))
        loaded = agentcert.load_certificate(str(path))
        assert loaded == cert

        # Verify loaded cert is still valid
        result = agentcert.verify(loaded)
        assert result.valid

    def test_receipt_roundtrip(self, tmp_path):
        receipt = agentcert.AnchorReceipt(
            txid="abc", network="testnet",
            anchor_hash="ff" * 32, op_return_hex="ee" * 19,
            cert_id="dd" * 32,
        )
        path = tmp_path / "receipt.json"
        agentcert.save_receipt(receipt, str(path))
        loaded = agentcert.load_receipt(str(path))
        assert loaded == receipt


class TestPublicAPICompleteness:
    """Verify all documented API symbols are accessible."""

    def test_all_exports(self):
        expected_functions = [
            "generate_keys", "save_keys", "load_keys",
            "create_certificate", "save_certificate", "load_certificate",
            "update_certificate", "revoke_certificate", "verify_chain",
            "anchor", "compute_anchor_hash", "build_op_return_payload",
            "derive_bitcoin_address", "save_receipt", "load_receipt",
            "verify",
        ]
        for name in expected_functions:
            assert hasattr(agentcert, name), f"Missing export: {name}"
            assert callable(getattr(agentcert, name))

    def test_all_types(self):
        expected_types = [
            "KeyPair", "Certificate", "AgentMetadata", "CertType",
            "AnchorReceipt", "VerificationResult", "VerificationCheck", "ChainResult",
        ]
        for name in expected_types:
            assert hasattr(agentcert, name), f"Missing type: {name}"

    def test_all_exceptions(self):
        expected = [
            "AgentCertError", "KeyGenerationError", "KeyLoadError",
            "CertificateError", "SignatureError", "AnchorError",
            "VerificationError", "ChainError", "SerializationError",
        ]
        for name in expected:
            cls = getattr(agentcert, name)
            assert issubclass(cls, agentcert.AgentCertError)

    def test_version(self):
        assert agentcert.__version__ == "0.1.0"


class TestCLI:
    """Smoke tests for the CLI entry point."""

    def test_help(self):
        result = subprocess.run(
            [sys.executable, "-m", "agentcert.cli", "--help"],
            capture_output=True, text=True,
        )
        # cli.py doesn't have __main__ — use the entry point script
        # Fall back to testing via click's test runner
        from click.testing import CliRunner
        from agentcert.cli import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "AgentCert" in result.output

    def test_version(self):
        from click.testing import CliRunner
        from agentcert.cli import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_keygen_create_verify(self, tmp_path):
        from click.testing import CliRunner
        from agentcert.cli import cli
        runner = CliRunner()

        ck = str(tmp_path / "ck.json")
        ak = str(tmp_path / "ak.json")
        cert_path = str(tmp_path / "cert.json")

        # keygen
        r1 = runner.invoke(cli, ["keygen", "-o", ck])
        assert r1.exit_code == 0, r1.output
        r2 = runner.invoke(cli, ["keygen", "-o", ak])
        assert r2.exit_code == 0, r2.output

        # create
        r3 = runner.invoke(cli, [
            "create",
            "--creator-keys", ck,
            "--agent-keys", ak,
            "--name", "cli-test",
            "--platform", "pytest",
            "--capabilities", "a,b",
            "--constraints", "c",
            "--risk-tier", "2",
            "--expires", "30d",
            "-o", cert_path,
        ])
        assert r3.exit_code == 0, r3.output

        # verify
        r4 = runner.invoke(cli, ["verify", cert_path])
        assert r4.exit_code == 0, r4.output
        assert "VALID" in r4.output

        # inspect
        r5 = runner.invoke(cli, ["inspect", cert_path])
        assert r5.exit_code == 0, r5.output
        assert "cli-test" in r5.output

    def test_update_revoke_chain(self, tmp_path):
        from click.testing import CliRunner
        from agentcert.cli import cli
        runner = CliRunner()

        ck = str(tmp_path / "ck.json")
        ak = str(tmp_path / "ak.json")
        v1 = str(tmp_path / "v1.json")
        v2 = str(tmp_path / "v2.json")
        rev = str(tmp_path / "rev.json")

        runner.invoke(cli, ["keygen", "-o", ck])
        runner.invoke(cli, ["keygen", "-o", ak])
        runner.invoke(cli, [
            "create", "--creator-keys", ck, "--agent-keys", ak,
            "--name", "t", "--platform", "t", "--risk-tier", "1",
            "--expires", "30d", "-o", v1,
        ])

        # update
        r1 = runner.invoke(cli, [
            "update", v1, "--creator-keys", ck,
            "--add-capability", "new-cap", "-o", v2,
        ])
        assert r1.exit_code == 0, r1.output

        # revoke
        r2 = runner.invoke(cli, [
            "revoke", v2, "--creator-keys", ck,
            "--reason", "Done", "-o", rev,
        ])
        assert r2.exit_code == 0, r2.output

        # verify-chain
        r3 = runner.invoke(cli, ["verify-chain", v1, v2, rev])
        assert r3.exit_code == 0, r3.output
        assert "REVOKED" in r3.output
