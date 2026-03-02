"""Tests for CoordinatorIdentity."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

import agentcert
from agentcert.types import KeyPair

from agentcert_middleware.coordinator import CoordinatorIdentity


class TestCoordinatorIdentity:
    """Tests for CoordinatorIdentity.get_or_create."""

    def test_auto_generate(self, creator_keys: KeyPair, tmp_storage_dir: str):
        """Auto-generates keys + cert and saves to disk."""
        coord_keys, coord_cert = CoordinatorIdentity.get_or_create(
            creator_keys=creator_keys,
            coordinator_name="test-coordinator",
            storage_dir=tmp_storage_dir,
        )

        assert coord_keys is not None
        assert coord_cert is not None
        assert coord_cert.agent_metadata.name == "test-coordinator"
        assert coord_cert.agent_metadata.platform == "coordinator"
        assert "orchestration" in coord_cert.agent_metadata.capabilities
        assert "task_delegation" in coord_cert.agent_metadata.capabilities

        # Files should be persisted
        coord_dir = Path(tmp_storage_dir) / "test-coordinator"
        assert (coord_dir / "keys.json").exists()
        assert (coord_dir / "cert.json").exists()

    def test_persist_and_reload(self, creator_keys: KeyPair, tmp_storage_dir: str):
        """Second call returns the same keys from disk."""
        keys1, cert1 = CoordinatorIdentity.get_or_create(
            creator_keys=creator_keys,
            coordinator_name="test-coordinator",
            storage_dir=tmp_storage_dir,
        )

        keys2, cert2 = CoordinatorIdentity.get_or_create(
            creator_keys=creator_keys,
            coordinator_name="test-coordinator",
            storage_dir=tmp_storage_dir,
        )

        # Same keys should be loaded
        assert keys1.public_key_hex == keys2.public_key_hex
        assert cert1.cert_id == cert2.cert_id

    def test_explicit_override(self, creator_keys: KeyPair, tmp_storage_dir: str):
        """Uses provided keys when explicit_keys is given."""
        explicit = agentcert.generate_keys()
        coord_keys, coord_cert = CoordinatorIdentity.get_or_create(
            creator_keys=creator_keys,
            coordinator_name="test-coordinator",
            storage_dir=tmp_storage_dir,
            explicit_keys=explicit,
        )

        assert coord_keys.public_key_hex == explicit.public_key_hex
        assert coord_cert.agent_public_key == explicit.public_key_hex

        # Should NOT save to disk when using explicit keys
        coord_dir = Path(tmp_storage_dir) / "test-coordinator"
        assert not (coord_dir / "keys.json").exists()

    def test_explicit_override_ignores_disk(
        self, creator_keys: KeyPair, tmp_storage_dir: str
    ):
        """Explicit keys take priority even when keys exist on disk."""
        # First: auto-generate and save to disk
        keys1, cert1 = CoordinatorIdentity.get_or_create(
            creator_keys=creator_keys,
            coordinator_name="test-coordinator",
            storage_dir=tmp_storage_dir,
        )

        # Second: explicit override — should use explicit, not disk
        explicit = agentcert.generate_keys()
        keys2, cert2 = CoordinatorIdentity.get_or_create(
            creator_keys=creator_keys,
            coordinator_name="test-coordinator",
            storage_dir=tmp_storage_dir,
            explicit_keys=explicit,
        )

        assert keys2.public_key_hex == explicit.public_key_hex
        assert keys2.public_key_hex != keys1.public_key_hex

    def test_directory_creation(self, creator_keys: KeyPair, tmp_path):
        """Works even if the storage directory doesn't exist yet."""
        deep_dir = str(tmp_path / "deep" / "nested" / "dir")
        assert not os.path.exists(deep_dir)

        coord_keys, coord_cert = CoordinatorIdentity.get_or_create(
            creator_keys=creator_keys,
            coordinator_name="coord",
            storage_dir=deep_dir,
        )

        assert coord_keys is not None
        assert (Path(deep_dir) / "coord" / "keys.json").exists()

    def test_custom_capabilities(self, creator_keys: KeyPair, tmp_storage_dir: str):
        """Custom capabilities are set on the certificate."""
        coord_keys, coord_cert = CoordinatorIdentity.get_or_create(
            creator_keys=creator_keys,
            coordinator_name="custom-coord",
            storage_dir=tmp_storage_dir,
            capabilities=["custom_cap"],
            constraints=["custom_constraint"],
            risk_tier=1,
        )

        assert "custom_cap" in coord_cert.agent_metadata.capabilities
        assert "custom_constraint" in coord_cert.agent_metadata.constraints
        assert coord_cert.agent_metadata.risk_tier == 1

    def test_creator_keys_from_path(self, creator_keys: KeyPair, tmp_storage_dir: str):
        """Accepts creator_keys as a file path."""
        keys_path = os.path.join(tmp_storage_dir, "creator_keys.json")
        os.makedirs(tmp_storage_dir, exist_ok=True)
        agentcert.save_keys(creator_keys, keys_path)

        coord_keys, coord_cert = CoordinatorIdentity.get_or_create(
            creator_keys=keys_path,
            coordinator_name="from-path",
            storage_dir=tmp_storage_dir,
        )

        assert coord_cert is not None
        assert coord_cert.creator_public_key == creator_keys.public_key_hex

    def test_explicit_keys_from_path(
        self, creator_keys: KeyPair, tmp_storage_dir: str
    ):
        """Accepts explicit_keys as a file path."""
        explicit = agentcert.generate_keys()
        keys_path = os.path.join(tmp_storage_dir, "explicit_keys.json")
        os.makedirs(tmp_storage_dir, exist_ok=True)
        agentcert.save_keys(explicit, keys_path)

        coord_keys, coord_cert = CoordinatorIdentity.get_or_create(
            creator_keys=creator_keys,
            coordinator_name="from-path",
            storage_dir=tmp_storage_dir,
            explicit_keys=keys_path,
        )

        assert coord_keys.public_key_hex == explicit.public_key_hex
