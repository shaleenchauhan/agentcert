"""Tests for agentcert.keys — key generation, saving, and loading."""

import json
import hashlib
from pathlib import Path

import pytest

from agentcert.keys import generate_keys, save_keys, load_keys
from agentcert.types import KeyPair
from agentcert.exceptions import KeyLoadError, SerializationError


class TestGenerateKeys:
    def test_returns_keypair(self):
        keys = generate_keys()
        assert isinstance(keys, KeyPair)

    def test_public_key_is_compressed(self):
        keys = generate_keys()
        assert len(keys.public_key_hex) == 66  # 33 bytes = 66 hex chars
        assert keys.public_key_hex[:2] in ("02", "03")  # compressed prefix

    def test_unique_keys(self):
        k1 = generate_keys()
        k2 = generate_keys()
        assert k1.public_key_hex != k2.public_key_hex

    def test_identity_is_sha256_of_pubkey(self):
        keys = generate_keys()
        expected = hashlib.sha256(keys.public_key_hex.encode("utf-8")).hexdigest()
        assert keys.identity == expected

    def test_identity_is_64_hex_chars(self):
        keys = generate_keys()
        assert len(keys.identity) == 64
        int(keys.identity, 16)  # should not raise


class TestSaveLoadKeys:
    def test_roundtrip(self, tmp_path):
        keys = generate_keys()
        path = tmp_path / "keys.json"
        save_keys(keys, path)
        loaded = load_keys(path)
        assert loaded.public_key_hex == keys.public_key_hex
        assert loaded.identity == keys.identity

    def test_file_is_valid_json(self, tmp_path):
        keys = generate_keys()
        path = tmp_path / "keys.json"
        save_keys(keys, path)
        data = json.loads(path.read_text())
        assert "private_key" in data
        assert "public_key" in data
        assert len(data["private_key"]) == 64  # 32 bytes hex
        assert data["public_key"] == keys.public_key_hex

    def test_load_nonexistent_file(self):
        with pytest.raises(KeyLoadError):
            load_keys("/nonexistent/path.json")

    def test_load_invalid_json(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("not json")
        with pytest.raises(KeyLoadError):
            load_keys(path)

    def test_load_tampered_public_key(self, tmp_path):
        keys = generate_keys()
        path = tmp_path / "keys.json"
        save_keys(keys, path)
        data = json.loads(path.read_text())
        data["public_key"] = "02" + "ff" * 32  # wrong public key
        path.write_text(json.dumps(data))
        with pytest.raises(KeyLoadError, match="does not match"):
            load_keys(path)

    def test_save_to_invalid_path(self):
        keys = generate_keys()
        with pytest.raises(SerializationError):
            save_keys(keys, "/nonexistent/dir/keys.json")
