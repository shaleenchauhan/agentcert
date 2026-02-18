"""Key generation, loading, and saving for secp256k1 key pairs."""

from __future__ import annotations

import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from agentcert.exceptions import KeyGenerationError, KeyLoadError, SerializationError
from agentcert.types import KeyPair


def generate_keys() -> KeyPair:
    """Generate a new secp256k1 key pair.

    Returns:
        A KeyPair containing the private key and compressed public key.

    Raises:
        KeyGenerationError: If key generation fails.
    """
    try:
        private_key = ec.generate_private_key(ec.SECP256K1())
        public_key_bytes = private_key.public_key().public_bytes(
            Encoding.X962, PublicFormat.CompressedPoint
        )
        public_key_hex = public_key_bytes.hex()
        return KeyPair(private_key=private_key, public_key_hex=public_key_hex)
    except Exception as exc:
        raise KeyGenerationError(f"Failed to generate secp256k1 key pair: {exc}") from exc


def save_keys(keys: KeyPair, path: str | Path) -> None:
    """Save a key pair to a JSON file.

    The private key is stored as a raw hex-encoded integer. The public key
    is stored as a compressed hex string.

    Args:
        keys: The key pair to save.
        path: File path to write to.

    Raises:
        SerializationError: If saving fails.
    """
    try:
        private_numbers = keys.private_key.private_numbers()
        private_key_hex = format(private_numbers.private_value, "064x")
        data = {
            "private_key": private_key_hex,
            "public_key": keys.public_key_hex,
        }
        Path(path).write_text(
            json.dumps(data, indent=2) + "\n", encoding="utf-8"
        )
    except Exception as exc:
        raise SerializationError(f"Failed to save keys to {path}: {exc}") from exc


def load_keys(path: str | Path) -> KeyPair:
    """Load a key pair from a JSON file.

    Args:
        path: File path to read from.

    Returns:
        The loaded KeyPair.

    Raises:
        KeyLoadError: If loading or parsing fails.
    """
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        private_value = int(data["private_key"], 16)
        private_key = ec.derive_private_key(private_value, ec.SECP256K1())
        public_key_bytes = private_key.public_key().public_bytes(
            Encoding.X962, PublicFormat.CompressedPoint
        )
        public_key_hex = public_key_bytes.hex()

        # Verify consistency: derived public key must match stored public key
        if public_key_hex != data["public_key"]:
            raise KeyLoadError(
                "Public key in file does not match the key derived from the private key"
            )

        return KeyPair(private_key=private_key, public_key_hex=public_key_hex)
    except KeyLoadError:
        raise
    except Exception as exc:
        raise KeyLoadError(f"Failed to load keys from {path}: {exc}") from exc
