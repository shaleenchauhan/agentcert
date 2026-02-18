"""Service configuration for the AgentCert anchoring service."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from agentcert.exceptions import ServiceError


@dataclass
class ServiceConfig:
    """Configuration for the AgentCert anchoring service.

    Attributes:
        db_path: Path to the SQLite database file.
        batch_interval_seconds: Seconds between automatic batch cycles.
        batch_min_entries: Minimum entries required to create a batch.
        batch_max_entries: Maximum entries per batch.
        network: Bitcoin network ("testnet" or "mainnet").
        anchor_wallet_key: Path to wallet key file, or None to skip anchoring.
        host: Server host address.
        port: Server port.
    """

    db_path: str = "./agentcert-service/agentcert.db"
    batch_interval_seconds: int = 600
    batch_min_entries: int = 1
    batch_max_entries: int = 10000
    network: str = "testnet"
    anchor_wallet_key: str | None = None
    host: str = "0.0.0.0"
    port: int = 8932

    @classmethod
    def from_env(cls) -> ServiceConfig:
        """Load config from environment variables.

        Environment variables (all optional):
            AGENTCERT_DB_PATH: Database file path.
            AGENTCERT_BATCH_INTERVAL: Seconds between batch cycles.
            AGENTCERT_BATCH_MIN: Minimum entries per batch.
            AGENTCERT_BATCH_MAX: Maximum entries per batch.
            AGENTCERT_NETWORK: Bitcoin network.
            AGENTCERT_WALLET_KEY: Path to wallet key file.
            AGENTCERT_HOST: Server host.
            AGENTCERT_PORT: Server port.

        Returns:
            A ServiceConfig populated from environment variables.
        """
        kwargs: dict = {}

        if val := os.environ.get("AGENTCERT_DB_PATH"):
            kwargs["db_path"] = val
        if val := os.environ.get("AGENTCERT_BATCH_INTERVAL"):
            kwargs["batch_interval_seconds"] = int(val)
        if val := os.environ.get("AGENTCERT_BATCH_MIN"):
            kwargs["batch_min_entries"] = int(val)
        if val := os.environ.get("AGENTCERT_BATCH_MAX"):
            kwargs["batch_max_entries"] = int(val)
        if val := os.environ.get("AGENTCERT_NETWORK"):
            kwargs["network"] = val
        if val := os.environ.get("AGENTCERT_WALLET_KEY"):
            kwargs["anchor_wallet_key"] = val
        if val := os.environ.get("AGENTCERT_HOST"):
            kwargs["host"] = val
        if val := os.environ.get("AGENTCERT_PORT"):
            kwargs["port"] = int(val)

        return cls(**kwargs)

    @classmethod
    def from_file(cls, path: str) -> ServiceConfig:
        """Load config from a JSON file.

        The JSON file should have keys matching the dataclass field names.
        Unknown keys are ignored.

        Args:
            path: Path to the JSON config file.

        Returns:
            A ServiceConfig populated from the file.

        Raises:
            ServiceError: If the file cannot be read or parsed.
        """
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except Exception as exc:
            raise ServiceError(f"Failed to load config from {path}: {exc}") from exc

        valid_keys = {f.name for f in cls.__dataclass_fields__.values()}
        kwargs = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**kwargs)
