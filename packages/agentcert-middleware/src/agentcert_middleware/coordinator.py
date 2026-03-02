"""Coordinator identity management for multi-agent crews and teams."""

from __future__ import annotations

import os

import agentcert
from agentcert.types import Certificate, KeyPair


class CoordinatorIdentity:
    """Manages auto-generated coordinator identity for crews/teams.

    Three-tier strategy (Decision D043):
        1. If explicit_keys provided — use those (power user override)
        2. If keys exist at ``{storage_dir}/{coordinator_name}/keys.json`` — load and reuse
        3. Else — generate new keys, create certificate, save to storage_dir

    The coordinator is a specialized agent — a "coordinator agent" (Decision D046).
    Uses the existing Certificate schema, no new types needed.
    """

    @staticmethod
    def get_or_create(
        creator_keys: KeyPair | str,
        coordinator_name: str,
        storage_dir: str,
        explicit_keys: KeyPair | str | None = None,
        capabilities: list[str] | None = None,
        constraints: list[str] | None = None,
        risk_tier: int = 2,
        expires_days: int = 90,
    ) -> tuple[KeyPair, Certificate]:
        """Get or create a coordinator identity.

        Returns ``(coordinator_keys, coordinator_certificate)``.

        Directory structure when auto-generated::

            {storage_dir}/{coordinator_name}/keys.json     — persisted keys
            {storage_dir}/{coordinator_name}/cert.json     — certificate

        Args:
            creator_keys: Creator's key pair or path to keys file.
            coordinator_name: Human-readable coordinator name.
            storage_dir: Base directory for coordinator identity files.
            explicit_keys: Optional key pair or path — power user override.
            capabilities: Coordinator capabilities (default: orchestration, task_delegation).
            constraints: Coordinator constraints (default: empty).
            risk_tier: Risk tier for the coordinator certificate (1-5).
            expires_days: Certificate validity period in days.

        Returns:
            Tuple of (KeyPair, Certificate) for the coordinator.
        """
        if capabilities is None:
            capabilities = ["orchestration", "task_delegation"]

        # Load creator keys if path
        if isinstance(creator_keys, str):
            creator_keys = agentcert.load_keys(creator_keys)

        # Path 1: Explicit override
        if explicit_keys is not None:
            if isinstance(explicit_keys, str):
                explicit_keys = agentcert.load_keys(explicit_keys)
            cert = agentcert.create_certificate(
                creator_keys=creator_keys,
                agent_keys=explicit_keys,
                name=coordinator_name,
                platform="coordinator",
                model_hash="coordinator",
                capabilities=capabilities,
                constraints=constraints or [],
                risk_tier=risk_tier,
                expires_days=expires_days,
            )
            return (explicit_keys, cert)

        # Path 2: Load from disk
        coord_dir = os.path.join(storage_dir, coordinator_name)
        keys_path = os.path.join(coord_dir, "keys.json")
        cert_path = os.path.join(coord_dir, "cert.json")

        if os.path.exists(keys_path) and os.path.exists(cert_path):
            coord_keys = agentcert.load_keys(keys_path)
            cert = agentcert.load_certificate(cert_path)
            return (coord_keys, cert)

        # Path 3: Generate new
        coord_keys = agentcert.generate_keys()
        cert = agentcert.create_certificate(
            creator_keys=creator_keys,
            agent_keys=coord_keys,
            name=coordinator_name,
            platform="coordinator",
            model_hash="coordinator",
            capabilities=capabilities,
            constraints=constraints or [],
            risk_tier=risk_tier,
            expires_days=expires_days,
        )

        # Persist
        os.makedirs(coord_dir, exist_ok=True)
        agentcert.save_keys(coord_keys, keys_path)
        agentcert.save_certificate(cert, cert_path)

        return (coord_keys, cert)
