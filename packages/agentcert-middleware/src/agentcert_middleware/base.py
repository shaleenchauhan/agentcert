"""Base middleware shared by all framework-specific integrations."""

from __future__ import annotations

import hashlib
import logging
from typing import TYPE_CHECKING

import agentcert
from agentcert.audit import AuditTrail, create_audit_trail, log_action
from agentcert.audit_verify import verify_audit_trail
from agentcert.types import ActionType, AuditEntry, Certificate, KeyPair

from agentcert_middleware.retry import RetryPolicy
from agentcert_middleware.storage import LocalStorage, StorageBackend, create_storage
from agentcert_middleware.trust import TrustVerifier

if TYPE_CHECKING:
    from agentcert.types import AuditTrailVerificationResult

logger = logging.getLogger("agentcert.middleware")


class BaseMiddleware:
    """Shared base for all framework-specific middleware.

    Covers Protocol Roles:
        - Role 1 (Identity): Creates certificate at init from provided keys
        - Role 2 (Observer): Subclasses implement framework-specific hooks
          that call ``_log_action()``
        - Role 3 (Persistence): Storage backends handle local/service/both
        - Role 4 (Trust): TrustVerifier available via ``get_trust_verifier()``

    Non-interference principle (Decision D044):
        - ``_log_action()`` NEVER raises exceptions to the caller
        - ``persist_entry()`` failures are caught, logged, and entries buffered
        - Only ``save()`` can raise exceptions (developer's explicit call)

    Args:
        creator_keys: Path to creator keys file or KeyPair object.
        agent_keys: Path to agent keys file or KeyPair object.
        agent_name: Human-readable agent name.
        capabilities: Agent capabilities for the certificate.
        constraints: Agent constraints for the certificate.
        risk_tier: Risk tier for the certificate (1-5).
        log_level: Logging detail level — ``"minimal"``, ``"standard"``,
            or ``"verbose"``.
        storage: Storage mode — ``"local"``, ``"service"``, or ``"both"``.
        storage_dir: Base directory for local audit storage.
        service_url: URL of the AgentCert managed service.
        api_key: Optional API key for service authentication.
        auto_save: Whether to persist entries automatically.
        auto_save_interval: Persist every N entries when auto_save is True.
        retry_attempts: Max retry attempts for service submissions.
        retry_backoff: Backoff multiplier for retries.
        model_hash: Hash of the model weights or code.
        platform: Platform or framework name for the certificate.
        expires_days: Certificate validity period in days.
    """

    def __init__(
        self,
        creator_keys: str | KeyPair,
        agent_keys: str | KeyPair,
        agent_name: str,
        capabilities: list[str] | None = None,
        constraints: list[str] | None = None,
        risk_tier: int = 3,
        log_level: str = "standard",
        storage: str = "local",
        storage_dir: str = "./agentcert-audit/",
        service_url: str | None = None,
        api_key: str | None = None,
        auto_save: bool = False,
        auto_save_interval: int = 1,
        retry_attempts: int = 3,
        retry_backoff: float = 2.0,
        model_hash: str = "unknown",
        platform: str = "middleware",
        expires_days: int = 90,
    ) -> None:
        """Initialize middleware.

        Steps:
            1. Load keys (from file path or KeyPair object)
            2. Create certificate via ``agentcert.create_certificate()``
            3. Create audit trail via ``create_audit_trail()``
            4. Initialize storage backend via ``create_storage()``
            5. Initialize TrustVerifier if service_url provided
            6. If storage is ``"service"`` or ``"both"``, register cert
               with service (best-effort)
        """
        # Load keys
        if isinstance(creator_keys, str):
            creator_keys = agentcert.load_keys(creator_keys)
        if isinstance(agent_keys, str):
            agent_keys = agentcert.load_keys(agent_keys)

        self._creator_keys = creator_keys
        self._agent_keys = agent_keys
        self._agent_name = agent_name
        self._log_level = log_level
        self._auto_save = auto_save
        self._auto_save_interval = auto_save_interval
        self._entries_since_save = 0

        # Role 1: Create certificate
        self._certificate = agentcert.create_certificate(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            name=agent_name,
            platform=platform,
            model_hash=model_hash,
            capabilities=capabilities or [],
            constraints=constraints or [],
            risk_tier=risk_tier,
            expires_days=expires_days,
        )

        # Create audit trail
        self._trail = create_audit_trail(self._certificate, agent_keys)

        # Initialize storage
        retry_policy = RetryPolicy(
            max_attempts=retry_attempts, backoff_multiplier=retry_backoff
        )
        self._storage: StorageBackend = create_storage(
            storage=storage,
            storage_dir=storage_dir,
            agent_name=agent_name,
            service_url=service_url,
            api_key=api_key,
            retry_policy=retry_policy,
        )
        self._storage_mode = storage
        self._storage_dir = storage_dir

        # Role 4: Trust verifier
        self._trust_verifier = TrustVerifier(
            service_url=service_url, api_key=api_key
        )

        # Register cert with service (best-effort, non-interfering)
        if storage in ("service", "both") and service_url:
            try:
                self._storage.persist_trail(self._trail, self._certificate)
            except Exception as e:
                logger.warning("Failed to register certificate with service: %s", e)

    def _log_action(
        self,
        action_type: ActionType | int,
        action_summary: str,
        action_detail: dict | None = None,
        action_detail_hash: str | None = None,
    ) -> AuditEntry | None:
        """Create a signed audit entry and persist via storage backend.

        Called by framework-specific subclasses (NOT directly by users).

        NON-INTERFERING: This method NEVER raises exceptions.
        If persistence fails, the entry stays in the in-memory trail
        and is buffered for retry.

        Args:
            action_type: ActionType enum value or int.
            action_summary: Brief human-readable description.
            action_detail: Structured action details dict.
            action_detail_hash: Pre-computed SHA-256 hash of action detail.

        Returns:
            The created AuditEntry, or None if creation failed.
        """
        try:
            # Build detail dict
            detail: dict = {}
            if action_detail is not None:
                detail = action_detail
            if action_detail_hash:
                detail["detail_hash"] = action_detail_hash
            elif action_detail is not None and not action_detail_hash:
                import json

                detail_json = json.dumps(
                    action_detail, sort_keys=True, separators=(",", ":")
                )
                detail["detail_hash"] = hashlib.sha256(
                    detail_json.encode()
                ).hexdigest()

            entry = log_action(
                trail=self._trail,
                agent_keys=self._agent_keys,
                action_type=action_type,
                action_summary=action_summary,
                action_detail=detail if detail else None,
            )

            # Auto-save if configured
            if self._auto_save:
                self._entries_since_save += 1
                if self._entries_since_save >= self._auto_save_interval:
                    try:
                        self._storage.persist_entry(
                            entry, self._trail, self._certificate
                        )
                        self._entries_since_save = 0
                    except Exception as e:
                        logger.warning("Auto-save failed (entry buffered): %s", e)

            return entry

        except Exception as e:
            logger.error("Failed to create audit entry: %s", e)
            return None

    def verify(self) -> AuditTrailVerificationResult:
        """Verify audit trail integrity (11 checks, local math).

        Returns:
            AuditTrailVerificationResult from ``agentcert.audit_verify.verify_audit_trail()``.
        """
        return verify_audit_trail(self._trail, self._certificate)

    def save(self, directory: str | None = None) -> None:
        """Final flush — persist all entries to all backends.

        Unlike ``_log_action()``, this CAN raise exceptions.
        This is the developer's explicit "I want to persist now" call.

        Args:
            directory: Optional override directory for this save.
        """
        if directory:
            local = LocalStorage(directory, self._agent_name)
            local.persist_trail(self._trail, self._certificate)
        else:
            self._storage.persist_trail(self._trail, self._certificate)

    @classmethod
    def load(
        cls, directory: str, agent_keys: str | KeyPair, creator_keys: str | KeyPair | None = None
    ) -> BaseMiddleware:
        """Reload middleware from saved state.

        Loads certificate and trail from ``{directory}/{agent_name}/``.
        Continues appending to the existing trail.

        Args:
            directory: Path to the saved state directory.
            agent_keys: Agent key pair or path to keys file.
            creator_keys: Creator key pair or path (optional).

        Raises:
            NotImplementedError: Resume support not yet implemented.
        """
        raise NotImplementedError(
            "load() will be implemented when resume support is needed"
        )

    def get_entries(self, action_type: ActionType | int | None = None) -> list[AuditEntry]:
        """Get logged entries, optionally filtered by ActionType.

        Args:
            action_type: Filter by this action type (optional).

        Returns:
            List of matching AuditEntry objects.
        """
        entries = self._trail.entries
        if action_type is not None:
            action_int = int(action_type)
            return [e for e in entries if e.action_type == action_int]
        return list(entries)

    def get_trust_verifier(self) -> TrustVerifier:
        """Get the TrustVerifier for creating framework-specific verification tools.

        Returns:
            The configured TrustVerifier instance.
        """
        return self._trust_verifier

    @property
    def certificate(self) -> Certificate:
        """The agent's certificate."""
        return self._certificate

    @property
    def trail(self) -> AuditTrail:
        """The agent's audit trail."""
        return self._trail

    @property
    def agent_name(self) -> str:
        """The agent's name."""
        return self._agent_name
