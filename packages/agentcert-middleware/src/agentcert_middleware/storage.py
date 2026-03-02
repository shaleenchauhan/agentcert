"""Storage backends for audit trail persistence.

Provides LocalStorage (disk), ServiceStorage (managed service),
and BothStorage (local backup + service submission).
"""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING

from agentcert.audit import AuditTrail, save_trail, load_trail as _load_trail
from agentcert.certificate import save_certificate, load_certificate
from agentcert.client import AgentCertClient
from agentcert.types import AuditEntry, Certificate

if TYPE_CHECKING:
    from agentcert_middleware.retry import RetryPolicy

logger = logging.getLogger("agentcert.middleware")


class StorageBackend(ABC):
    """Abstract storage backend.

    All concrete backends implement persist_entry, persist_trail, and
    load_trail to handle audit trail persistence.
    """

    @abstractmethod
    def persist_entry(
        self, entry: AuditEntry, trail: AuditTrail, cert: Certificate
    ) -> None:
        """Persist a single entry. Called after each log_action when auto_save=True.

        Args:
            entry: The audit entry to persist.
            trail: The full audit trail (for context / full-trail writes).
            cert: The agent's certificate.
        """
        ...

    @abstractmethod
    def persist_trail(self, trail: AuditTrail, cert: Certificate) -> None:
        """Persist the full trail and certificate. Called on save().

        Args:
            trail: The audit trail to persist.
            cert: The agent's certificate.
        """
        ...

    @abstractmethod
    def load_trail(self, trail_id: str) -> tuple[AuditTrail, Certificate | None]:
        """Load trail and optionally its certificate from storage.

        Args:
            trail_id: The trail identifier (used to locate files or query service).

        Returns:
            Tuple of (AuditTrail, Certificate or None).
        """
        ...


class LocalStorage(StorageBackend):
    """Writes JSON files to disk.

    Directory structure::

        {storage_dir}/{agent_name}/cert.json
        {storage_dir}/{agent_name}/trail.json

    Args:
        storage_dir: Base directory for audit data.
        agent_name: Agent name used as subdirectory.
    """

    def __init__(
        self, storage_dir: str = "./agentcert-audit/", agent_name: str = "agent"
    ) -> None:
        self._storage_dir = storage_dir
        self._agent_name = agent_name
        self._agent_dir = Path(storage_dir) / agent_name

    def persist_entry(
        self, entry: AuditEntry, trail: AuditTrail, cert: Certificate
    ) -> None:
        """Persist by writing the full trail to disk.

        Args:
            entry: The new audit entry (included in trail).
            trail: The full audit trail.
            cert: The agent's certificate.
        """
        self.persist_trail(trail, cert)

    def persist_trail(self, trail: AuditTrail, cert: Certificate) -> None:
        """Write trail and certificate to disk as JSON files.

        Args:
            trail: The audit trail to save.
            cert: The agent's certificate to save.
        """
        self._agent_dir.mkdir(parents=True, exist_ok=True)
        trail_path = self._agent_dir / "trail.json"
        cert_path = self._agent_dir / "cert.json"
        save_trail(trail, trail_path)
        save_certificate(cert, cert_path)

    def load_trail(self, trail_id: str) -> tuple[AuditTrail, Certificate | None]:
        """Load trail and certificate from disk.

        Args:
            trail_id: Not used for local storage (files located by agent_name).

        Returns:
            Tuple of (AuditTrail, Certificate or None).
        """
        trail_path = self._agent_dir / "trail.json"
        cert_path = self._agent_dir / "cert.json"

        trail = _load_trail(trail_path)

        cert: Certificate | None = None
        if cert_path.exists():
            cert = load_certificate(cert_path)

        return (trail, cert)


class ServiceStorage(StorageBackend):
    """Submits to AgentCert managed service via AgentCertClient.

    STUBS (tracked in managed-service-integration-stubs.md):
        - Bulk submission: falls back to sequential single POST /entries calls
        - Revocation check: not available via this backend (handled by TrustVerifier)
        - API key: accepted but not sent in headers (service has no auth yet)

    Args:
        service_url: Base URL of the AgentCert service.
        api_key: API key for authentication (stored but not sent yet — Stub 3).
        retry_policy: Optional retry policy for resilient submission.
    """

    def __init__(
        self,
        service_url: str,
        api_key: str | None = None,
        retry_policy: RetryPolicy | None = None,
    ) -> None:
        self._service_url = service_url
        self._api_key = api_key  # Stored but NOT sent yet (Stub 3)
        self._retry_policy = retry_policy
        self._client = AgentCertClient(service_url)
        self._registered_certs: set[str] = set()

    def persist_entry(
        self, entry: AuditEntry, trail: AuditTrail, cert: Certificate
    ) -> None:
        """Submit single entry via POST /api/v1/entries.

        Wraps in retry policy if configured.

        Args:
            entry: The audit entry to submit.
            trail: The full audit trail (for context).
            cert: The agent's certificate.
        """
        def _submit() -> None:
            self._client.submit_entries([entry])

        if self._retry_policy:
            self._retry_policy.execute_sync(_submit)
        else:
            _submit()

    def persist_trail(self, trail: AuditTrail, cert: Certificate) -> None:
        """Register cert (if not already) and submit all entries.

        Currently submits entries one-at-a-time (Stub 1).
        Registers cert via POST /api/v1/certificates.

        Args:
            trail: The audit trail to submit.
            cert: The agent's certificate.
        """
        # Register certificate if not already done
        if cert.cert_id not in self._registered_certs:
            self._client.register_certificate(cert)
            self._registered_certs.add(cert.cert_id)

        # Submit all entries (sequential — Stub 1: no bulk endpoint)
        if trail.entries:
            self._client.submit_entries(trail.entries)

    def load_trail(self, trail_id: str) -> tuple[AuditTrail, Certificate | None]:
        """Load trail from the service.

        Args:
            trail_id: The trail identifier.

        Returns:
            Tuple of (AuditTrail, None). Certificate not returned from service.
        """
        data = self._client.get_trail(trail_id)
        trail = AuditTrail.from_dict(data)
        return (trail, None)


class BothStorage(StorageBackend):
    """Local backup + service submission.

    Local write is PRIMARY (always attempted first, synchronous).
    Service submission is SECONDARY (best-effort, with retry).
    If service fails, entries accumulate locally — no data loss.

    Args:
        local: The local storage backend.
        service: The service storage backend.
    """

    def __init__(self, local: LocalStorage, service: ServiceStorage) -> None:
        self._local = local
        self._service = service

    def persist_entry(
        self, entry: AuditEntry, trail: AuditTrail, cert: Certificate
    ) -> None:
        """Write locally first, then submit to service (best-effort).

        1. Write locally (fast, reliable)
        2. Submit to service (best-effort, catch errors, buffer for retry)

        Args:
            entry: The audit entry to persist.
            trail: The full audit trail.
            cert: The agent's certificate.
        """
        # Primary: local write (always)
        self._local.persist_entry(entry, trail, cert)

        # Secondary: service submission (best-effort)
        try:
            self._service.persist_entry(entry, trail, cert)
        except Exception as e:
            logger.warning("Service submission failed (entry saved locally): %s", e)

    def persist_trail(self, trail: AuditTrail, cert: Certificate) -> None:
        """Persist trail to both local and service.

        Args:
            trail: The audit trail to persist.
            cert: The agent's certificate.
        """
        # Primary: local write (always)
        self._local.persist_trail(trail, cert)

        # Secondary: service submission (best-effort)
        try:
            self._service.persist_trail(trail, cert)
        except Exception as e:
            logger.warning("Service submission failed (trail saved locally): %s", e)

    def load_trail(self, trail_id: str) -> tuple[AuditTrail, Certificate | None]:
        """Load trail from local storage.

        Args:
            trail_id: The trail identifier.

        Returns:
            Tuple of (AuditTrail, Certificate or None) from local storage.
        """
        return self._local.load_trail(trail_id)


def create_storage(
    storage: str = "local",
    storage_dir: str = "./agentcert-audit/",
    agent_name: str = "agent",
    service_url: str | None = None,
    api_key: str | None = None,
    retry_policy: RetryPolicy | None = None,
) -> StorageBackend:
    """Create the appropriate storage backend based on configuration.

    Args:
        storage: Storage mode — ``"local"``, ``"service"``, or ``"both"``.
        storage_dir: Base directory for local storage.
        agent_name: Agent name used as subdirectory for local storage.
        service_url: URL of the AgentCert service (required for ``"service"`` and ``"both"``).
        api_key: Optional API key for service authentication.
        retry_policy: Optional retry policy for service submissions.

    Returns:
        A configured StorageBackend instance.

    Raises:
        ValueError: If storage mode is invalid or required params are missing.
    """
    if storage == "local":
        return LocalStorage(storage_dir, agent_name)
    elif storage == "service":
        if not service_url:
            raise ValueError("service_url required for storage='service'")
        return ServiceStorage(service_url, api_key, retry_policy)
    elif storage == "both":
        if not service_url:
            raise ValueError("service_url required for storage='both'")
        local = LocalStorage(storage_dir, agent_name)
        service = ServiceStorage(service_url, api_key, retry_policy)
        return BothStorage(local, service)
    else:
        raise ValueError(
            f"Invalid storage mode: {storage}. Must be 'local', 'service', or 'both'"
        )
