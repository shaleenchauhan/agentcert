"""SDK client for the AgentCert anchoring service.

Provides a Python interface for registering certificates, submitting entries,
retrieving proofs, and verifying entries against the anchoring service.

Requires ``httpx`` — install with ``pip install agentcert[client]``.
"""

from __future__ import annotations

from typing import Any

import httpx

from agentcert.audit import AuditTrail
from agentcert.exceptions import ClientError
from agentcert.types import AuditEntry, Certificate, MerkleProof


class AgentCertClient:
    """Client for the AgentCert anchoring service.

    Usage::

        from agentcert.client import AgentCertClient

        with AgentCertClient("http://localhost:8932") as client:
            client.register_certificate(cert)
            client.submit_trail(trail)
            proof = client.get_proof(entry_id)

    Args:
        service_url: Base URL of the service (e.g., ``"http://localhost:8932"``).
        timeout: HTTP request timeout in seconds.
    """

    def __init__(self, service_url: str, timeout: float = 30.0) -> None:
        self._base = service_url.rstrip("/")
        self._client = httpx.Client(base_url=self._base, timeout=timeout)

    def register_certificate(self, certificate: Certificate) -> dict[str, Any]:
        """Register a certificate with the service.

        Args:
            certificate: The certificate to register.

        Returns:
            Dict with ``cert_id`` and ``status`` keys.

        Raises:
            ClientError: If registration fails.
        """
        return self._post(
            "/api/v1/certificates",
            json={"certificate": certificate.to_dict()},
        )

    def get_certificate(self, cert_id: str) -> dict[str, Any]:
        """Get a certificate from the service.

        Args:
            cert_id: The certificate ID.

        Returns:
            The certificate dict.

        Raises:
            ClientError: If the request fails.
        """
        return self._get(f"/api/v1/certificates/{cert_id}")

    def submit_entries(self, entries: list[AuditEntry]) -> dict[str, Any]:
        """Submit signed audit entries to the service.

        Args:
            entries: List of signed audit entries.

        Returns:
            Dict with ``accepted``, ``rejected``, ``errors``, and ``entry_ids``.

        Raises:
            ClientError: If the request fails.
        """
        return self._post(
            "/api/v1/entries",
            json={"entries": [e.to_dict() for e in entries]},
        )

    def submit_trail(self, trail: AuditTrail) -> dict[str, Any]:
        """Submit all entries from an audit trail.

        Args:
            trail: The audit trail whose entries to submit.

        Returns:
            Dict with ``accepted``, ``rejected``, ``errors``, and ``entry_ids``.

        Raises:
            ClientError: If the request fails.
        """
        return self.submit_entries(trail.entries)

    def get_entry(self, entry_id: str) -> dict[str, Any]:
        """Get a specific entry from the service.

        Args:
            entry_id: The entry ID.

        Returns:
            The entry dict.

        Raises:
            ClientError: If the request fails.
        """
        return self._get(f"/api/v1/entries/{entry_id}")

    def get_trail(self, trail_id: str) -> dict[str, Any]:
        """Get all entries for a trail from the service.

        Args:
            trail_id: The trail identifier.

        Returns:
            Dict with ``trail_id``, ``entries``, and ``entry_count``.

        Raises:
            ClientError: If the request fails.
        """
        return self._get(f"/api/v1/trails/{trail_id}")

    def get_proof(self, entry_id: str) -> MerkleProof | None:
        """Get the Merkle proof for an entry.

        Args:
            entry_id: The entry ID.

        Returns:
            A MerkleProof if the entry has been batched, None if still pending.

        Raises:
            ClientError: If the request fails.
        """
        data = self._get(f"/api/v1/proofs/{entry_id}")
        if data.get("status") == "pending":
            return None
        proof_dict = data.get("proof")
        if proof_dict is None:
            return None
        return MerkleProof.from_dict(proof_dict)

    def get_proof_raw(self, entry_id: str) -> dict[str, Any]:
        """Get the raw proof response (including batch and anchor info).

        Args:
            entry_id: The entry ID.

        Returns:
            The full proof response dict.

        Raises:
            ClientError: If the request fails.
        """
        return self._get(f"/api/v1/proofs/{entry_id}")

    def verify_entry(self, entry_id: str) -> dict[str, Any]:
        """Get full verification result for an entry.

        Args:
            entry_id: The entry ID.

        Returns:
            Verification result dict with ``status``, ``checks``, etc.

        Raises:
            ClientError: If the request fails.
        """
        return self._get(f"/api/v1/verify/{entry_id}")

    def get_batch(self, batch_id: str) -> dict[str, Any]:
        """Get batch details.

        Args:
            batch_id: The batch ID.

        Returns:
            The batch dict.

        Raises:
            ClientError: If the request fails.
        """
        return self._get(f"/api/v1/batches/{batch_id}")

    def get_latest_batch(self) -> dict[str, Any]:
        """Get the most recent batch.

        Returns:
            The batch dict.

        Raises:
            ClientError: If the request fails.
        """
        return self._get("/api/v1/batches/latest")

    def force_batch(self) -> dict[str, Any]:
        """Force an immediate batch cycle.

        Returns:
            Dict with batch result info.

        Raises:
            ClientError: If the request fails.
        """
        return self._post("/api/v1/admin/force-batch")

    def health(self) -> dict[str, Any]:
        """Check service health.

        Returns:
            Health status dict.

        Raises:
            ClientError: If the request fails.
        """
        return self._get("/api/v1/health")

    def stats(self) -> dict[str, Any]:
        """Get service statistics.

        Returns:
            Statistics dict.

        Raises:
            ClientError: If the request fails.
        """
        return self._get("/api/v1/stats")

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()

    def __enter__(self) -> AgentCertClient:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    # ── Internal helpers ────────────────────────────────────────────────

    def _get(self, path: str) -> dict[str, Any]:
        """Make a GET request and return JSON."""
        try:
            resp = self._client.get(path)
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as exc:
            detail = ""
            try:
                detail = exc.response.json().get("detail", "")
            except Exception:
                detail = exc.response.text
            raise ClientError(
                f"Service returned {exc.response.status_code}: {detail}"
            ) from exc
        except httpx.HTTPError as exc:
            raise ClientError(f"Request failed: {exc}") from exc

    def _post(
        self,
        path: str,
        json: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Make a POST request and return JSON."""
        try:
            resp = self._client.post(path, json=json)
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as exc:
            detail = ""
            try:
                detail = exc.response.json().get("detail", "")
            except Exception:
                detail = exc.response.text
            raise ClientError(
                f"Service returned {exc.response.status_code}: {detail}"
            ) from exc
        except httpx.HTTPError as exc:
            raise ClientError(f"Request failed: {exc}") from exc
