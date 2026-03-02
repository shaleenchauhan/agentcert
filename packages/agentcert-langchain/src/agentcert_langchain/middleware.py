"""LangChain middleware for AgentCert.

Provides :class:`AgentCertLangChainMiddleware`, a high-level integration that
creates an identity certificate, audit trail, and storage backend, then
exposes a LangChain callback handler for automatic event logging and a
verification tool for peer trust checks.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from agentcert.audit import AuditTrail, create_audit_trail, load_trail, save_trail
from agentcert.audit_verify import verify_audit_trail
from agentcert.certificate import load_certificate, save_certificate
from agentcert.exceptions import AuditError
from agentcert.types import (
    ActionType,
    AuditEntry,
    AuditTrailVerificationResult,
    Certificate,
    KeyPair,
)
from agentcert_middleware import BaseMiddleware, LocalStorage, TrustVerifier

from agentcert_langchain.handler import AgentCertCallbackHandler


class AgentCertLangChainMiddleware(BaseMiddleware):
    """LangChain middleware with storage configurability and trust verification.

    Inherits from :class:`BaseMiddleware` and adds LangChain-specific methods:
    :meth:`get_handler` for callback integration and :meth:`get_verify_tool`
    for peer certificate verification. Also provides backward-compatible
    methods matching the original ``AgentCertMiddleware`` API.

    Usage::

        middleware = AgentCertLangChainMiddleware(
            creator_keys="creator.keys.json",
            agent_keys="agent.keys.json",
            agent_name="research-agent",
            capabilities=["web_search", "analysis"],
            risk_tier=2,
            storage="both",
            service_url="https://agentcert.dev",
            auto_save=True,
        )
        handler = middleware.get_handler()
        verify_tool = middleware.get_verify_tool()

        result = agent.invoke(
            {"messages": [HumanMessage(content="...")]},
            config={"callbacks": [handler]},
        )

        verification = middleware.verify()
        middleware.save()

    Args:
        creator_keys: Path to a keys JSON file, or a :class:`KeyPair`.
        agent_keys: Path to a keys JSON file, or a :class:`KeyPair`.
        agent_name: Human-readable name for the agent.
        platform: Platform identifier (default ``"langchain"``).
        model_hash: Hash of the model weights or code (optional).
        capabilities: List of agent capabilities (optional).
        constraints: List of operational constraints (optional).
        risk_tier: Risk tier 1-5 (default 1).
        expires_days: Certificate validity in days (default 90).
        certificate: Use an existing certificate instead of creating one.
        log_level: Logging verbosity for the callback handler.
        storage: Storage mode — ``"local"``, ``"service"``, or ``"both"``.
        storage_dir: Base directory for local audit storage.
        service_url: URL of the AgentCert managed service.
        api_key: Optional API key for service authentication.
        auto_save: Whether to persist entries automatically.
        auto_save_interval: Persist every N entries when auto_save is True.
        retry_attempts: Max retry attempts for service submissions.
        retry_backoff: Backoff multiplier for retries.
    """

    def __init__(
        self,
        creator_keys: str | KeyPair,
        agent_keys: str | KeyPair,
        agent_name: str,
        *,
        platform: str = "langchain",
        model_hash: str = "",
        capabilities: list[str] | None = None,
        constraints: list[str] | None = None,
        risk_tier: int = 1,
        expires_days: int = 90,
        certificate: Certificate | None = None,
        log_level: str = "standard",
        storage: str = "local",
        storage_dir: str = "./agentcert-audit/",
        service_url: str | None = None,
        api_key: str | None = None,
        auto_save: bool = False,
        auto_save_interval: int = 1,
        retry_attempts: int = 3,
        retry_backoff: float = 2.0,
    ) -> None:
        super().__init__(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name=agent_name,
            capabilities=capabilities,
            constraints=constraints,
            risk_tier=risk_tier,
            log_level=log_level,
            storage=storage,
            storage_dir=storage_dir,
            service_url=service_url,
            api_key=api_key,
            auto_save=auto_save,
            auto_save_interval=auto_save_interval,
            retry_attempts=retry_attempts,
            retry_backoff=retry_backoff,
            model_hash=model_hash or "unknown",
            platform=platform,
            expires_days=expires_days,
        )

        # Override cert if an existing one was provided
        if certificate is not None:
            self._certificate = certificate
            self._trail = create_audit_trail(certificate, self._agent_keys)

        self._handler: AgentCertCallbackHandler | None = None

    def get_handler(self) -> AgentCertCallbackHandler:
        """Return the LangChain callback handler bound to this middleware.

        The handler is created lazily and cached — repeated calls return the
        same instance.

        Returns:
            An :class:`AgentCertCallbackHandler` in middleware mode.
        """
        if self._handler is None:
            self._handler = AgentCertCallbackHandler(
                middleware=self, log_level=self._log_level,
            )
        return self._handler

    def get_verify_tool(self) -> Any:
        """Get a LangChain ``BaseTool`` for peer certificate verification.

        Returns:
            An :class:`AgentCertVerifyTool` bound to this middleware.
        """
        from agentcert_langchain.tool import AgentCertVerifyTool

        return AgentCertVerifyTool(middleware=self)

    # ── Backward-compatible accessors ───────────────────────────────────

    def get_certificate(self) -> Certificate:
        """Return the agent's identity certificate."""
        return self._certificate

    def get_trail(self) -> AuditTrail:
        """Return the audit trail."""
        return self._trail

    def get_entries(
        self,
        *,
        action_type: ActionType | int | None = None,
        start: int | None = None,
        end: int | None = None,
    ) -> list[AuditEntry]:
        """Return audit entries, optionally filtered.

        Args:
            action_type: Filter by action type.
            start: Start sequence number (inclusive).
            end: End sequence number (inclusive).

        Returns:
            List of matching entries.
        """
        entries = self._trail.entries

        if action_type is not None:
            action_int = int(action_type)
            entries = [e for e in entries if e.action_type == action_int]

        if start is not None:
            entries = [e for e in entries if e.sequence >= start]

        if end is not None:
            entries = [e for e in entries if e.sequence <= end]

        return entries

    def wrap(self, executor: Any) -> Any:
        """Inject the callback handler into a legacy ``AgentExecutor``.

        Mutates the executor's ``callbacks`` list in place and returns it for
        chaining. For LangGraph agents and other runnables, use
        ``config={"callbacks": [middleware.get_handler()]}`` instead.

        Args:
            executor: An ``AgentExecutor`` or any object with a ``callbacks``
                attribute.

        Returns:
            The same executor, with the AgentCert handler added.

        Raises:
            AuditError: If the executor has no ``callbacks`` attribute.
        """
        if not hasattr(executor, "callbacks"):
            raise AuditError(
                f"{type(executor).__name__} has no 'callbacks' attribute. "
                "Pass an AgentExecutor or compatible object."
            )
        if executor.callbacks is None:
            executor.callbacks = []
        executor.callbacks.append(self.get_handler())
        return executor

    # ── Save / Load (backward-compatible file layout) ───────────────────

    def save(self, directory: str | Path | None = None) -> None:
        """Save the certificate and audit trail.

        When ``directory`` is given, writes files in the backward-compatible
        layout (``certificate.json`` and ``trail.json`` directly in the
        directory). When omitted, delegates to the configured storage backend.

        Args:
            directory: Path to the output directory (created if needed).

        Raises:
            AuditError: If saving fails.
        """
        if directory is not None:
            dirpath = Path(directory)
            try:
                dirpath.mkdir(parents=True, exist_ok=True)
                save_certificate(self._certificate, dirpath / "certificate.json")
                save_trail(self._trail, dirpath / "trail.json")
            except AuditError:
                raise
            except Exception as exc:
                raise AuditError(
                    f"Failed to save middleware state to {directory}: {exc}"
                ) from exc
        else:
            super().save()

    @classmethod
    def load(
        cls,
        directory: str | Path,
        agent_keys: str | KeyPair,
        *,
        creator_keys: str | KeyPair | None = None,
        log_level: str = "standard",
    ) -> AgentCertLangChainMiddleware:
        """Load a previously saved middleware state.

        Restores the certificate and audit trail from disk. The agent keys are
        required to continue logging new entries.

        Args:
            directory: Path to the saved directory.
            agent_keys: The agent's key pair (path or KeyPair).
            creator_keys: The creator's key pair (path or KeyPair). Optional.
            log_level: Logging verbosity for the callback handler.

        Returns:
            A restored :class:`AgentCertLangChainMiddleware` ready for use.

        Raises:
            AuditError: If loading fails.
        """
        from agentcert.keys import load_keys

        dirpath = Path(directory)

        if isinstance(agent_keys, str):
            agent_keys = load_keys(agent_keys)
        resolved_creator = agent_keys
        if creator_keys is not None:
            if isinstance(creator_keys, str):
                resolved_creator = load_keys(creator_keys)
            else:
                resolved_creator = creator_keys

        try:
            cert = load_certificate(dirpath / "certificate.json")
            trail = load_trail(dirpath / "trail.json")
        except Exception as exc:
            raise AuditError(
                f"Failed to load middleware state from {directory}: {exc}"
            ) from exc

        instance = cls.__new__(cls)
        instance._agent_keys = agent_keys
        instance._creator_keys = resolved_creator
        instance._agent_name = cert.agent_metadata.name
        instance._log_level = log_level
        instance._auto_save = False
        instance._auto_save_interval = 1
        instance._entries_since_save = 0
        instance._certificate = cert
        instance._trail = trail
        instance._handler = None
        instance._storage = LocalStorage("./agentcert-audit/", instance._agent_name)
        instance._storage_mode = "local"
        instance._storage_dir = "./agentcert-audit/"
        instance._trust_verifier = TrustVerifier()
        return instance
