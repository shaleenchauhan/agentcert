"""LangChain integration for AgentCert.

Provides two levels of integration:

- :class:`AgentCertCallbackHandler` — A LangChain ``BaseCallbackHandler`` that
  automatically creates signed audit entries for LLM calls, tool invocations,
  and agent decisions.
- :class:`AgentCertMiddleware` — A high-level wrapper that creates a certificate
  and audit trail, and provides a callback handler to pass via
  ``config={"callbacks": [handler]}`` to any LangChain runnable (LangGraph
  agents, chains, or legacy ``AgentExecutor``).

Install with::

    pip install agentcert[langchain]
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any
from uuid import UUID

try:
    from langchain_core.callbacks import BaseCallbackHandler
except ImportError:
    raise ImportError(
        "LangChain integration requires langchain-core. "
        "Install with: pip install agentcert[langchain]"
    )

import agentcert
from agentcert.audit import (
    AuditTrail,
    create_audit_trail,
    get_trail_entries,
    load_trail,
    log_action,
    save_trail,
)
from agentcert.audit_verify import verify_audit_trail
from agentcert.certificate import load_certificate, save_certificate
from agentcert.exceptions import AuditError
from agentcert.keys import load_keys
from agentcert.types import (
    ActionType,
    AuditEntry,
    AuditTrailVerificationResult,
    Certificate,
    KeyPair,
)


# ── Log Levels ──────────────────────────────────────────────────────────────


MINIMAL = "minimal"
STANDARD = "standard"
VERBOSE = "verbose"

_VALID_LOG_LEVELS = {MINIMAL, STANDARD, VERBOSE}


# ── Helpers ─────────────────────────────────────────────────────────────────


def _sha256_hash(data: str) -> str:
    """Return the SHA-256 hex digest of a string."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _extract_model_name(serialized: dict[str, Any]) -> str:
    """Extract a human-readable model name from LangChain serialized dict."""
    # Try common locations for the model name
    kwargs = serialized.get("kwargs", {})
    for key in ("model_name", "model", "model_id"):
        if key in kwargs:
            return str(kwargs[key])
    # Fall back to the class name or id list
    name = serialized.get("name")
    if name:
        return str(name)
    id_list = serialized.get("id", [])
    if id_list:
        return str(id_list[-1])
    return "unknown"


def _extract_tool_name(serialized: dict[str, Any]) -> str:
    """Extract a tool name from LangChain serialized dict."""
    name = serialized.get("name")
    if name:
        return str(name)
    id_list = serialized.get("id", [])
    if id_list:
        return str(id_list[-1])
    return "unknown"


# ── AgentCertCallbackHandler ───────────────────────────────────────────────


class AgentCertCallbackHandler(BaseCallbackHandler):
    """LangChain callback handler that creates signed AgentCert audit entries.

    Buffers ``on_*_start`` events and creates a single signed audit entry on
    the corresponding ``on_*_end`` event (Option B from spec). Error events
    create separate error entries immediately.

    Args:
        trail: An existing audit trail to log entries to.
        agent_keys: The agent's key pair for signing entries.
        log_level: Logging verbosity. One of ``"minimal"``, ``"standard"``
            (default), or ``"verbose"``.

    Attributes:
        trail: The audit trail being written to.
        entries: Shortcut to ``trail.entries``.
    """

    def __init__(
        self,
        trail: AuditTrail,
        agent_keys: KeyPair,
        *,
        log_level: str = STANDARD,
    ) -> None:
        super().__init__()
        if log_level not in _VALID_LOG_LEVELS:
            raise ValueError(
                f"Invalid log_level {log_level!r}, "
                f"must be one of {sorted(_VALID_LOG_LEVELS)}"
            )
        self._trail = trail
        self._agent_keys = agent_keys
        self._log_level = log_level
        self._pending: dict[str, dict[str, Any]] = {}

    @property
    def trail(self) -> AuditTrail:
        """The audit trail being written to."""
        return self._trail

    @property
    def entries(self) -> list[AuditEntry]:
        """All entries in the audit trail."""
        return self._trail.entries

    # ── LLM events ──────────────────────────────────────────────────────

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Buffer LLM start event for pairing with on_llm_end."""
        if self._log_level == MINIMAL:
            return
        self._pending[str(run_id)] = {
            "event_type": "llm",
            "action_type": ActionType.API_CALL,
            "model_name": _extract_model_name(serialized),
            "prompt_hash": _sha256_hash("\n".join(prompts)),
            "started_at": time.time(),
        }

    def on_chat_model_start(
        self,
        serialized: dict[str, Any],
        messages: list[list[Any]],
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Buffer chat model start event (same as LLM start)."""
        if self._log_level == MINIMAL:
            return
        # Serialize messages to a string for hashing
        msg_str = str(messages)
        self._pending[str(run_id)] = {
            "event_type": "llm",
            "action_type": ActionType.API_CALL,
            "model_name": _extract_model_name(serialized),
            "prompt_hash": _sha256_hash(msg_str),
            "started_at": time.time(),
        }

    def on_llm_end(
        self,
        response: Any,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Create audit entry for completed LLM call."""
        pending = self._pending.pop(str(run_id), None)
        if pending is None:
            return

        # Hash the response text
        try:
            response_text = str(response.generations[0][0].text)
        except (AttributeError, IndexError):
            response_text = str(response)
        output_hash = _sha256_hash(response_text)

        duration_ms = int((time.time() - pending["started_at"]) * 1000)

        log_action(
            self._trail,
            self._agent_keys,
            action_type=pending["action_type"],
            action_summary=f"LLM call: {pending['model_name']}",
            action_detail={
                "model": pending["model_name"],
                "prompt_hash": pending["prompt_hash"],
                "output_hash": output_hash,
                "duration_ms": duration_ms,
            },
        )

    def on_llm_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Create error entry for failed LLM call."""
        pending = self._pending.pop(str(run_id), None)
        model_name = pending["model_name"] if pending else "unknown"

        log_action(
            self._trail,
            self._agent_keys,
            action_type=ActionType.ERROR,
            action_summary=f"LLM error: {type(error).__name__}",
            action_detail={
                "model": model_name,
                "error_type": type(error).__name__,
                "error_message": str(error),
            },
        )

    # ── Tool events ─────────────────────────────────────────────────────

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Buffer tool start event for pairing with on_tool_end."""
        self._pending[str(run_id)] = {
            "event_type": "tool",
            "action_type": ActionType.TOOL_USE,
            "tool_name": _extract_tool_name(serialized),
            "input": input_str,
            "started_at": time.time(),
        }

    def on_tool_end(
        self,
        output: Any,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Create audit entry for completed tool call."""
        pending = self._pending.pop(str(run_id), None)
        if pending is None:
            return

        output_hash = _sha256_hash(str(output))
        duration_ms = int((time.time() - pending["started_at"]) * 1000)

        log_action(
            self._trail,
            self._agent_keys,
            action_type=pending["action_type"],
            action_summary=f"Tool call: {pending['tool_name']}",
            action_detail={
                "tool": pending["tool_name"],
                "input": pending["input"],
                "output_hash": output_hash,
                "duration_ms": duration_ms,
            },
        )

    def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Create error entry for failed tool call."""
        pending = self._pending.pop(str(run_id), None)
        tool_name = pending["tool_name"] if pending else "unknown"

        log_action(
            self._trail,
            self._agent_keys,
            action_type=ActionType.ERROR,
            action_summary=f"Tool error: {type(error).__name__}",
            action_detail={
                "tool": tool_name,
                "error_type": type(error).__name__,
                "error_message": str(error),
            },
        )

    # ── Agent events ────────────────────────────────────────────────────

    def on_agent_action(
        self,
        action: Any,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Log agent decision (tool selection)."""
        tool = getattr(action, "tool", "unknown")
        tool_input = getattr(action, "tool_input", {})
        action_log = getattr(action, "log", "")

        log_action(
            self._trail,
            self._agent_keys,
            action_type=ActionType.DECISION,
            action_summary=f"Agent action: {tool}",
            action_detail={
                "tool": str(tool),
                "tool_input": str(tool_input),
                "log": str(action_log),
            },
        )

    def on_agent_finish(
        self,
        finish: Any,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Log agent finish event."""
        return_values = getattr(finish, "return_values", {})
        finish_log = getattr(finish, "log", "")

        log_action(
            self._trail,
            self._agent_keys,
            action_type=ActionType.DECISION,
            action_summary="Agent finished",
            action_detail={
                "output_hash": _sha256_hash(str(return_values)),
                "log": str(finish_log),
            },
        )

    # ── Chain events (verbose only) ─────────────────────────────────────

    def on_chain_start(
        self,
        serialized: dict[str, Any],
        inputs: dict[str, Any],
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Buffer chain start event (verbose mode only, top-level only)."""
        if self._log_level != VERBOSE:
            return
        # Only log top-level chains (no parent)
        if parent_run_id is not None:
            return
        chain_name = serialized.get("name", "")
        if not chain_name:
            id_list = serialized.get("id", [])
            chain_name = str(id_list[-1]) if id_list else "unknown"
        self._pending[str(run_id)] = {
            "event_type": "chain",
            "action_type": ActionType.API_CALL,
            "chain_name": chain_name,
            "started_at": time.time(),
        }

    def on_chain_end(
        self,
        outputs: dict[str, Any],
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Create audit entry for completed chain (verbose mode only)."""
        pending = self._pending.pop(str(run_id), None)
        if pending is None or pending.get("event_type") != "chain":
            return

        output_hash = _sha256_hash(str(outputs))
        duration_ms = int((time.time() - pending["started_at"]) * 1000)

        log_action(
            self._trail,
            self._agent_keys,
            action_type=pending["action_type"],
            action_summary=f"Chain: {pending['chain_name']}",
            action_detail={
                "chain": pending["chain_name"],
                "output_hash": output_hash,
                "duration_ms": duration_ms,
            },
        )

    def on_chain_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Create error entry for failed chain (verbose mode only)."""
        pending = self._pending.pop(str(run_id), None)
        if pending is None or pending.get("event_type") != "chain":
            return

        log_action(
            self._trail,
            self._agent_keys,
            action_type=ActionType.ERROR,
            action_summary=f"Chain error: {type(error).__name__}",
            action_detail={
                "chain": pending.get("chain_name", "unknown"),
                "error_type": type(error).__name__,
                "error_message": str(error),
            },
        )


# ── AgentCertMiddleware ────────────────────────────────────────────────────


def _resolve_keys(keys: str | KeyPair) -> KeyPair:
    """Load keys from a file path, or return the KeyPair as-is."""
    if isinstance(keys, KeyPair):
        return keys
    return load_keys(str(keys))


class AgentCertMiddleware:
    """High-level LangChain integration that provides identity + audit in a few lines.

    Creates a certificate and audit trail on init, and provides a callback
    handler via :meth:`get_handler` that you pass to any LangChain runnable
    through ``config={"callbacks": [handler]}``. This works with LangGraph
    agents, chains, and legacy ``AgentExecutor``. For ``AgentExecutor``
    specifically, :meth:`wrap` can inject the callback automatically.

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
            If provided, ``creator_keys`` is still needed for type but not used
            for signing.
        log_level: Logging verbosity for the callback handler.

    Example::

        middleware = AgentCertMiddleware(
            creator_keys="creator.keys.json",
            agent_keys="agent.keys.json",
            agent_name="my-agent",
            capabilities=["search", "summarize"],
        )
        handler = middleware.get_handler()
        result = agent.invoke(
            {"messages": [{"role": "user", "content": "..."}]},
            config={"callbacks": [handler]},
        )
        print(middleware.verify().status)  # "VALID"
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
        log_level: str = STANDARD,
    ) -> None:
        self._creator_keys = _resolve_keys(creator_keys)
        self._agent_keys = _resolve_keys(agent_keys)

        if certificate is not None:
            self._certificate = certificate
        else:
            self._certificate = agentcert.create_certificate(
                creator_keys=self._creator_keys,
                agent_keys=self._agent_keys,
                name=agent_name,
                platform=platform,
                model_hash=model_hash,
                capabilities=capabilities or [],
                constraints=constraints or [],
                risk_tier=risk_tier,
                expires_days=expires_days,
            )

        self._trail = create_audit_trail(self._certificate, self._agent_keys)
        self._handler = AgentCertCallbackHandler(
            self._trail, self._agent_keys, log_level=log_level,
        )

    def wrap(self, executor: Any) -> Any:
        """Convenience method to inject the callback into a legacy ``AgentExecutor``.

        Mutates the executor's ``callbacks`` list in place and returns it for
        chaining. For LangGraph agents and other runnables, use
        ``config={"callbacks": [middleware.get_handler()]}`` at invoke time
        instead — that pattern works universally.

        Args:
            executor: An ``AgentExecutor`` or any object with a ``callbacks`` attribute.

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
        executor.callbacks.append(self._handler)
        return executor

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
        return get_trail_entries(
            self._trail, action_type=action_type, start=start, end=end,
        )

    def get_handler(self) -> AgentCertCallbackHandler:
        """Return the callback handler (for manual use with LangChain configs)."""
        return self._handler

    def verify(self) -> AuditTrailVerificationResult:
        """Verify the complete audit trail against the certificate.

        Returns:
            An :class:`AuditTrailVerificationResult` with status and checks.
        """
        return verify_audit_trail(self._trail, self._certificate)

    def save(self, directory: str | Path) -> None:
        """Save the certificate and audit trail to a directory.

        Creates the directory structure::

            directory/
                certificate.json
                trail.json

        Args:
            directory: Path to the output directory (created if needed).

        Raises:
            AuditError: If saving fails.
        """
        dirpath = Path(directory)
        try:
            dirpath.mkdir(parents=True, exist_ok=True)
            save_certificate(self._certificate, dirpath / "certificate.json")
            save_trail(self._trail, dirpath / "trail.json")
        except AuditError:
            raise
        except Exception as exc:
            raise AuditError(f"Failed to save middleware state to {directory}: {exc}") from exc

    @classmethod
    def load(
        cls,
        directory: str | Path,
        agent_keys: str | KeyPair,
        *,
        creator_keys: str | KeyPair | None = None,
        log_level: str = STANDARD,
    ) -> AgentCertMiddleware:
        """Load a previously saved middleware state.

        Restores the certificate and audit trail from disk. The agent keys are
        required to continue logging new entries.

        Args:
            directory: Path to the saved directory.
            agent_keys: The agent's key pair (path or KeyPair).
            creator_keys: The creator's key pair (path or KeyPair). Optional;
                if not provided, a dummy is used (the certificate is already
                created and doesn't need re-signing).
            log_level: Logging verbosity for the callback handler.

        Returns:
            A restored :class:`AgentCertMiddleware` ready for use.

        Raises:
            AuditError: If loading fails.
        """
        dirpath = Path(directory)
        resolved_agent = _resolve_keys(agent_keys)

        try:
            cert = load_certificate(dirpath / "certificate.json")
            trail = load_trail(dirpath / "trail.json")
        except Exception as exc:
            raise AuditError(f"Failed to load middleware state from {directory}: {exc}") from exc

        instance = cls.__new__(cls)
        instance._agent_keys = resolved_agent
        instance._creator_keys = _resolve_keys(creator_keys) if creator_keys else resolved_agent
        instance._certificate = cert
        instance._trail = trail
        instance._handler = AgentCertCallbackHandler(
            trail, resolved_agent, log_level=log_level,
        )
        return instance
