"""AgentCert callback handler for LangChain.

Translates LangChain callback events into signed AgentCert audit entries.
Supports both middleware mode (delegates to ``BaseMiddleware._log_action()``)
and legacy mode (calls ``agentcert.audit.log_action()`` directly for backward
compatibility).
"""

from __future__ import annotations

import hashlib
import time
from typing import TYPE_CHECKING, Any
from uuid import UUID

try:
    from langchain_core.callbacks import BaseCallbackHandler
except ImportError:
    raise ImportError(
        "LangChain integration requires langchain-core. "
        "Install with: pip install agentcert-langchain"
    )

from agentcert.audit import log_action
from agentcert.types import ActionType, AuditEntry

if TYPE_CHECKING:
    from agentcert.audit import AuditTrail
    from agentcert.types import KeyPair
    from agentcert_middleware import BaseMiddleware


# ── Log Levels ──────────────────────────────────────────────────────────────


MINIMAL = "minimal"
STANDARD = "standard"
VERBOSE = "verbose"

_VALID_LOG_LEVELS = {MINIMAL, STANDARD, VERBOSE}


# ── Helpers ─────────────────────────────────────────────────────────────────


def _sha256_hash(data: str) -> str:
    """Return the SHA-256 hex digest of a string.

    Args:
        data: The string to hash.

    Returns:
        64-character lowercase hex digest.
    """
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _extract_model_name(serialized: dict[str, Any]) -> str:
    """Extract a human-readable model name from LangChain serialized dict.

    Checks ``kwargs.model_name``, ``kwargs.model``, ``kwargs.model_id``,
    ``name``, and ``id[-1]`` in order.

    Args:
        serialized: LangChain serialized component dict.

    Returns:
        Model name string, or ``"unknown"`` if not found.
    """
    kwargs = serialized.get("kwargs", {})
    for key in ("model_name", "model", "model_id"):
        if key in kwargs:
            return str(kwargs[key])
    name = serialized.get("name")
    if name:
        return str(name)
    id_list = serialized.get("id", [])
    if id_list:
        return str(id_list[-1])
    return "unknown"


def _extract_tool_name(serialized: dict[str, Any]) -> str:
    """Extract a tool name from LangChain serialized dict.

    Args:
        serialized: LangChain serialized component dict.

    Returns:
        Tool name string, or ``"unknown"`` if not found.
    """
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

    Supports two initialization modes:

    **Middleware mode** (recommended)::

        handler = AgentCertCallbackHandler(middleware=mw)

    **Legacy mode** (backward compatible)::

        handler = AgentCertCallbackHandler(trail, agent_keys)

    Buffers ``on_*_start`` events and creates a single signed audit entry on
    the corresponding ``on_*_end`` event. Error events create separate error
    entries immediately.

    Args:
        trail: An existing audit trail to log entries to (legacy mode).
        agent_keys: The agent's key pair for signing entries (legacy mode).
        log_level: Logging verbosity. One of ``"minimal"``, ``"standard"``
            (default), or ``"verbose"``.
        middleware: A BaseMiddleware instance (middleware mode).

    Attributes:
        trail: The audit trail being written to.
        entries: Shortcut to ``trail.entries``.
    """

    def __init__(
        self,
        trail: AuditTrail | None = None,
        agent_keys: KeyPair | None = None,
        *,
        log_level: str = STANDARD,
        middleware: BaseMiddleware | None = None,
    ) -> None:
        super().__init__()
        if log_level not in _VALID_LOG_LEVELS:
            raise ValueError(
                f"Invalid log_level {log_level!r}, "
                f"must be one of {sorted(_VALID_LOG_LEVELS)}"
            )
        self._log_level = log_level
        self._pending: dict[str, dict[str, Any]] = {}

        if middleware is not None:
            self._middleware = middleware
            self._trail = middleware._trail
            self._agent_keys = middleware._agent_keys
        elif trail is not None and agent_keys is not None:
            self._middleware = None
            self._trail = trail
            self._agent_keys = agent_keys
        else:
            raise ValueError(
                "Either middleware or (trail, agent_keys) must be provided"
            )

    @property
    def trail(self) -> AuditTrail:
        """The audit trail being written to."""
        return self._trail

    @property
    def entries(self) -> list[AuditEntry]:
        """All entries in the audit trail."""
        return self._trail.entries

    def _do_log(
        self,
        action_type: ActionType | int,
        action_summary: str,
        action_detail: dict[str, Any],
    ) -> None:
        """Route the log call to middleware or direct ``log_action()``.

        Args:
            action_type: ActionType enum value or int.
            action_summary: Brief human-readable description.
            action_detail: Structured action details dict.
        """
        if self._middleware is not None:
            self._middleware._log_action(
                action_type=action_type,
                action_summary=action_summary,
                action_detail=action_detail,
            )
        else:
            log_action(
                self._trail,
                self._agent_keys,
                action_type=action_type,
                action_summary=action_summary,
                action_detail=action_detail,
            )

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

        try:
            response_text = str(response.generations[0][0].text)
        except (AttributeError, IndexError):
            response_text = str(response)
        output_hash = _sha256_hash(response_text)

        duration_ms = int((time.time() - pending["started_at"]) * 1000)

        self._do_log(
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

        self._do_log(
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

        self._do_log(
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

        self._do_log(
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

        self._do_log(
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

        self._do_log(
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

        self._do_log(
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

        self._do_log(
            action_type=ActionType.ERROR,
            action_summary=f"Chain error: {type(error).__name__}",
            action_detail={
                "chain": pending.get("chain_name", "unknown"),
                "error_type": type(error).__name__,
                "error_message": str(error),
            },
        )
