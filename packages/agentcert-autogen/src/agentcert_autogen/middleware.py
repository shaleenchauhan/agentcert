"""Single-agent AutoGen middleware — async-native.

AutoGen v0.4 has NO callback system. Integration works through:
1. Tool wrapping — wraps agent's tools to capture every invocation
2. Stream processing — reads ``run_stream()`` output, maps typed messages
   to ActionTypes

Both approaches are used together: tool wrapping captures tool use details,
stream processing captures agent decisions (TextMessages).
"""

from __future__ import annotations

import asyncio
import functools
import hashlib
import json
import logging
from typing import TYPE_CHECKING, Any, AsyncGenerator, Callable, Sequence

from agentcert.types import ActionType
from agentcert_middleware import BaseMiddleware

if TYPE_CHECKING:
    from autogen_agentchat.base import TaskResult
    from autogen_agentchat.messages import (
        BaseAgentEvent,
        BaseChatMessage,
    )

logger = logging.getLogger("agentcert.autogen")


class AgentCertAutoGenMiddleware(BaseMiddleware):
    """Single-agent AutoGen middleware with async audit trail.

    Integration approach:
        AutoGen v0.4 has no callbacks. This middleware integrates via:

        1. **Tool wrapping** — ``wrap_tools()`` wraps each callable so that
           every invocation is logged as ``ActionType.TOOL_USE``.
        2. **Stream processing** — ``process_stream()`` reads
           ``run_stream()`` output and maps typed messages to ActionTypes.

    Usage::

        middleware = AgentCertAutoGenMiddleware(
            creator_keys="creator.keys.json",
            agent_keys="agent.keys.json",
            agent_name="assistant",
            capabilities=["web_search"],
            storage="both",
            service_url="https://agentcert.dev",
            auto_save=True,
        )

        agent = AssistantAgent(
            name="assistant",
            model_client=model_client,
            tools=middleware.wrap_tools([get_weather, search_web]),
        )

        # Option A: convenience method
        result = await middleware.run(agent, "What's the weather?")

        # Option B: manual stream processing
        result = await middleware.process_stream(
            agent.run_stream(task="What's the weather?")
        )

        verification = middleware.verify()
        await middleware.save()

    Args:
        creator_keys: Path to creator keys file or KeyPair object.
        agent_keys: Path to agent keys file or KeyPair object.
        agent_name: Human-readable agent name.
        capabilities: Agent capabilities for the certificate.
        constraints: Agent constraints for the certificate.
        risk_tier: Risk tier (1-5).
        storage: Storage mode — ``"local"``, ``"service"``, or ``"both"``.
        storage_dir: Base directory for local audit storage.
        service_url: URL of the AgentCert managed service.
        api_key: Optional API key for service authentication.
        auto_save: Persist entries automatically after each action.
        **kwargs: Additional arguments passed to ``BaseMiddleware``.
    """

    def __init__(
        self,
        creator_keys: str | Any,
        agent_keys: str | Any,
        agent_name: str,
        capabilities: list[str] | None = None,
        constraints: list[str] | None = None,
        risk_tier: int = 3,
        storage: str = "local",
        storage_dir: str = "./agentcert-audit/",
        service_url: str | None = None,
        api_key: str | None = None,
        auto_save: bool = False,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name=agent_name,
            capabilities=capabilities,
            constraints=constraints,
            risk_tier=risk_tier,
            storage=storage,
            storage_dir=storage_dir,
            service_url=service_url,
            api_key=api_key,
            auto_save=auto_save,
            platform="autogen",
            **kwargs,
        )

    def wrap_tools(self, tools: list[Callable[..., Any]]) -> list[Callable[..., Any]]:
        """Wrap tools to capture invocations as audit entries.

        Each wrapped tool:
            1. Runs the original function (sync or async)
            2. Logs a ``TOOL_USE`` entry with the tool name and args hash
            3. Returns the original result unchanged

        The wrapper preserves the original function's ``__name__``,
        ``__doc__``, ``__module__``, and type annotations so AutoGen's
        ``FunctionTool`` can extract the correct JSON schema.

        Args:
            tools: List of callable tool functions.

        Returns:
            List of wrapped callables with identical signatures.
        """
        wrapped = []
        for tool in tools:
            tool_name = getattr(tool, "__name__", str(tool))

            if asyncio.iscoroutinefunction(tool):
                @functools.wraps(tool)
                async def async_wrapper(
                    *args: Any,
                    _original: Callable[..., Any] = tool,
                    _name: str = tool_name,
                    **kwargs: Any,
                ) -> Any:
                    result = await _original(*args, **kwargs)
                    self._log_tool_use(_name, args, kwargs)
                    return result

                wrapped.append(async_wrapper)
            else:
                @functools.wraps(tool)
                def sync_wrapper(
                    *args: Any,
                    _original: Callable[..., Any] = tool,
                    _name: str = tool_name,
                    **kwargs: Any,
                ) -> Any:
                    result = _original(*args, **kwargs)
                    self._log_tool_use(_name, args, kwargs)
                    return result

                wrapped.append(sync_wrapper)

        return wrapped

    def _log_tool_use(self, name: str, args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
        """Log a TOOL_USE entry for a tool invocation.

        Args:
            name: Tool function name.
            args: Positional arguments passed to the tool.
            kwargs: Keyword arguments passed to the tool.
        """
        args_hash = hashlib.sha256(
            json.dumps(
                {"args": str(args), "kwargs": str(kwargs)},
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        self._log_action(
            action_type=ActionType.TOOL_USE,
            action_summary=f"Tool call: {name}",
            action_detail_hash=args_hash,
        )

    async def process_stream(
        self,
        stream: AsyncGenerator[BaseAgentEvent | BaseChatMessage | TaskResult, None],
    ) -> TaskResult | None:
        """Process AutoGen ``run_stream()`` output.

        Maps message types to ActionTypes:
            - ``ToolCallRequestEvent`` → ``TOOL_USE`` (agent decided to call a tool)
            - ``ToolCallExecutionEvent`` → skipped (already captured by ``wrap_tools``)
            - ``TextMessage`` (source != ``"user"``) → ``DECISION``
            - ``StopMessage`` → ``DECISION``
            - ``HandoffMessage`` → ``DECISION``
            - ``ToolCallSummaryMessage`` → skipped (summary of already-logged events)
            - ``ThoughtEvent`` → ``DECISION`` (agent reasoning)
            - ``SelectSpeakerEvent`` / ``SelectorEvent`` → ``DECISION`` (team routing)
            - ``TaskResult`` → captured as final result

        Args:
            stream: Async generator from ``agent.run_stream()`` or
                ``team.run_stream()``.

        Returns:
            The ``TaskResult`` if one was yielded, otherwise ``None``.
        """
        from autogen_agentchat.base import TaskResult as _TaskResult

        last_result: TaskResult | None = None

        async for message in stream:
            if isinstance(message, _TaskResult):
                last_result = message
                continue

            source = getattr(message, "source", None)
            msg_type = type(message).__name__

            # Skip user messages
            if source == "user":
                continue

            # Skip tool execution events (already captured by wrap_tools)
            # and tool call summary messages
            if msg_type in ("ToolCallExecutionEvent", "ToolCallSummaryMessage"):
                continue

            content = getattr(message, "content", "")
            content_hash = hashlib.sha256(str(content).encode()).hexdigest()

            if msg_type == "ToolCallRequestEvent":
                self._log_action(
                    action_type=ActionType.TOOL_USE,
                    action_summary=f"Tool call requested by {source}",
                    action_detail_hash=content_hash,
                )
            else:
                # TextMessage, StopMessage, HandoffMessage, ThoughtEvent,
                # SelectSpeakerEvent, SelectorEvent → DECISION
                self._log_action(
                    action_type=ActionType.DECISION,
                    action_summary=f"Agent {source}: {msg_type}",
                    action_detail_hash=content_hash,
                )

        return last_result

    async def run(
        self,
        agent: Any,
        task: str,
    ) -> TaskResult | None:
        """Convenience: run agent with automatic audit capture.

        Equivalent to::

            await middleware.process_stream(agent.run_stream(task=task))

        Args:
            agent: An AutoGen ``AssistantAgent`` or any agent with
                ``run_stream(task=...)``.
            task: The task string to send to the agent.

        Returns:
            The ``TaskResult`` if one was yielded, otherwise ``None``.
        """
        return await self.process_stream(agent.run_stream(task=task))

    def get_verify_tool(self) -> Callable[..., Any]:
        """Return an async verification tool for the AutoGen ``tools=`` parameter.

        The returned function can be passed directly to
        ``AssistantAgent(tools=[...])``. AutoGen uses the function's name,
        docstring, and type hints to describe the tool to the LLM.

        Returns:
            An async callable compatible with AutoGen's tool interface.
        """
        from agentcert_autogen.tool import create_verify_tool

        return create_verify_tool(self)

    async def save(self, directory: str | None = None) -> None:
        """Async save — wraps the sync parent ``save()``.

        Args:
            directory: Optional override directory for this save.
        """
        super().save(directory)
