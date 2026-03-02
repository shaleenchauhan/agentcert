"""Single-agent CrewAI middleware with AgentCert audit trail."""

from __future__ import annotations

import hashlib
import logging
from typing import TYPE_CHECKING, Any

from agentcert.types import ActionType
from agentcert_middleware import BaseMiddleware

if TYPE_CHECKING:
    from agentcert_crewai.tool import AgentCertVerifyTool

logger = logging.getLogger("agentcert.middleware.crewai")


class AgentCertCrewAIMiddleware(BaseMiddleware):
    """Single-agent CrewAI middleware with cryptographic audit trail.

    Extends BaseMiddleware to provide a ``step_callback`` compatible with
    CrewAI's ``Agent(step_callback=...)`` parameter.

    CrewAI invokes ``step_callback(step_output)`` after each agent step, where
    ``step_output`` is one of:

    - ``AgentAction`` — tool invocation (has ``.tool``, ``.tool_input``,
      ``.thought``, ``.text``)
    - ``AgentFinish`` — final answer (has ``.output``, ``.thought``,
      ``.text``)
    - ``ToolResult`` — raw tool output (has ``.result``)

    Each step is mapped to an ActionType and logged to the agent's audit trail.

    Example::

        middleware = AgentCertCrewAIMiddleware(
            creator_keys=creator_keys,
            agent_keys=agent_keys,
            agent_name="research-agent",
            capabilities=["web_search"],
            risk_tier=2,
        )

        agent = Agent(
            role="Research Analyst",
            goal="Find comprehensive data",
            tools=[middleware.get_verify_tool()],
            step_callback=middleware.step_callback,
        )

    Args:
        creator_keys: Path to creator keys file or KeyPair object.
        agent_keys: Path to agent keys file or KeyPair object.
        agent_name: Human-readable agent name.
        capabilities: Agent capabilities for the certificate.
        constraints: Agent constraints for the certificate.
        risk_tier: Risk tier for the certificate (1-5).
        storage: Storage mode — ``"local"``, ``"service"``, or ``"both"``.
        storage_dir: Base directory for local audit storage.
        service_url: URL of the AgentCert managed service.
        api_key: Optional API key for service authentication.
        auto_save: Whether to persist entries automatically.
        **kwargs: Additional keyword arguments passed to BaseMiddleware.
    """

    def __init__(
        self,
        creator_keys: Any,
        agent_keys: Any,
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
            platform="crewai",
            **kwargs,
        )

    def step_callback(self, step_output: Any) -> None:
        """CrewAI Agent step callback — logs each step to the audit trail.

        Pass as ``step_callback=middleware.step_callback`` to a CrewAI Agent.

        Maps CrewAI step output types to ActionTypes:

        - ``AgentAction`` (has ``.tool``) → ``ActionType.TOOL_USE``
        - ``AgentFinish`` (has ``.output``) → ``ActionType.DECISION``
        - ``ToolResult`` (has ``.result`` only) → ``ActionType.TOOL_USE``
        - Unrecognized type → ``ActionType.CUSTOM``

        NON-INTERFERING: This method catches all exceptions internally
        and never propagates them to CrewAI.

        Args:
            step_output: CrewAI step output — ``AgentAction``,
                ``AgentFinish``, or ``ToolResult``.
        """
        try:
            action_type, summary, detail = self._classify_step(step_output)
            self._log_action(
                action_type=action_type,
                action_summary=summary,
                action_detail=detail,
            )
        except Exception as e:
            logger.error("step_callback failed (non-interfering): %s", e)

    def _classify_step(
        self, step_output: Any
    ) -> tuple[ActionType, str, dict[str, str] | None]:
        """Classify a CrewAI step output into ActionType, summary, and detail.

        Args:
            step_output: The step output object from CrewAI.

        Returns:
            Tuple of (ActionType, summary string, optional detail dict).
        """
        # AgentAction — tool invocation (has .tool attribute)
        if hasattr(step_output, "tool"):
            tool_name = str(step_output.tool)
            tool_input = str(getattr(step_output, "tool_input", ""))
            thought = str(getattr(step_output, "thought", ""))
            input_hash = hashlib.sha256(tool_input.encode()).hexdigest()[:16]
            return (
                ActionType.TOOL_USE,
                f"Tool: {tool_name}",
                {
                    "tool": tool_name,
                    "input_hash": input_hash,
                    "thought_preview": thought[:200] if thought else "",
                },
            )

        # AgentFinish — final answer (has .output attribute)
        if hasattr(step_output, "output"):
            output = str(step_output.output)
            thought = str(getattr(step_output, "thought", ""))
            output_hash = hashlib.sha256(output.encode()).hexdigest()[:16]
            return (
                ActionType.DECISION,
                "Agent finished",
                {
                    "output_hash": output_hash,
                    "thought_preview": thought[:200] if thought else "",
                },
            )

        # ToolResult — raw tool output (has .result only)
        if hasattr(step_output, "result") and not hasattr(step_output, "tool"):
            result_str = str(step_output.result)
            result_hash = hashlib.sha256(result_str.encode()).hexdigest()[:16]
            return (
                ActionType.TOOL_USE,
                "Tool result received",
                {"result_hash": result_hash},
            )

        # Unrecognized — log as CUSTOM
        return (
            ActionType.CUSTOM,
            f"Unknown step: {type(step_output).__name__}",
            None,
        )

    def get_verify_tool(self) -> AgentCertVerifyTool:
        """Return a CrewAI BaseTool for peer certificate verification.

        Returns:
            An ``AgentCertVerifyTool`` bound to this middleware's TrustVerifier.
        """
        from agentcert_crewai.tool import AgentCertVerifyTool

        return AgentCertVerifyTool(middleware=self)
