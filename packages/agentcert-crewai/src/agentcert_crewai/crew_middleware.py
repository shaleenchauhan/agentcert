"""Multi-agent crew middleware with two-tier observation and coordinator identity."""

from __future__ import annotations

import hashlib
import logging
from typing import Any, TYPE_CHECKING

import agentcert
from agentcert.types import ActionType, KeyPair
from agentcert_middleware import BaseMiddleware, CoordinatorIdentity

from agentcert_crewai.middleware import AgentCertCrewAIMiddleware

if TYPE_CHECKING:
    from agentcert.types import AuditTrailVerificationResult, Certificate
    from agentcert_crewai.tool import AgentCertVerifyTool

logger = logging.getLogger("agentcert.middleware.crewai")


class AgentCertCrewMiddleware:
    """Multi-agent crew middleware with coordinator identity.

    Provides two-tier observation (Insight 12):

    - **Agent-level:** ``step_callback`` on each Agent captures per-step
      actions into agent-specific audit trails.
    - **Crew-level:** ``task_callback`` on each Task captures task
      completions into a coordinator audit trail.

    Coordinator identity (Decision D043, D046):

    - Auto-generated on first run, persisted to disk for reuse.
    - Overridable by power users via ``coordinator_keys``.
    - Coordinator is a specialized agent (uses existing Certificate schema).

    Example::

        crew_middleware = AgentCertCrewMiddleware(
            creator_keys=creator_keys,
            crew_name="research-writing-crew",
            agents={
                "researcher": {
                    "keys": researcher_keys,
                    "capabilities": ["web_search", "analysis"],
                    "risk_tier": 2,
                },
                "writer": {
                    "keys": writer_keys,
                    "capabilities": ["writing"],
                    "risk_tier": 1,
                },
            },
            storage="local",
        )

        researcher = Agent(
            role="Research Analyst",
            step_callback=crew_middleware.get_step_callback("researcher"),
            tools=[crew_middleware.get_verify_tool("researcher")],
        )

        research_task = Task(
            description="Research AI trust",
            agent=researcher,
            callback=crew_middleware.get_task_callback(),
        )

    Args:
        creator_keys: Path to creator keys file or KeyPair object.
        crew_name: Human-readable crew name.
        agents: Dict mapping agent names to config dicts. Each config
            must include ``"keys"`` (path or KeyPair) and may include
            ``"capabilities"``, ``"constraints"``, ``"risk_tier"``.
        coordinator_keys: Optional explicit coordinator keys (power user
            override).
        storage: Storage mode — ``"local"``, ``"service"``, or ``"both"``.
        storage_dir: Base directory for local audit storage.
        service_url: URL of the AgentCert managed service.
        api_key: Optional API key for service authentication.
        auto_save: Whether to persist entries automatically.
        **kwargs: Additional keyword arguments forwarded to BaseMiddleware.
    """

    def __init__(
        self,
        creator_keys: str | KeyPair,
        crew_name: str,
        agents: dict[str, dict[str, Any]],
        coordinator_keys: str | KeyPair | None = None,
        storage: str = "local",
        storage_dir: str = "./agentcert-audit/",
        service_url: str | None = None,
        api_key: str | None = None,
        auto_save: bool = False,
        **kwargs: Any,
    ) -> None:
        if isinstance(creator_keys, str):
            creator_keys = agentcert.load_keys(creator_keys)
        self._creator_keys = creator_keys
        self._crew_name = crew_name

        # Create per-agent middlewares
        self._agent_middlewares: dict[str, AgentCertCrewAIMiddleware] = {}
        for agent_name, agent_config in agents.items():
            self._agent_middlewares[agent_name] = AgentCertCrewAIMiddleware(
                creator_keys=creator_keys,
                agent_keys=agent_config["keys"],
                agent_name=agent_name,
                capabilities=agent_config.get("capabilities", []),
                constraints=agent_config.get("constraints", []),
                risk_tier=agent_config.get("risk_tier", 3),
                storage=storage,
                storage_dir=storage_dir,
                service_url=service_url,
                api_key=api_key,
                auto_save=auto_save,
                **kwargs,
            )

        # Get or create coordinator identity
        coord_keys, coord_cert = CoordinatorIdentity.get_or_create(
            creator_keys=creator_keys,
            coordinator_name=f"{crew_name}-coordinator",
            storage_dir=storage_dir,
            explicit_keys=coordinator_keys,
            capabilities=["orchestration", "task_delegation"],
        )

        # Create coordinator middleware (uses BaseMiddleware, not CrewAI-specific)
        self._coordinator_middleware = BaseMiddleware(
            creator_keys=creator_keys,
            agent_keys=coord_keys,
            agent_name=f"{crew_name}-coordinator",
            capabilities=["orchestration", "task_delegation"],
            storage=storage,
            storage_dir=storage_dir,
            service_url=service_url,
            api_key=api_key,
            auto_save=auto_save,
            platform="crewai-coordinator",
        )

    def get_step_callback(self, agent_name: str) -> Any:
        """Get the ``step_callback`` for a specific agent.

        Pass the return value as ``step_callback=`` to a CrewAI Agent.

        Args:
            agent_name: Name of the agent (must match a key in the
                ``agents`` dict passed to ``__init__``).

        Returns:
            A callable compatible with CrewAI's ``step_callback`` parameter.

        Raises:
            ValueError: If ``agent_name`` is not recognized.
        """
        if agent_name not in self._agent_middlewares:
            raise ValueError(
                f"Unknown agent: {agent_name}. "
                f"Known: {list(self._agent_middlewares.keys())}"
            )
        return self._agent_middlewares[agent_name].step_callback

    def get_task_callback(self) -> Any:
        """Get a task callback that logs to the coordinator trail.

        Pass the return value as ``callback=`` to a CrewAI Task.

        CrewAI calls ``callback(task_output)`` after task completion, where
        ``task_output`` is a ``TaskOutput`` with attributes: ``description``,
        ``agent``, ``raw``, ``summary``, ``name``, etc.

        Captures: task description, completing agent name, output hash.

        Returns:
            A callable compatible with CrewAI's ``Task(callback=...)``
            parameter.
        """

        def callback(task_output: Any) -> None:
            try:
                agent_name = str(getattr(task_output, "agent", "unknown"))
                description = str(
                    getattr(task_output, "description", "")
                )[:100]
                raw = str(getattr(task_output, "raw", ""))
                output_hash = hashlib.sha256(raw.encode()).hexdigest()

                self._coordinator_middleware._log_action(
                    action_type=ActionType.DECISION,
                    action_summary=f"Task completed by {agent_name}: {description}",
                    action_detail={
                        "agent": agent_name,
                        "description": description,
                        "output_hash": output_hash,
                    },
                )
            except Exception as e:
                logger.error(
                    "task_callback failed (non-interfering): %s", e
                )

        return callback

    def get_verify_tool(self, agent_name: str) -> AgentCertVerifyTool:
        """Get a verification tool bound to a specific agent's middleware.

        Args:
            agent_name: Name of the agent.

        Returns:
            An ``AgentCertVerifyTool`` bound to the specified agent.

        Raises:
            ValueError: If ``agent_name`` is not recognized.
        """
        if agent_name not in self._agent_middlewares:
            raise ValueError(
                f"Unknown agent: {agent_name}. "
                f"Known: {list(self._agent_middlewares.keys())}"
            )
        return self._agent_middlewares[agent_name].get_verify_tool()

    def verify_all(self) -> dict[str, AuditTrailVerificationResult]:
        """Verify all trails: each agent trail plus the coordinator trail.

        Returns:
            Dict mapping agent names (and ``"coordinator"``) to their
            ``AuditTrailVerificationResult``.
        """
        results: dict[str, Any] = {}
        for name, mw in self._agent_middlewares.items():
            results[name] = mw.verify()
        results["coordinator"] = self._coordinator_middleware.verify()
        return results

    def save(self, directory: str | None = None) -> None:
        """Save all agent trails and the coordinator trail.

        Args:
            directory: Optional override directory for this save.
        """
        for mw in self._agent_middlewares.values():
            mw.save(directory)
        self._coordinator_middleware.save(directory)

    @property
    def coordinator_certificate(self) -> Certificate:
        """The auto-generated coordinator's certificate."""
        return self._coordinator_middleware.certificate

    @property
    def crew_name(self) -> str:
        """The crew name."""
        return self._crew_name

    def get_agent_middleware(self, agent_name: str) -> AgentCertCrewAIMiddleware:
        """Get the middleware for a specific agent (for advanced use).

        Args:
            agent_name: Name of the agent.

        Returns:
            The ``AgentCertCrewAIMiddleware`` for the specified agent.

        Raises:
            KeyError: If ``agent_name`` is not recognized.
        """
        return self._agent_middlewares[agent_name]
