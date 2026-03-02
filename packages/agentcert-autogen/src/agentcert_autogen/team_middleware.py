"""Multi-agent team middleware for AutoGen.

Handles all three team types:
    - ``RoundRobinGroupChat``: coordinator logs agent turn order
    - ``SelectorGroupChat``: coordinator logs LLM selection decisions
    - ``MagenticOneGroupChat``: coordinator logs orchestrator planning

Each agent gets its own audit trail and certificate; a coordinator
identity captures team-level orchestration events.
"""

from __future__ import annotations

import hashlib
import logging
from typing import TYPE_CHECKING, Any, Callable

import agentcert
from agentcert.types import ActionType
from agentcert_middleware import BaseMiddleware, CoordinatorIdentity

from agentcert_autogen.middleware import AgentCertAutoGenMiddleware

if TYPE_CHECKING:
    from autogen_agentchat.base import TaskResult

logger = logging.getLogger("agentcert.autogen.team")


class AgentCertTeamMiddleware:
    """Multi-agent team middleware for AutoGen.

    Creates per-agent audit trails and a coordinator trail for
    team-level orchestration events.

    Handles all three AutoGen team types:
        - ``RoundRobinGroupChat``: coordinator logs agent turn order
        - ``SelectorGroupChat``: coordinator logs LLM selection decisions
        - ``MagenticOneGroupChat``: coordinator logs orchestrator planning

    Usage::

        team_middleware = AgentCertTeamMiddleware(
            creator_keys="creator.keys.json",
            team_name="research-team",
            agents={
                "researcher": {
                    "keys": "researcher.keys.json",
                    "capabilities": ["web_search"],
                },
                "analyst": {
                    "keys": "analyst.keys.json",
                    "capabilities": ["analysis"],
                },
            },
            storage="both",
            service_url="https://agentcert.dev",
        )

        researcher = AssistantAgent(
            name="researcher",
            model_client=model_client,
            tools=team_middleware.wrap_tools("researcher", [search_web]),
        )
        analyst = AssistantAgent(
            name="analyst",
            model_client=model_client,
        )

        team = SelectorGroupChat(
            participants=[researcher, analyst],
            model_client=model_client,
        )

        result = await team_middleware.run(team, "Research and analyze AI trust")
        verification = team_middleware.verify_all()
        await team_middleware.save()

    Args:
        creator_keys: Path to creator keys file or KeyPair object.
        team_name: Human-readable team name.
        agents: Dict mapping agent name → config dict. Each config must
            have a ``"keys"`` field (path or KeyPair) and may have
            ``"capabilities"``, ``"constraints"``, ``"risk_tier"``.
        coordinator_keys: Optional explicit coordinator keys (override).
        storage: Storage mode — ``"local"``, ``"service"``, or ``"both"``.
        storage_dir: Base directory for local audit storage.
        service_url: URL of the AgentCert managed service.
        api_key: Optional API key for service authentication.
        auto_save: Persist entries automatically after each action.
        **kwargs: Additional arguments passed to per-agent middleware.
    """

    def __init__(
        self,
        creator_keys: str | Any,
        team_name: str,
        agents: dict[str, dict[str, Any]],
        coordinator_keys: str | Any | None = None,
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
        self._team_name = team_name

        # Per-agent middlewares
        self._agent_middlewares: dict[str, AgentCertAutoGenMiddleware] = {}
        for agent_name, config in agents.items():
            self._agent_middlewares[agent_name] = AgentCertAutoGenMiddleware(
                creator_keys=creator_keys,
                agent_keys=config["keys"],
                agent_name=agent_name,
                capabilities=config.get("capabilities", []),
                constraints=config.get("constraints", []),
                risk_tier=config.get("risk_tier", 3),
                storage=storage,
                storage_dir=storage_dir,
                service_url=service_url,
                api_key=api_key,
                auto_save=auto_save,
                **kwargs,
            )

        # Coordinator identity (Decision D043 three-tier strategy)
        coord_keys, coord_cert = CoordinatorIdentity.get_or_create(
            creator_keys=creator_keys,
            coordinator_name=f"{team_name}-coordinator",
            storage_dir=storage_dir,
            explicit_keys=coordinator_keys,
        )

        self._coordinator_middleware = BaseMiddleware(
            creator_keys=creator_keys,
            agent_keys=coord_keys,
            agent_name=f"{team_name}-coordinator",
            capabilities=["orchestration", "task_delegation"],
            storage=storage,
            storage_dir=storage_dir,
            service_url=service_url,
            api_key=api_key,
            auto_save=auto_save,
            platform="coordinator",
        )

    @property
    def team_name(self) -> str:
        """The team name."""
        return self._team_name

    @property
    def agent_middlewares(self) -> dict[str, AgentCertAutoGenMiddleware]:
        """Per-agent middleware instances keyed by agent name."""
        return dict(self._agent_middlewares)

    @property
    def coordinator(self) -> BaseMiddleware:
        """The coordinator middleware instance."""
        return self._coordinator_middleware

    def wrap_tools(
        self, agent_name: str, tools: list[Callable[..., Any]]
    ) -> list[Callable[..., Any]]:
        """Wrap tools for a specific agent.

        Args:
            agent_name: Name of the agent whose tools to wrap.
            tools: List of callable tool functions.

        Returns:
            List of wrapped callables with identical signatures.

        Raises:
            ValueError: If agent_name is not a registered agent.
        """
        if agent_name not in self._agent_middlewares:
            raise ValueError(
                f"Unknown agent: {agent_name!r}. "
                f"Registered agents: {list(self._agent_middlewares.keys())}"
            )
        return self._agent_middlewares[agent_name].wrap_tools(tools)

    async def run(self, team: Any, task: str) -> TaskResult | None:
        """Process team's ``run_stream()``, routing events to correct trails.

        Event routing by ``message.source``:
            - Source matches a registered agent name → route to that agent's trail
            - Source is unrecognized or a team-level event → route to coordinator trail

        Coordinator trail captures:
            - ``SelectSpeakerEvent`` / ``SelectorEvent`` (agent selection)
            - Agent transition events
            - Unattributed team-level events

        Args:
            team: An AutoGen team (``RoundRobinGroupChat``,
                ``SelectorGroupChat``, or ``MagenticOneGroupChat``).
            task: The task string to send to the team.

        Returns:
            The ``TaskResult`` if one was yielded, otherwise ``None``.
        """
        from autogen_agentchat.base import TaskResult as _TaskResult

        last_result: TaskResult | None = None

        async for message in team.run_stream(task=task):
            if isinstance(message, _TaskResult):
                last_result = message
                continue

            source = getattr(message, "source", None)
            msg_type = type(message).__name__

            # Skip user messages
            if source == "user":
                continue

            # Skip tool execution events and summaries (logged by wrap_tools)
            if msg_type in ("ToolCallExecutionEvent", "ToolCallSummaryMessage"):
                continue

            content = getattr(message, "content", "")
            content_hash = hashlib.sha256(str(content).encode()).hexdigest()

            if source in self._agent_middlewares:
                # Route to agent's trail
                agent_mw = self._agent_middlewares[source]
                if msg_type == "ToolCallRequestEvent":
                    agent_mw._log_action(
                        action_type=ActionType.TOOL_USE,
                        action_summary=f"Tool call requested by {source}",
                        action_detail_hash=content_hash,
                    )
                else:
                    agent_mw._log_action(
                        action_type=ActionType.DECISION,
                        action_summary=f"Agent {source}: {msg_type}",
                        action_detail_hash=content_hash,
                    )
            else:
                # Route to coordinator trail
                self._coordinator_middleware._log_action(
                    action_type=ActionType.DECISION,
                    action_summary=f"Team event: {msg_type} from {source}",
                    action_detail_hash=content_hash,
                )

        return last_result

    def verify_all(self) -> dict[str, Any]:
        """Verify all trails: each agent + coordinator.

        Returns:
            Dict mapping agent names (and ``"coordinator"``) to their
            ``AuditTrailVerificationResult``.
        """
        results: dict[str, Any] = {}
        for name, mw in self._agent_middlewares.items():
            results[name] = mw.verify()
        results["coordinator"] = self._coordinator_middleware.verify()
        return results

    async def save(self, directory: str | None = None) -> None:
        """Save all trails (each agent + coordinator).

        Args:
            directory: Optional override directory for this save.
        """
        for mw in self._agent_middlewares.values():
            await mw.save(directory)
        self._coordinator_middleware.save(directory)

    def get_verify_tool(self, agent_name: str) -> Callable[..., Any]:
        """Get verification tool for a specific agent.

        Args:
            agent_name: Name of the agent.

        Returns:
            An async callable compatible with AutoGen's ``tools=`` parameter.

        Raises:
            ValueError: If agent_name is not a registered agent.
        """
        if agent_name not in self._agent_middlewares:
            raise ValueError(
                f"Unknown agent: {agent_name!r}. "
                f"Registered agents: {list(self._agent_middlewares.keys())}"
            )
        return self._agent_middlewares[agent_name].get_verify_tool()
