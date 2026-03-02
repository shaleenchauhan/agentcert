"""Shared test fixtures for agentcert-autogen tests."""

from __future__ import annotations

from typing import Any, Sequence

import pytest

import agentcert
from agentcert.types import KeyPair
from autogen_core import FunctionCall
from autogen_core.models import (
    ChatCompletionClient,
    CreateResult,
    ModelInfo,
    RequestUsage,
)


class MockModelClient(ChatCompletionClient):
    """Minimal mock for AutoGen's ChatCompletionClient.

    Accepts a list of responses. Each ``create()`` call returns the next
    response in order. String responses become ``TextMessage``; list-of-
    ``FunctionCall`` responses trigger tool calling.
    """

    def __init__(self, responses: list[str | list[FunctionCall]] | None = None) -> None:
        self._responses: list[str | list[FunctionCall]] = responses or ["Done."]
        self._idx = 0
        self._total = RequestUsage(prompt_tokens=0, completion_tokens=0)

    async def create(
        self,
        messages: Any,
        *,
        tools: Any = [],
        tool_choice: Any = "auto",
        json_output: Any = None,
        extra_create_args: Any = {},
        cancellation_token: Any = None,
    ) -> CreateResult:
        resp = self._responses[min(self._idx, len(self._responses) - 1)]
        self._idx += 1
        usage = RequestUsage(prompt_tokens=10, completion_tokens=5)
        self._total = RequestUsage(
            prompt_tokens=self._total.prompt_tokens + usage.prompt_tokens,
            completion_tokens=self._total.completion_tokens + usage.completion_tokens,
        )
        if isinstance(resp, str):
            return CreateResult(
                finish_reason="stop", content=resp, usage=usage, cached=False
            )
        return CreateResult(
            finish_reason="function_calls", content=resp, usage=usage, cached=False
        )

    def create_stream(self, messages: Any, **kwargs: Any) -> Any:
        raise NotImplementedError

    def count_tokens(self, messages: Any, *, tools: Any = []) -> int:
        return 0

    def remaining_tokens(self, messages: Any, *, tools: Any = []) -> int:
        return 4096

    def actual_usage(self) -> RequestUsage:
        return self._total

    def total_usage(self) -> RequestUsage:
        return self._total

    @property
    def model_info(self) -> ModelInfo:
        return ModelInfo(
            vision=False,
            function_calling=True,
            json_output=True,
            family="unknown",
            structured_output=True,
        )

    @property
    def capabilities(self) -> ModelInfo:
        return self.model_info

    async def close(self) -> None:
        pass


@pytest.fixture
def creator_keys() -> KeyPair:
    """Generate a fresh creator key pair."""
    return agentcert.generate_keys()


@pytest.fixture
def agent_keys() -> KeyPair:
    """Generate a fresh agent key pair."""
    return agentcert.generate_keys()


@pytest.fixture
def second_agent_keys() -> KeyPair:
    """Generate a second agent key pair (for team tests)."""
    return agentcert.generate_keys()


@pytest.fixture
def mock_client() -> MockModelClient:
    """Simple mock model client that returns a text response."""
    return MockModelClient(responses=["Test response."])


@pytest.fixture
def tool_calling_client() -> MockModelClient:
    """Mock model client that issues a tool call then a text response."""
    return MockModelClient(
        responses=[
            [FunctionCall(id="call_1", arguments='{"city": "London"}', name="get_weather")],
            "The weather is sunny.",
        ]
    )


@pytest.fixture
def tmp_storage_dir(tmp_path: Any) -> str:
    """Temporary directory for storage tests."""
    return str(tmp_path / "agentcert-audit")
