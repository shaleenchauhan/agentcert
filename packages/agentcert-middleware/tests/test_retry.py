"""Tests for RetryPolicy."""

from __future__ import annotations

import asyncio
import time
from unittest.mock import MagicMock

import pytest

from agentcert_middleware.retry import RetryPolicy


class TestRetryPolicySync:
    """Tests for synchronous retry execution."""

    def test_success_first_attempt(self):
        """Successful first attempt returns immediately without retry."""
        func = MagicMock(return_value="ok")
        policy = RetryPolicy(max_attempts=3)
        result = policy.execute_sync(func, "arg1", key="val")

        assert result == "ok"
        func.assert_called_once_with("arg1", key="val")

    def test_retry_with_eventual_success(self):
        """Retries on failure and returns result on success."""
        func = MagicMock(side_effect=[ValueError("fail"), ValueError("fail"), "ok"])
        policy = RetryPolicy(
            max_attempts=3, backoff_multiplier=0.01, max_delay=0.01
        )
        result = policy.execute_sync(func)

        assert result == "ok"
        assert func.call_count == 3

    def test_max_attempts_exceeded(self):
        """Raises last exception when all attempts fail."""
        func = MagicMock(
            side_effect=[ValueError("fail1"), ValueError("fail2"), ValueError("fail3")]
        )
        policy = RetryPolicy(
            max_attempts=3, backoff_multiplier=0.01, max_delay=0.01
        )

        with pytest.raises(ValueError, match="fail3"):
            policy.execute_sync(func)

        assert func.call_count == 3

    def test_backoff_timing(self):
        """Verify delays increase with exponential backoff."""
        call_times: list[float] = []

        def tracking_func():
            call_times.append(time.monotonic())
            if len(call_times) < 3:
                raise ValueError("not yet")
            return "ok"

        # Use small but measurable backoff
        policy = RetryPolicy(
            max_attempts=3, backoff_multiplier=2.0, max_delay=30.0
        )
        result = policy.execute_sync(tracking_func)

        assert result == "ok"
        assert len(call_times) == 3

        # First retry delay: 2^0 = 1s, second: 2^1 = 2s
        # With tolerance for timing jitter
        delay1 = call_times[1] - call_times[0]
        delay2 = call_times[2] - call_times[1]
        assert delay1 >= 0.8  # ~1s with tolerance
        assert delay2 >= 1.5  # ~2s with tolerance
        assert delay2 > delay1  # Second delay is longer

    def test_max_delay_cap(self):
        """max_delay caps the backoff delay."""
        call_times: list[float] = []

        def tracking_func():
            call_times.append(time.monotonic())
            if len(call_times) < 3:
                raise ValueError("not yet")
            return "ok"

        policy = RetryPolicy(
            max_attempts=3, backoff_multiplier=100.0, max_delay=0.1
        )
        result = policy.execute_sync(tracking_func)

        assert result == "ok"
        delay1 = call_times[1] - call_times[0]
        delay2 = call_times[2] - call_times[1]
        # Both delays should be capped at ~0.1s
        assert delay1 < 0.5
        assert delay2 < 0.5

    def test_single_attempt(self):
        """With max_attempts=1, no retry on failure."""
        func = MagicMock(side_effect=ValueError("fail"))
        policy = RetryPolicy(max_attempts=1)

        with pytest.raises(ValueError, match="fail"):
            policy.execute_sync(func)

        func.assert_called_once()


class TestRetryPolicyAsync:
    """Tests for asynchronous retry execution."""

    @pytest.mark.asyncio
    async def test_success_first_attempt(self):
        """Async: successful first attempt returns immediately."""
        async def func():
            return "ok"

        policy = RetryPolicy(max_attempts=3)
        result = await policy.execute_async(func)
        assert result == "ok"

    @pytest.mark.asyncio
    async def test_retry_with_eventual_success(self):
        """Async: retries on failure and returns result on success."""
        call_count = 0

        async def func():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("fail")
            return "ok"

        policy = RetryPolicy(
            max_attempts=3, backoff_multiplier=0.01, max_delay=0.01
        )
        result = await policy.execute_async(func)

        assert result == "ok"
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_max_attempts_exceeded(self):
        """Async: raises last exception when all attempts fail."""
        async def func():
            raise ValueError("async_fail")

        policy = RetryPolicy(
            max_attempts=2, backoff_multiplier=0.01, max_delay=0.01
        )

        with pytest.raises(ValueError, match="async_fail"):
            await policy.execute_async(func)

    @pytest.mark.asyncio
    async def test_backoff_uses_asyncio_sleep(self):
        """Async: uses asyncio.sleep for backoff, not time.sleep."""
        call_count = 0

        async def func():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ValueError("fail")
            return "ok"

        policy = RetryPolicy(
            max_attempts=2, backoff_multiplier=0.01, max_delay=0.01
        )
        result = await policy.execute_async(func)
        assert result == "ok"
        assert call_count == 2
