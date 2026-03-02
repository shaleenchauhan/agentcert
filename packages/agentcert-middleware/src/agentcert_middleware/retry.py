"""Exponential backoff retry policy for service submissions."""

from __future__ import annotations

import asyncio
import logging
import time

logger = logging.getLogger("agentcert.middleware")


class RetryPolicy:
    """Exponential backoff retry for service submissions.

    Used by ServiceStorage for resilient entry submission.
    Provides both sync and async variants.

    Args:
        max_attempts: Maximum number of attempts before giving up.
        backoff_multiplier: Multiplier for exponential delay between attempts.
        max_delay: Maximum delay in seconds between retries.
    """

    def __init__(
        self,
        max_attempts: int = 3,
        backoff_multiplier: float = 2.0,
        max_delay: float = 30.0,
    ) -> None:
        self.max_attempts = max_attempts
        self.backoff_multiplier = backoff_multiplier
        self.max_delay = max_delay

    def execute_sync(self, func: object, *args: object, **kwargs: object) -> object:
        """Execute func with retry. Returns result or raises last exception.

        Args:
            func: Callable to execute.
            *args: Positional arguments for func.
            **kwargs: Keyword arguments for func.

        Returns:
            The return value of func.

        Raises:
            Exception: The last exception if all attempts fail.
        """
        last_exception: Exception | None = None
        for attempt in range(self.max_attempts):
            try:
                return func(*args, **kwargs)  # type: ignore[operator]
            except Exception as e:
                last_exception = e
                if attempt < self.max_attempts - 1:
                    delay = min(
                        self.backoff_multiplier ** attempt, self.max_delay
                    )
                    logger.warning(
                        "Retry %d/%d after %.1fs: %s",
                        attempt + 1,
                        self.max_attempts,
                        delay,
                        e,
                    )
                    time.sleep(delay)
        raise last_exception  # type: ignore[misc]

    async def execute_async(
        self, func: object, *args: object, **kwargs: object
    ) -> object:
        """Async version of execute_sync.

        Args:
            func: Async callable to execute.
            *args: Positional arguments for func.
            **kwargs: Keyword arguments for func.

        Returns:
            The return value of func.

        Raises:
            Exception: The last exception if all attempts fail.
        """
        last_exception: Exception | None = None
        for attempt in range(self.max_attempts):
            try:
                return await func(*args, **kwargs)  # type: ignore[operator]
            except Exception as e:
                last_exception = e
                if attempt < self.max_attempts - 1:
                    delay = min(
                        self.backoff_multiplier ** attempt, self.max_delay
                    )
                    logger.warning(
                        "Retry %d/%d after %.1fs: %s",
                        attempt + 1,
                        self.max_attempts,
                        delay,
                        e,
                    )
                    await asyncio.sleep(delay)
        raise last_exception  # type: ignore[misc]
