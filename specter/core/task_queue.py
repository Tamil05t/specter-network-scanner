"""Producer-consumer task queue for async scanning."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Awaitable, Callable, Optional

TaskCallable = Callable[[], Awaitable[None]]


@dataclass
class TaskItem:
    """Queue item wrapping an awaitable task."""

    name: str
    coro_factory: TaskCallable


class TaskQueue:
    """Async producer-consumer queue with worker management."""

    def __init__(self, maxsize: int = 0) -> None:
        """Create a task queue with optional max size.

        Args:
            maxsize (int): Max queue size before producers block.

        Returns:
            None: Initializes queue and worker list.

        Raises:
            Exception: Unexpected initialization errors.

        Example:
            >>> queue = TaskQueue(maxsize=100)

        Note:
            A maxsize of 0 means unbounded.
        """
        self._queue: asyncio.Queue[Optional[TaskItem]] = asyncio.Queue(maxsize=maxsize)
        self._workers: list[asyncio.Task[None]] = []

    async def put(self, item: TaskItem) -> None:
        """Enqueue a task item.

        Args:
            item (TaskItem): Task wrapper to enqueue.

        Returns:
            None: Enqueues item in the async queue.

        Raises:
            asyncio.CancelledError: If the coroutine is cancelled.

        Example:
            >>> await queue.put(TaskItem(name="t", coro_factory=task))

        Note:
            This call may block if the queue is full.
        """
        await self._queue.put(item)

    async def stop(self, worker_count: int) -> None:
        """Signal workers to stop by sending sentinel values.

        Args:
            worker_count (int): Number of workers to stop.

        Returns:
            None: Enqueues sentinel stop items.

        Raises:
            asyncio.CancelledError: If the coroutine is cancelled.

        Example:
            >>> await queue.stop(5)

        Note:
            One sentinel is added per worker.
        """
        for _ in range(worker_count):
            await self._queue.put(None)

    async def worker(self) -> None:
        """Worker loop that executes queued tasks.

        Args:
            None

        Returns:
            None: Runs until a sentinel is received.

        Raises:
            Exception: Task execution errors propagate to the task.

        Example:
            >>> await queue.worker()

        Note:
            Intended to be run as a background task.
        """
        while True:
            item = await self._queue.get()
            if item is None:
                self._queue.task_done()
                return
            try:
                await item.coro_factory()
            finally:
                self._queue.task_done()

    def start_workers(self, worker_count: int) -> None:
        """Start background worker tasks.

        Args:
            worker_count (int): Number of worker tasks to spawn.

        Returns:
            None: Creates background tasks.

        Raises:
            Exception: Task creation errors are propagated.

        Example:
            >>> queue.start_workers(10)

        Note:
            Workers are stored for later awaiting.
        """
        self._workers = [
            asyncio.create_task(self.worker()) for _ in range(worker_count)
        ]

    async def join(self) -> None:
        """Wait until all queued tasks complete.

        Args:
            None

        Returns:
            None: Returns when queue is empty.

        Raises:
            asyncio.CancelledError: If the coroutine is cancelled.

        Example:
            >>> await queue.join()

        Note:
            Call after enqueueing all tasks.
        """
        await self._queue.join()

    async def wait_workers(self) -> None:
        """Wait for worker tasks to exit.

        Args:
            None

        Returns:
            None: Waits for all worker tasks.

        Raises:
            Exception: Worker exceptions are captured by gather.

        Example:
            >>> await queue.wait_workers()

        Note:
            Uses `return_exceptions=True`.
        """
        if self._workers:
            await asyncio.gather(*self._workers, return_exceptions=True)
