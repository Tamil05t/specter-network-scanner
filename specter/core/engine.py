"""Async scanning engine for Specter Network Scanner.

This module coordinates discovery, scanning, and fingerprinting using asyncio
with defensive error handling and resource cleanup. It implements a producer-
consumer model to distribute scan tasks and applies a token bucket rate limiter
for safe network utilization.
"""

from __future__ import annotations

import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Iterable, List, Optional

import aiohttp

from specter.core.rate_limiter import RateLimiter
from specter.core.task_queue import TaskItem, TaskQueue
from specter.models.dataclasses import Device, ScanResult
from specter.scanners.network_mapper import NetworkMapper
from specter.scanners.port_scanner import PortScanner
from specter.scanners.router_explorer import RouterExplorer
from specter.scanners.vuln_fingerprinter import VulnerabilityFingerprinter
from specter.utils.constants import DEFAULT_PORTS


@dataclass
class EngineConfig:
    """Runtime configuration for the scanner engine."""

    concurrency: int = 200
    rate_limit: float = 100.0
    bucket_capacity: int = 200
    request_timeout: float = 5.0
    scan_ports: Optional[List[int]] = None
    thread_workers: int = 4
    scan_delay: float = 0.0
    randomize_ports: bool = True
    syn_scan: bool = False
    decoy_scan: bool = False
    decoy_count: int = 3
    fragment_packets: bool = False
    fragment_size: int = 8


class ScannerEngine:
    """Main async engine for orchestrating the scanning workflow.

    The engine runs in phases:
      1. Discovery (network mapping)
      2. Port scanning
      3. Vulnerability fingerprinting
      4. Router exploration
    """

    def __init__(self, config: Optional[EngineConfig] = None) -> None:
        """Initialize engine dependencies and scanning modules.

        Args:
            config (Optional[EngineConfig]): Optional engine configuration overrides.

        Returns:
            None: Initializes internal modules.

        Raises:
            Exception: Unexpected initialization errors.

        Example:
            >>> engine = ScannerEngine(EngineConfig())

        Note:
            The engine creates module instances eagerly.
        """
        self._config = config or EngineConfig()
        self._logger = logging.getLogger("specter.engine")
        self._rate_limiter = RateLimiter(
            rate=self._config.rate_limit, capacity=self._config.bucket_capacity
        )
        self._executor = ThreadPoolExecutor(max_workers=self._config.thread_workers)
        self._packets_sent = 0

        self._network_mapper = NetworkMapper(timeout=self._config.request_timeout)
        self._port_scanner = PortScanner(
            timeout=self._config.request_timeout,
            concurrency=self._config.concurrency,
            scan_delay=self._config.scan_delay,
            randomize_ports=self._config.randomize_ports,
            syn_scan=self._config.syn_scan,
            decoy_scan=self._config.decoy_scan,
            decoy_count=self._config.decoy_count,
            fragment_packets=self._config.fragment_packets,
            fragment_size=self._config.fragment_size,
        )
        self._vuln_fingerprinter = VulnerabilityFingerprinter(
            timeout=self._config.request_timeout
        )
        self._router_explorer = RouterExplorer(timeout=self._config.request_timeout)
        self.current_devices: List[Device] = []

    async def run(self, targets: Iterable[str]) -> ScanResult:
        """Run the full scan workflow.

        Args:
            targets (Iterable[str]): Iterable of target IP addresses or hostnames.

        Returns:
            ScanResult: Populated result object.

        Raises:
            Exception: Unexpected runtime failures.

        Example:
            >>> result = await engine.run(["127.0.0.1"])

        Note:
            Module failures are logged and the scan continues.
        """

        start_time = time.monotonic()
        devices: List[Device] = []
        timeout = aiohttp.ClientTimeout(total=self._config.request_timeout)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            try:
                devices = await self._network_mapper.discover(
                    targets=targets, rate_limiter=self._rate_limiter
                )
            except Exception:
                self._logger.exception(
                    "Network discovery failed, falling back to raw targets"
                )
                devices = [Device(ip=t) for t in targets]

            self.current_devices = devices

            ports = self._config.scan_ports or DEFAULT_PORTS
            try:
                await self._run_port_scans(devices, ports)
            except Exception:
                self._logger.exception("Port scanning failed, continuing")

            try:
                await self._run_fingerprinting(devices, session)
            except Exception:
                self._logger.exception(
                    "Vulnerability fingerprinting failed, continuing"
                )

            try:
                await self._run_router_exploration(devices, session)
            except Exception:
                self._logger.exception("Router exploration failed, continuing")

        duration = time.monotonic() - start_time
        return ScanResult(
            devices=devices,
            scan_duration=duration,
            packets_sent=self._packets_sent,
            correlation_matches=0,
        )

    async def _run_port_scans(self, devices: List[Device], ports: List[int]) -> None:
        """Scan device ports with worker queue.

        Args:
            devices (List[Device]): Devices to scan.
            ports (List[int]): List of ports to probe.

        Returns:
            None: Updates device objects in-place.

        Raises:
            Exception: Worker execution errors are logged by callers.

        Example:
            >>> await engine._run_port_scans(devices, [22, 80])

        Note:
            Uses a bounded worker pool for scanning.
        """
        queue = TaskQueue()
        worker_count = max(1, min(self._config.concurrency, 500))
        queue.start_workers(worker_count)

        async def schedule(device: Device) -> None:
            """
            Docstring.

            Args:
                TODO
            Returns:
                TODO
            Raises:
                TODO
            Example:
                TODO
            """

            async def task() -> None:
                """
                Docstring.

                Args:
                    TODO
                Returns:
                    TODO
                Raises:
                    TODO
                Example:
                    TODO
                """
                await self._rate_limiter.acquire()
                await self._port_scanner.scan_device(device, ports, self._rate_limiter)

            await queue.put(TaskItem(name=f"port-scan-{device.ip}", coro_factory=task))

        for device in devices:
            await schedule(device)

        await queue.join()
        await queue.stop(worker_count)
        await queue.wait_workers()

    async def _run_fingerprinting(
        self, devices: List[Device], session: aiohttp.ClientSession
    ) -> None:
        """Fingerprint devices for vulnerabilities using HTTP checks.

        Args:
            devices (List[Device]): Devices to fingerprint.
            session (aiohttp.ClientSession): Shared HTTP session for probes.

        Returns:
            None: Updates device objects in-place.

        Raises:
            Exception: Worker execution errors are logged by callers.

        Example:
            >>> await engine._run_fingerprinting(devices, session)

        Note:
            HTTP probes are rate limited.
        """
        queue = TaskQueue()
        worker_count = max(1, min(self._config.concurrency, 300))
        queue.start_workers(worker_count)

        async def schedule(device: Device) -> None:
            """
            Docstring.

            Args:
                TODO
            Returns:
                TODO
            Raises:
                TODO
            Example:
                TODO
            """

            async def task() -> None:
                """
                Docstring.

                Args:
                    TODO
                Returns:
                    TODO
                Raises:
                    TODO
                Example:
                    TODO
                """
                await self._rate_limiter.acquire()
                await self._vuln_fingerprinter.fingerprint(
                    device, session, self._rate_limiter
                )

            await queue.put(
                TaskItem(name=f"fingerprint-{device.ip}", coro_factory=task)
            )

        for device in devices:
            await schedule(device)

        await queue.join()
        await queue.stop(worker_count)
        await queue.wait_workers()

    async def _run_router_exploration(
        self, devices: List[Device], session: aiohttp.ClientSession
    ) -> None:
        """Perform router discovery and safety checks.

        Args:
            devices (List[Device]): Devices to analyze for router traits.
            session (aiohttp.ClientSession): Shared HTTP session for probes.

        Returns:
            None: Updates device objects in-place.

        Raises:
            Exception: Worker execution errors are logged by callers.

        Example:
            >>> await engine._run_router_exploration(devices, session)

        Note:
            Router exploration is best-effort.
        """
        queue = TaskQueue()
        worker_count = max(1, min(self._config.concurrency, 200))
        queue.start_workers(worker_count)

        async def schedule(device: Device) -> None:
            """
            Docstring.

            Args:
                TODO
            Returns:
                TODO
            Raises:
                TODO
            Example:
                TODO
            """

            async def task() -> None:
                """
                Docstring.

                Args:
                    TODO
                Returns:
                    TODO
                Raises:
                    TODO
                Example:
                    TODO
                """
                await self._rate_limiter.acquire()
                await self._router_explorer.explore(device, session, self._rate_limiter)

            await queue.put(
                TaskItem(name=f"router-explore-{device.ip}", coro_factory=task)
            )

        for device in devices:
            await schedule(device)

        await queue.join()
        await queue.stop(worker_count)
        await queue.wait_workers()

    async def close(self) -> None:
        """Clean up resources like the executor.

        Args:
            None

        Returns:
            None: Shuts down background resources.

        Raises:
            Exception: Executor shutdown errors are suppressed.

        Example:
            >>> await engine.close()

        Note:
            The executor is shut down without waiting.
        """

        self._executor.shutdown(wait=False)


def install_uvloop() -> None:
    """Install uvloop if available and enabled by env.

    Args:
        None

    Returns:
        None: Installs uvloop in-place.

    Raises:
        Exception: Import errors are suppressed.

    Example:
        >>> install_uvloop()

    Note:
        Controlled via `SPECTER_USE_UVLOOP` env var.
    """

    if os.environ.get("SPECTER_USE_UVLOOP", "1") != "1":
        return
    try:
        import uvloop

        uvloop.install()
    except Exception:
        return
