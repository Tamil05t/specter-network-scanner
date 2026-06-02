"""Async vulnerability fingerprinting placeholder."""

from __future__ import annotations

from typing import List

import aiohttp

from specter.core.rate_limiter import RateLimiter
from specter.models.dataclasses import Device, Vulnerability


class VulnerabilityFingerprinter:
    """Lightweight HTTP header checks as a safe placeholder."""

    def __init__(self, timeout: float = 3.0) -> None:
        """Initialize fingerprinter with request timeout.

        Args:
            timeout (float): HTTP timeout in seconds.

        Returns:
            None: Initializes the fingerprinter.

        Raises:
            Exception: Unexpected initialization errors.

        Example:
            >>> vf = VulnerabilityFingerprinter(timeout=2.0)

        Note:
            This is a lightweight placeholder implementation.
        """
        self._timeout = timeout

    async def fingerprint(
        self,
        device: Device,
        session: aiohttp.ClientSession,
        rate_limiter: RateLimiter,
    ) -> Device:
        """Probe HTTP headers for basic vulnerability hints.

        Args:
            device (Device): Device record to update.
            session (aiohttp.ClientSession): HTTP client session.
            rate_limiter (RateLimiter): Rate limiter for outbound requests.

        Returns:
            Device: Updated device record.

        Raises:
            Exception: Request errors are suppressed.

        Example:
            >>> device = await vf.fingerprint(device, session, limiter)

        Note:
            Only HTTP headers are inspected.
        """
        vulns: List[Vulnerability] = []
        await rate_limiter.acquire()
        try:
            async with session.get(f"http://{device.ip}", timeout=self._timeout) as response:
                server = response.headers.get("Server")
                if server:
                    vulns.append(
                        Vulnerability(
                            cve_id="INFO",
                            description=f"Server header exposed: {server}",
                            severity="info",
                            affected_service="http",
                            exploit_db_id=None,
                        )
                    )
        except Exception:
            return device

        device.vulnerabilities.extend(vulns)
        return device
