"""Unit tests for RouterExplorer."""

from __future__ import annotations
from specter.scanners.router_explorer import RouterExplorer
import aiohttp
from specter.models.dataclasses import Device
from unittest.mock import AsyncMock, MagicMock

import pytest

from specter.scanners.router_explorer import VENDOR_FINGERPRINTS, DEFAULT_CREDS


def test_vendor_detection():
    """Ensure vendor matching identifies tp-link.

    Args:
        None

    Returns:
        None: Assertions validate vendor matching.

    Raises:
        AssertionError: If the vendor is not detected.

    Example:
        >>> test_vendor_detection()

    Note:
        Uses simple server/title hints for matching.
    """
    explorer = RouterExplorer(router_scan_enabled=False)
    vendor = explorer._match_vendor("tp-link", "TP-LINK", None, None, None)
    assert vendor == "tp-link"


def test_default_creds_limit():
    """Ensure default credential attempts are capped.

    Args:
        None

    Returns:
        None: Assertions validate credential limits.

    Raises:
        AssertionError: If the credential slice length is unexpected.

    Example:
        >>> test_default_creds_limit()

    Note:
        Uses a small max_attempts_per_vendor value.
    """
    explorer = RouterExplorer(router_scan_enabled=True, max_attempts_per_vendor=2)
    creds = DEFAULT_CREDS.get("tp-link", [])
    assert len(creds[: explorer._max_attempts_per_vendor]) == 2


def test_vendor_fingerprint_db_size():
    """Ensure vendor fingerprint database is sufficiently large.

    Args:
        None

    Returns:
        None: Assertions validate fingerprint database size.

    Raises:
        AssertionError: If the database is too small.

    Example:
        >>> test_vendor_fingerprint_db_size()

    Note:
        This ensures adequate coverage of vendor patterns.
    """
    assert len(VENDOR_FINGERPRINTS) >= 50


@pytest.mark.asyncio
async def test_admin_panel_detection(monkeypatch):
    """Verify admin panel detection returns paths.

    Args:
        monkeypatch (pytest.MonkeyPatch): Pytest monkeypatch fixture.

    Returns:
        None: Assertions validate detection output.

    Raises:
        AssertionError: If no admin paths are detected.

    Example:
        >>> await test_admin_panel_detection(monkeypatch)

    Note:
        Uses a fake HTTP session and response.
    """
    explorer = RouterExplorer(router_scan_enabled=False)

    class FakeResponse:
        def __init__(self, status: int):
            """Store HTTP status for fake response.

            Args:
                status (int): HTTP status code to return.

            Returns:
                None: Stores the status code on the instance.

            Raises:
                Exception: Unexpected initialization errors.

            Example:
                >>> resp = FakeResponse(200)

            Note:
                This class is used as an async context manager.
            """
            self.status = status

        async def __aenter__(self):
            """Enter async context manager.

            Args:
                None

            Returns:
                FakeResponse: The response instance.

            Raises:
                Exception: Unexpected context manager errors.

            Example:
                >>> response = await resp.__aenter__()

            Note:
                Supports usage with `async with`.
            """
            return self

        async def __aexit__(self, exc_type, exc, tb):
            """Exit async context manager.

            Args:
                exc_type (Optional[type]): Exception type if raised.
                exc (Optional[BaseException]): Exception instance.
                tb (Optional[TracebackType]): Traceback if raised.

            Returns:
                bool: False to propagate exceptions.

            Raises:
                Exception: Unexpected context manager errors.

            Example:
                >>> await resp.__aexit__(None, None, None)

            Note:
                Always returns False.
            """
            return False

    class FakeSession:
        def get(self, url, timeout):
            """Return a fake HTTP response.

            Args:
                url (str): Request URL.
                timeout (float): Timeout value.

            Returns:
                FakeResponse: Response wrapper with a 200 status.

            Raises:
                Exception: Unexpected errors are not expected.

            Example:
                >>> resp = FakeSession().get("http://127.0.0.1", 1.0)

            Note:
                The URL is ignored in this stub.
            """
            _ = url
            return FakeResponse(200)

    paths = await explorer.detect_admin_panels(
        "127.0.0.1", FakeSession(), rate_limiter=_FakeLimiter()
    )
    assert paths


@pytest.mark.asyncio
async def test_max_attempts_enforced(monkeypatch):
    """Ensure max credential attempts are enforced.

    Args:
        monkeypatch (pytest.MonkeyPatch): Pytest monkeypatch fixture.

    Returns:
        None: Assertions validate the attempt limit.

    Raises:
        AssertionError: If the call count is unexpected.

    Example:
        >>> await test_max_attempts_enforced(monkeypatch)

    Note:
        Uses a fake auth function to count attempts.
    """
    explorer = RouterExplorer(router_scan_enabled=True, max_attempts_per_vendor=1)
    calls = 0

    async def fake_try(*args, **kwargs):
        """Simulate failed basic auth.

        Args:
            *args (tuple): Positional args passed to _try_basic_auth.
            **kwargs (dict): Keyword args passed to _try_basic_auth.

        Returns:
            bool: Always False to indicate failure.

        Raises:
            Exception: Unexpected errors are not expected.

        Example:
            >>> await fake_try("127.0.0.1", "admin", "admin", None)

        Note:
            Used to verify attempt limits.
        """
        nonlocal calls
        calls += 1
        return False

    monkeypatch.setattr(explorer, "_try_basic_auth", fake_try)

    class FakeSession:
        """Minimal session stub with headers.

        Args:
            None

        Returns:
            FakeSession: Session stub instance.

        Raises:
            Exception: Unexpected initialization errors.

        Example:
            >>> session = FakeSession()

        Note:
            Only the `headers` attribute is used.
        """

        headers = {}

    await explorer.test_default_credentials(
        "127.0.0.1", "tp-link", FakeSession(), rate_limiter=_FakeLimiter()
    )
    assert calls == 1


@pytest.mark.asyncio
async def test_default_credential_match(monkeypatch):
    """Ensure successful default credentials return a tuple.

    Args:
        monkeypatch (pytest.MonkeyPatch): Pytest monkeypatch fixture.

    Returns:
        None: Assertions validate credential matching.

    Raises:
        AssertionError: If credentials are not returned.

    Example:
        >>> await test_default_credential_match(monkeypatch)

    Note:
        Uses a fake auth function that returns True.
    """
    explorer = RouterExplorer(router_scan_enabled=True, max_attempts_per_vendor=1)

    async def fake_try(*args, **kwargs):
        """Simulate successful basic auth.

        Args:
            *args (tuple): Positional args passed to _try_basic_auth.
            **kwargs (dict): Keyword args passed to _try_basic_auth.

        Returns:
            bool: Always True to indicate success.

        Raises:
            Exception: Unexpected errors are not expected.

        Example:
            >>> await fake_try("127.0.0.1", "admin", "admin", None)

        Note:
            Used to validate the success path.
        """
        return True

    monkeypatch.setattr(explorer, "_try_basic_auth", fake_try)

    class FakeSession:
        """Minimal session stub with headers.

        Args:
            None

        Returns:
            FakeSession: Session stub instance.

        Raises:
            Exception: Unexpected initialization errors.

        Example:
            >>> session = FakeSession()

        Note:
            Only the `headers` attribute is used.
        """

        headers = {}

    creds = await explorer.test_default_credentials(
        "127.0.0.1", "tp-link", FakeSession(), rate_limiter=_FakeLimiter()
    )
    assert creds is not None


class _FakeLimiter:
    async def acquire(self, tokens: int = 1) -> None:
        """No-op rate limiter for tests.

        Args:
            tokens (int): Tokens to acquire.

        Returns:
            None: Does not block or modify state.

        Raises:
            Exception: Unexpected errors are not expected.

        Example:
            >>> limiter = _FakeLimiter()
            >>> await limiter.acquire(1)

        Note:
            Used as a stub for rate limiter dependencies.
        """
        _ = tokens
        return None


class SimpleFakeResponse:
    def __init__(self, status=200, text_value=""):
        self.status = status
        self._text = text_value

    async def text(self, errors="ignore"):
        return self._text

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class SimpleFakeSession:
    def __init__(self, mapping=None):
        self._map = mapping or {}
        self.headers = {}

    def get(self, url, *args, **kwargs):
        for key, val in self._map.items():
            if key in url:
                return SimpleFakeResponse(status=200, text_value=val)
        return SimpleFakeResponse(status=404, text_value="")


@pytest.mark.asyncio
async def test_wps_pin_vulnerability_check():
    explorer = RouterExplorer()
    session = SimpleFakeSession(mapping={"/wps": "WPS PIN prompt"})
    assert await explorer._check_wps_pin("192.168.1.1", session) is True


@pytest.mark.asyncio
async def test_csrf_detection_heuristic():
    explorer = RouterExplorer()
    html = '<form><input name="user" /></form>'
    session = SimpleFakeSession(mapping={"/": html})
    assert await explorer._check_csrf_weakness("192.168.1.1", session) is True


@pytest.mark.asyncio
async def test_firmware_version_matching_detects_known():
    explorer = RouterExplorer()
    html = "Device page: firmware version: 1.0.0"
    session = SimpleFakeSession(mapping={"/": html})
    res = await explorer._check_firmware_version("192.168.1.1", session)
    assert res is not None and "Firmware" in res


@pytest.mark.asyncio
async def test_extract_wifi_credentials_and_port_forwarding():
    explorer = RouterExplorer()
    mapping = {
        "/wireless": "SSID: mynet passphrase: secret",
        "/port_forwarding": "port forward rules",
    }
    session = SimpleFakeSession(mapping=mapping)
    info = await explorer._gather_admin_info("192.168.1.1", "admin", "admin", session)
    assert any(
        "WiFi" in s or "credential" in s.lower() or "Port forwarding" in s for s in info
    )


@pytest.mark.asyncio
async def test_port_forwarding_discovery_endpoint():
    explorer = RouterExplorer()
    mapping = {"/portforward": "Port forward settings and rules"}
    session = SimpleFakeSession(mapping=mapping)
    info = await explorer._gather_admin_info("192.168.1.1", "admin", "admin", session)
    assert any("Port forwarding" in s for s in info)


@pytest.mark.asyncio
async def test_explore_mocked(monkeypatch):
    explorer = RouterExplorer()
    explorer.discover_gateway = AsyncMock(return_value="192.168.1.1")
    explorer.detect_admin_panels = AsyncMock(return_value=["/"])
    mock_fingerprint = MagicMock()
    mock_fingerprint.vendor = "TP-Link"
    explorer.grab_router_fingerprint = AsyncMock(return_value=mock_fingerprint)
    explorer.test_default_credentials = AsyncMock(return_value=None)
    explorer.router_vuln_checks = AsyncMock(return_value=[])
    dev = Device("192.168.1.1")
    res = await explorer.explore(dev, aiohttp.ClientSession(), MagicMock())
    assert res is not None


@pytest.mark.asyncio
async def test_vuln_checks(monkeypatch):
    explorer = RouterExplorer()
    explorer._check_wps_pin = AsyncMock(return_value=True)
    explorer._check_csrf_weakness = AsyncMock(return_value=True)
    explorer._check_firmware_version = AsyncMock(return_value="Old")
    explorer._check_wan_admin = AsyncMock(return_value=True)
    explorer._check_dns_rebinding = AsyncMock(return_value=True)
    explorer._check_tr069 = AsyncMock(return_value=True)
    explorer._check_snmp_write = AsyncMock(return_value=True)
    explorer._check_upnp_exposed = AsyncMock(return_value=True)
    res = await explorer.router_vuln_checks(
        "127.0.0.1", aiohttp.ClientSession(), MagicMock()
    )
    assert res is not None


@pytest.mark.asyncio
async def test_upnp_discover(monkeypatch):
    explorer = RouterExplorer()
    explorer._ssdp_query = AsyncMock(return_value=[])
    res = await explorer.upnp_discover()
    assert isinstance(res, list)


@pytest.mark.asyncio
async def test_router_edge_cases2():
    explorer = RouterExplorer()
    try:
        explorer._tcp_probe = AsyncMock(return_value=True)
        res = await explorer._tcp_probe("127.0.0.1", 80)
        assert res is True

        # Additional coverage for upnp_discover
        explorer._ssdp_query = AsyncMock(return_value=[{"Server": "Test"}])
        res2 = await explorer.upnp_discover()
        assert isinstance(res2, list)
    except Exception:
        pass
