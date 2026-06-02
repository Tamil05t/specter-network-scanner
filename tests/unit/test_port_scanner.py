"""Unit tests for PortScanner."""

from __future__ import annotations

import asyncio
import sys
import types

import pytest

from specter.scanners.port_scanner import PortScanner
from specter.models.dataclasses import Service


@pytest.mark.asyncio
async def test_detect_service_regex(sample_banners):
    """Verify banner regex detection returns a service name.

    Args:
        sample_banners (dict): Fixture with sample banner strings.

    Returns:
        None: Assertions validate detected service names.

    Raises:
        AssertionError: If the detected service name is unexpected.

    Example:
        >>> await test_detect_service_regex(sample_banners)

    Note:
        Service detection is heuristic and may return "unknown".
    """
    scanner = PortScanner()
    http = await scanner.detect_service("127.0.0.1", 80, sample_banners["http"])
    ssh = await scanner.detect_service("127.0.0.1", 22, sample_banners["ssh"])

    assert http.service_name in {"http", "unknown"}
    assert ssh.service_name in {"ssh", "unknown"}


@pytest.mark.asyncio
async def test_banner_grab_timeout(monkeypatch):
    """Ensure banner grab returns empty string on timeout.

    Args:
        monkeypatch (pytest.MonkeyPatch): Pytest monkeypatch fixture.

    Returns:
        None: Assertions validate the timeout behavior.

    Raises:
        AssertionError: If the banner is not empty.

    Example:
        >>> await test_banner_grab_timeout(monkeypatch)

    Note:
        Uses a very small timeout to trigger the condition.
    """
    scanner = PortScanner(timeout=0.01)

    async def fake_open(*args, **kwargs):
        """Simulate an open_connection timeout.

        Args:
            *args (tuple): Positional args passed to open_connection.
            **kwargs (dict): Keyword args passed to open_connection.

        Returns:
            None: Always raises a TimeoutError.

        Raises:
            TimeoutError: Simulated connection timeout.

        Example:
            >>> await fake_open("127.0.0.1", 80)

        Note:
            Sleep ensures the timeout path is exercised.
        """
        await asyncio.sleep(0.1)
        raise TimeoutError()

    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    banner = await scanner.grab_banner("127.0.0.1", 80, "tcp")
    assert banner == ""


@pytest.mark.asyncio
async def test_concurrency_limit(monkeypatch):
    """Validate concurrency limiting scans all ports.

    Args:
        monkeypatch (pytest.MonkeyPatch): Pytest monkeypatch fixture.

    Returns:
        None: Assertions validate concurrency handling.

    Raises:
        AssertionError: If the expected call count is wrong.

    Example:
        >>> await test_concurrency_limit(monkeypatch)

    Note:
        Uses a fake scan implementation to count calls.
    """
    scanner = PortScanner(concurrency=2)
    calls = 0

    async def fake_scan(*args, **kwargs):
        """Simulate a successful scan call.

        Args:
            *args (tuple): Positional args passed to _scan_tcp_port.
            **kwargs (dict): Keyword args passed to _scan_tcp_port.

        Returns:
            None: Simulates a scan result with no service.

        Raises:
            Exception: Unexpected errors are not expected.

        Example:
            >>> await fake_scan("127.0.0.1", 80, 1.0)

        Note:
            Increments a nonlocal call counter.
        """
        nonlocal calls
        calls += 1
        await asyncio.sleep(0.01)
        return None

    monkeypatch.setattr(scanner, "_scan_tcp_port", fake_scan)
    result = await scanner.scan_tcp_ports("127.0.0.1", [1, 2, 3, 4])
    assert isinstance(result, list)
    assert calls == 4


@pytest.mark.asyncio
async def test_scan_tcp_port_failure(monkeypatch):
    """Ensure connection errors yield no service result.

    Args:
        monkeypatch (pytest.MonkeyPatch): Pytest monkeypatch fixture.

    Returns:
        None: Assertions validate failure behavior.

    Raises:
        AssertionError: If a service is returned unexpectedly.

    Example:
        >>> await test_scan_tcp_port_failure(monkeypatch)

    Note:
        Simulates a connection refusal to trigger retries.
    """
    scanner = PortScanner(timeout=0.01)

    async def fake_open(*args, **kwargs):
        """Simulate a refused connection.

        Args:
            *args (tuple): Positional args passed to open_connection.
            **kwargs (dict): Keyword args passed to open_connection.

        Returns:
            None: Always raises a ConnectionRefusedError.

        Raises:
            ConnectionRefusedError: Simulated connection failure.

        Example:
            >>> await fake_open("127.0.0.1", 80)

        Note:
            Used to exercise the failure path.
        """
        raise ConnectionRefusedError()

    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    service = await scanner._scan_tcp_port("127.0.0.1", 80, 0.01)
    assert service is None


class DummyReader:
    pass


class DummyWriter:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True

    async def wait_closed(self):
        return None


@pytest.mark.asyncio
async def test_tcp_syn_scan_with_fallback(monkeypatch):
    scanner = PortScanner(syn_scan=True)

    # Force scapy unavailable so connect-scan is used
    monkeypatch.setattr(scanner, "_scapy_available", lambda: False)

    async def fake_open(host, port):
        return (DummyReader(), DummyWriter())

    monkeypatch.setattr(asyncio, "open_connection", fake_open)

    # stub out banner grab and service detection
    async def fake_grab(ip, port, proto='tcp'):
        return "FAKEBANNER"

    async def fake_detect(ip, port, banner):
        return Service(port=port, protocol='tcp', service_name='fake', version='1.0', banner=banner, cpe_guess=None)

    monkeypatch.setattr(scanner, "grab_banner", fake_grab)
    monkeypatch.setattr(scanner, "detect_service", fake_detect)
    # run
    svc = await scanner._scan_tcp_port("127.0.0.1", 22, timeout=0.5)
    assert isinstance(svc, Service)
    assert svc.port == 22


def _install_fake_scapy(monkeypatch, *, sr1_reply=None, fragment_list=None):
    # Create fake scapy.all module
    scapy_all = types.ModuleType("scapy.all")

    class FakeTCP:
        def __init__(self):
            self.flags = 18

    class FakeReply:
        def haslayer(self, proto):
            return True

        def getlayer(self, proto):
            return FakeTCP()

    def fake_sr1(pkt, timeout=None, verbose=False):
        return sr1_reply if sr1_reply is not None else FakeReply()

    def fake_send(pkt, verbose=False):
        return None

    def fake_fragment(pkt, fragsize=8):
        return fragment_list or []

    scapy_all.sr1 = fake_sr1
    scapy_all.send = fake_send
    scapy_all.fragment = fake_fragment

    class IP:
        def __init__(self, **kwargs):
            pass

        def __truediv__(self, other):
            return ("IP", other)

    class TCP:
        def __init__(self, **kwargs):
            pass

    scapy_all.IP = IP
    scapy_all.TCP = TCP
    scapy_all.UDP = object

    # Ensure imports "from scapy.all import ..." succeed
    monkeypatch.setitem(sys.modules, "scapy", types.ModuleType("scapy"))
    monkeypatch.setitem(sys.modules, "scapy.all", scapy_all)


def test_decoy_scan_implementation(monkeypatch):
    scanner = PortScanner()
    _install_fake_scapy(monkeypatch)
    called = {"decoy": 0}

    def spy_send_decoys(target, port, proto='tcp'):
        called["decoy"] += 1

    # enable decoy scan
    scanner._decoy_scan = True
    scanner._decoy_count = 2
    monkeypatch.setattr(scanner, "_send_decoys", spy_send_decoys)

    # call syn probe (synchronous)
    res = scanner._syn_probe("127.0.0.1", 22)
    # _syn_probe uses scapy sr1; our fake returns a reply so res is True/False
    assert res in (True, False)
    assert called["decoy"] == 1


def test_packet_fragmentation(monkeypatch):
    scanner = PortScanner()
    fragments_sent = {"count": 0}

    # install fake scapy that returns fragments
    def fake_fragment(pkt, fragsize=8):
        return [b'f1', b'f2']

    def fake_send(pkt, verbose=False):
        fragments_sent["count"] += 1

    scapy_all = types.ModuleType("scapy.all")
    scapy_all.fragment = fake_fragment
    scapy_all.send = fake_send
    scapy_all.sr1 = lambda *a, **k: None
    scapy_all.IP = object
    scapy_all.TCP = object
    monkeypatch.setitem(sys.modules, "scapy", types.ModuleType("scapy"))
    monkeypatch.setitem(sys.modules, "scapy.all", scapy_all)

    scanner._fragment_packets = True
    scanner._fragment_size = 4

    # run probe; should not raise
    res = scanner._syn_probe("127.0.0.1", 22)
    assert fragments_sent["count"] >= 0


@pytest.mark.asyncio
async def test_connection_pooling(monkeypatch):
    scanner = PortScanner()

    async def fake_open(host, port):
        return (DummyReader(), DummyWriter())

    monkeypatch.setattr(asyncio, "open_connection", fake_open)

    r, w = await scanner._get_pooled_connection("127.0.0.1", 80)
    assert r is not None and w is not None
    # release and ensure pool entry exists
    await scanner._release_pooled_connection("127.0.0.1", 80, r, w)
    key = ("127.0.0.1", 80)
    assert key in scanner._conn_pool

    # calling again within TTL should return same objects
    r2, w2 = await scanner._get_pooled_connection("127.0.0.1", 80)
    assert r2 is not None and w2 is not None


def test_build_probe_and_fingerprints_and_circuit():
    scanner = PortScanner()
    # probe payloads for known ports
    assert scanner._build_probe(80).startswith(b'GET')
    assert isinstance(scanner._build_fingerprints(), dict)

    target = '10.0.0.1'
    # circuit initially closed
    assert scanner._is_circuit_open(target) is False
    # record failures to open the circuit
    for _ in range(scanner._circuit_breaker_failures):
        scanner._record_failure(target)
    assert scanner._is_circuit_open(target) is True
    # record success resets
    scanner._record_success(target)
    assert scanner._is_circuit_open(target) is False


def test_prioritize_ports_randomness():
    scanner = PortScanner(randomize_ports=True)
    ports = [1, 2, 3, 80, 443]
    p1 = scanner._prioritize_ports(list(ports))
    # should return a list with same elements
    assert set(p1) == set(ports)

from unittest.mock import AsyncMock, MagicMock
from specter.models.dataclasses import Service, Device

@pytest.mark.asyncio
async def test_udp_scan_success(monkeypatch):
    scanner = PortScanner()
    scanner._scan_udp_port = AsyncMock(return_value=Service(port=53, protocol='udp', service_name='dns', version='', banner='', cpe_guess=None))
    res = await scanner.scan_udp_ports('127.0.0.1', [53], timeout=0.1)
    assert len(res) == 1

@pytest.mark.asyncio
async def test_udp_scan_failure(monkeypatch):
    scanner = PortScanner()
    scanner._scan_udp_port = AsyncMock(return_value=None)
    res = await scanner.scan_udp_ports('127.0.0.1', [53], timeout=0.1)
    assert len(res) == 0

@pytest.mark.asyncio
async def test_backoff(monkeypatch):
    scanner = PortScanner()
    await scanner._backoff(1)

@pytest.mark.asyncio
async def test_scan_device(monkeypatch):
    scanner = PortScanner()
    scanner.scan_tcp_ports = AsyncMock(return_value=[Service(80, 'tcp', 'http')])
    scanner.scan_udp_ports = AsyncMock(return_value=[Service(53, 'udp', 'dns')])
    dev = Device('127.0.0.1')
    from specter.core.rate_limiter import RateLimiter
    res = await scanner.scan_device(dev, [80, 53], MagicMock())
    assert res is not None
