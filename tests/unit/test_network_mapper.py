"""Unit tests for NetworkMapper and DeviceClassifier."""

from __future__ import annotations

import pytest

from specter.scanners.network_mapper import DeviceClassifier, FingerprintData, NetworkMapper


def test_guess_os_by_ttl():
    """Verify TTL-based OS guessing returns a known label.

    Args:
        None

    Returns:
        None: Assertions validate OS guessing behavior.

    Raises:
        AssertionError: If the OS label is unexpected.

    Example:
        >>> test_guess_os_by_ttl()

    Note:
        TTL values are heuristics, not definitive.
    """
    classifier = DeviceClassifier()
    guess = classifier.guess_os(FingerprintData(ttl=128))
    assert guess.name in {"windows", "network_device", "linux", "unknown"}


def test_mac_oui_lookup():
    """Ensure OUI lookup maps MAC prefixes to vendors.

    Args:
        None

    Returns:
        None: Assertions validate OUI lookups.

    Raises:
        AssertionError: If the vendor lookup fails.

    Example:
        >>> test_mac_oui_lookup()

    Note:
        Prefix comparison is case-insensitive.
    """
    classifier = DeviceClassifier({"00:11:22": "TestVendor"})
    assert classifier.classify_by_mac_oui("00:11:22:33:44:55") == "TestVendor"


def test_device_classification_ports():
    """Ensure port-based classification yields server.

    Args:
        None

    Returns:
        None: Assertions validate port-based classification.

    Raises:
        AssertionError: If the expected classification is not returned.

    Example:
        >>> test_device_classification_ports()

    Note:
        This test uses a common HTTP port for classification.
    """
    classifier = DeviceClassifier()
    assert classifier.classify_by_open_ports([80]) == "server"


def test_arp_table_parsing(monkeypatch):
    """Verify ARP table parsing extracts MAC/IP entries.

    Args:
        monkeypatch (pytest.MonkeyPatch): Pytest monkeypatch fixture.

    Returns:
        None: Assertions validate ARP parsing behavior.

    Raises:
        AssertionError: If the parsed mapping is incorrect.

    Example:
        >>> test_arp_table_parsing(monkeypatch)

    Note:
        Uses a fake ARP output string for determinism.
    """
    mapper = NetworkMapper()

    def fake_check_output(*args, **kwargs):
        """Return a fake ARP table entry.

        Args:
            *args (tuple): Positional args passed to check_output.
            **kwargs (dict): Keyword args passed to check_output.

        Returns:
            str: Fake ARP output string.

        Raises:
            Exception: Unexpected errors are not expected.

        Example:
            >>> fake_check_output(["arp", "-a"])

        Note:
            Output format mirrors common OS ARP output.
        """
        return "? (192.168.1.1) at 00:11:22:33:44:55 [ether] on eth0"

    monkeypatch.setattr("subprocess.check_output", fake_check_output)
    table = mapper._read_arp_table()
    assert table.get("00:11:22:33:44:55") == "192.168.1.1"


@pytest.mark.asyncio
async def test_passive_fingerprint_parsing():
    """Verify passive fingerprint parsing extracts fields.

    Args:
        None

    Returns:
        None: Assertions validate passive fingerprint parsing.

    Raises:
        AssertionError: If parsed fields do not match expectations.

    Example:
        >>> await test_passive_fingerprint_parsing()

    Note:
        Uses a representative metadata sample.
    """
    mapper = NetworkMapper()
    fp = await mapper.passive_fingerprint(
        {
            "ttl": "128",
            "window": "64240",
            "dhcp_option_55": "1,3,6",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0)",
            "smb_negotiate": "SMB2",
        }
    )
    assert fp.ttl == 128
    assert 6 in fp.dhcp_options
    assert fp.ua_family == "windows"


@pytest.mark.asyncio
async def test_geolocation_traceroute(monkeypatch):
    from specter.scanners.network_mapper import NetworkMapper

    class FakeResp:
        def __init__(self, status=200, payload=None):
            self.status = status
            self._payload = payload or {}

        async def json(self):
            return self._payload

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

    class FakeClientSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        def get(self, url, timeout=5):
            return FakeResp(
                status=200,
                payload={
                    "status": "success",
                    "country": "Country",
                    "regionName": "Region",
                    "city": "City",
                    "isp": "ISP",
                },
            )

    mapper = NetworkMapper()
    # directly call geolocate helper with fake session by monkeypatching aiohttp.ClientSession
    monkeypatch.setattr("aiohttp.ClientSession", FakeClientSession)
    geo = await mapper._geolocate_ip("8.8.8.8")
    assert geo is not None and "country" in geo


def test_mac_oui_lookup_all_formats():
    from specter.scanners.network_mapper import DeviceClassifier

    classifier = DeviceClassifier({"00:11:22": "VendorA", "AA:BB:CC": "VendorB"})
    assert classifier.classify_by_mac_oui("00-11-22-33-44-55") == "VendorA"
    assert classifier.classify_by_mac_oui("aa:bb:cc:dd:ee:ff") == "VendorB"


@pytest.mark.asyncio
async def test_active_fingerprint_tcp_options(monkeypatch):
    # Simulate scapy reply with TCP options
    import types, sys
    from specter.scanners.network_mapper import NetworkMapper

    class FakeReply:
        ttl = 64
        window = 1024
        options = [("MSS", 1460), ("TS", (0, 0))]

        def haslayer(self, proto):
            return True

        def getlayer(self, proto):
            return self

        def sprintf(self, fmt):
            return "S"

    def fake_sr1(pkt, timeout=None, verbose=False):
        return FakeReply()

    scapy_all = types.ModuleType("scapy.all")
    scapy_all.sr1 = fake_sr1
    scapy_all.IP = object
    scapy_all.TCP = object
    scapy_all.ICMP = object
    monkeypatch.setitem(sys.modules, "scapy", types.ModuleType("scapy"))
    monkeypatch.setitem(sys.modules, "scapy.all", scapy_all)

    mapper = NetworkMapper()
    fp = await mapper.active_fingerprint("127.0.0.1")
    assert isinstance(fp.tcp_options, list)
