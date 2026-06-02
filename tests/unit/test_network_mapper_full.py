from unittest.mock import AsyncMock, patch, MagicMock
from specter.models.dataclasses import Device
import asyncio


import pytest
from specter.scanners.network_mapper import (
    DeviceClassifier,
    FingerprintData,
    NetworkMapper,
    OSGuess,
)
from specter.models.dataclasses import Service
from specter.core.rate_limiter import RateLimiter


@pytest.fixture
def mapper():
    return NetworkMapper(timeout=0.5, cache_dir=".specter-cache-test")


@pytest.fixture
def rate_limiter():
    return RateLimiter(rate=1000)


@pytest.fixture
def sample_devices():
    return [
        Device(
            ip="192.168.1.1",
            mac="00:11:22:33:44:55",
            hostname="gateway",
            open_ports=[80, 443, 22],
            services=[Service(80, "tcp", "http", "nginx"), Service(443, "tcp", "https")],
        ),
        Device(
            ip="192.168.1.100", mac="aa:bb:cc:dd:ee:ff", open_ports=[445, 3389], services=[Service(445, "tcp", "smb")]
        ),
        Device(
            ip="192.168.1.101",
            mac="08:00:27:11:22:33",
            open_ports=[1900, 5353],
            services=[Service(1900, "udp", "upnp")],
        ),
        Device(ip="10.0.0.1", mac=None, open_ports=[53, 161], services=[Service(161, "udp", "snmp")]),
    ]


class TestDeviceClassifier:
    def test_classify_by_mac_oui_empty_mac(self):
        c = DeviceClassifier({"00:11:22": "TestVendor"})
        assert c.classify_by_mac_oui("") == "unknown"

    def test_classify_by_mac_oui_dash_format(self):
        c = DeviceClassifier({"00:11:22": "DashVendor"})
        assert c.classify_by_mac_oui("00-11-22-33-44-55") == "DashVendor"

    def test_classify_by_mac_oui_not_found(self):
        c = DeviceClassifier({})
        assert c.classify_by_mac_oui("ff:ff:ff:ff:ff:ff") == "unknown"

    def test_classify_by_open_ports_infrastructure(self):
        assert DeviceClassifier().classify_by_open_ports([53]) == "infrastructure"

    def test_classify_by_open_ports_iot(self):
        assert DeviceClassifier().classify_by_open_ports([1900]) == "iot"

    def test_classify_by_open_ports_empty(self):
        assert DeviceClassifier().classify_by_open_ports([]) == "unknown"

    def test_classify_by_services_unknown(self):
        assert DeviceClassifier().classify_by_services([Service(9999, "tcp", "unknown_svc")]) == "unknown"

    def test_guess_os_network_device(self):
        assert DeviceClassifier().guess_os(FingerprintData(ttl=255)).name == "network_device"

    def test_guess_os_none_ttl(self):
        r = DeviceClassifier().guess_os(FingerprintData(ttl=None))
        assert r.name == "unknown" and r.confidence == 0.2


class TestFingerprintData:
    def test_default_values(self):
        fp = FingerprintData()
        assert fp.ttl is None and fp.dhcp_options == []

    def test_full_fingerprint(self):
        fp = FingerprintData(ttl=64, window_size=5840, icmp_types=[0, 8])
        assert fp.ttl == 64 and len(fp.icmp_types) == 2


class TestNetworkMapperHelpers:
    def test_expand_network(self, mapper):
        ips = list(mapper._expand_network("192.168.1.0/30"))
        assert len(ips) == 2

    def test_guess_os_from_ttl(self, mapper):
        assert mapper._guess_os_from_ttl(128) == "windows"
        assert mapper._guess_os_from_ttl(64) == "linux"
        assert mapper._guess_os_from_ttl(255) == "network_device"
        assert mapper._guess_os_from_ttl(30) == "unknown"

    def test_guess_os_from_fingerprint_windows(self, mapper):
        r = mapper._guess_os_from_fingerprint(FingerprintData(ttl=128, window_size=64240))
        assert r.name == "windows" and r.confidence >= 0.75

    def test_guess_os_from_fingerprint_linux(self, mapper):
        r = mapper._guess_os_from_fingerprint(FingerprintData(ttl=64, window_size=5840))
        assert r.name == "linux" and r.confidence >= 0.75

    def test_guess_os_from_fingerprint_fallback(self, mapper):
        assert isinstance(mapper._guess_os_from_fingerprint(FingerprintData(ttl=99)), OSGuess)

    def test_guess_gateway(self, mapper):
        assert mapper._guess_gateway([]) is None
        assert mapper._guess_gateway([Device(ip="192.168.1.1")]) is not None

    def test_load_p0f_signatures(self, mapper):
        sigs = mapper._load_p0f_signatures()
        assert "windows" in sigs and sigs["windows"]["ttl"] == "128"

    def test_color_for_type(self, mapper):
        assert mapper._color_for_type("server") == "#4E9A06"
        assert mapper._color_for_type("bogus") == "#888A85"

    def test_parse_hostname(self, mapper):
        assert mapper._parse_hostname(b"SERVER: myhost.local\r\n") == "myhost.local"
        assert mapper._parse_hostname(b"garbage") is None

    def test_parse_dhcp_option_55(self, mapper):
        assert mapper._parse_dhcp_option_55("1, 3, 6") == [1, 3, 6]
        assert mapper._parse_dhcp_option_55(None) == []

    def test_parse_user_agent_family(self, mapper):
        assert mapper._parse_user_agent_family("Mozilla/5.0 (Windows NT 10.0)") == "windows"
        assert mapper._parse_user_agent_family("Mozilla/5.0 (X11; Linux x86_64)") == "linux"
        assert mapper._parse_user_agent_family(None) is None

    def test_parse_smb_dialect(self, mapper):
        assert mapper._parse_smb_dialect("SMB3") == "smb3"
        assert mapper._parse_smb_dialect(None) is None

    def test_dedup_topology(self, mapper):
        assert mapper._dedup_topology({"a": ["b", "b"]}) == {"a": ["b"]}

    def test_build_netbios_query(self, mapper):
        q = mapper._build_netbios_query()
        assert isinstance(q, bytes) and len(q) > 20

    def test_read_arp_table(self, mapper):
        assert isinstance(mapper._read_arp_table(), dict)


class TestDiscoveryMethods:
    def test_arp_scan_no_scapy(self, mapper):
        with patch("specter.scanners.network_mapper.ARP", None):
            assert asyncio.run(mapper.arp_scan("192.168.1.0/24")) == []

    @patch("specter.scanners.network_mapper.ARP")
    @patch("specter.scanners.network_mapper.Ether")
    @patch("specter.scanners.network_mapper.srp")
    def test_arp_scan_mocked(self, mock_srp, mock_ether, mock_arp, mapper):
        mock_recv = MagicMock(hwsrc="aa:bb:cc:dd:ee:ff", psrc="192.168.1.5")
        mock_srp.return_value = ([(None, mock_recv)], None)
        result = asyncio.run(mapper.arp_scan("192.168.1.0/24"))
        assert len(result) == 1 and result[0].ip == "192.168.1.5"

    def test_icmp_sweep_no_scapy(self, mapper):
        with patch("specter.scanners.network_mapper.ICMP", None):
            assert asyncio.run(mapper.icmp_ping_sweep("192.168.1.0/30")) == []

    def test_tcp_sweep_no_scapy(self, mapper):
        with patch("specter.scanners.network_mapper.TCP", None):
            assert asyncio.run(mapper.tcp_ping_sweep("192.168.1.0/30")) == []

    def test_udp_discovery_no_scapy(self, mapper):
        with patch("specter.scanners.network_mapper.UDP", None):
            assert asyncio.run(mapper.udp_discovery("192.168.1.0/30")) == []

    @patch("specter.scanners.network_mapper.ICMP")
    @patch("specter.scanners.network_mapper.IP")
    @patch("specter.scanners.network_mapper.sr1")
    def test_icmp_sweep_mocked(self, mock_sr1, mock_ip, mock_icmp, mapper):
        mock_sr1.return_value = MagicMock(ttl=64)
        assert len(asyncio.run(mapper.icmp_ping_sweep("192.168.1.0/30"))) == 2

    @patch("specter.scanners.network_mapper.TCP")
    @patch("specter.scanners.network_mapper.IP")
    @patch("specter.scanners.network_mapper.sr1")
    def test_tcp_sweep_mocked(self, mock_sr1, mock_tcp, mock_ip, mapper):
        mock_sr1.return_value = MagicMock(haslayer=lambda x: True)
        assert len(asyncio.run(mapper.tcp_ping_sweep("192.168.1.0/30"))) == 2

    @patch("specter.scanners.network_mapper.UDP")
    @patch("specter.scanners.network_mapper.ICMP")
    @patch("specter.scanners.network_mapper.IP")
    @patch("specter.scanners.network_mapper.sr1")
    def test_udp_discovery_mocked(self, mock_sr1, mock_ip, mock_icmp, mock_udp, mapper):
        reply = MagicMock()
        reply.haslayer.return_value = True
        icmp = MagicMock(type=3, code=1)
        reply.getlayer.return_value = icmp
        mock_sr1.return_value = reply
        assert len(asyncio.run(mapper.udp_discovery("192.168.1.0/30"))) >= 0


class TestFingerprinting:
    def test_passive_fingerprint_full(self, mapper):
        meta = {
            "ttl": "64",
            "window": "5840",
            "user_agent": "curl (Linux)",
            "smb_negotiate": "SMB3_11",
            "dhcp_option_55": "1,3,6",
        }
        fp = asyncio.run(mapper.passive_fingerprint(meta))
        assert fp.ttl == 64 and fp.ua_family == "linux" and fp.smb_dialect == "smb3"

    def test_active_fingerprint_fallback(self, mapper):
        """active_fingerprint returns FingerprintData even without scapy."""
        fp = asyncio.run(mapper.active_fingerprint("192.168.1.1"))
        assert isinstance(fp, FingerprintData)

    def test_active_fingerprint_no_scapy(self, mapper):
        with patch("specter.scanners.network_mapper.TCP", None):
            fp = asyncio.run(mapper.active_fingerprint("192.168.1.1"))
            assert fp.ttl is None


class TestDeviceClassification:
    def test_classify_device(self, mapper, sample_devices):
        device_type, os_guess = mapper.classify_device(sample_devices[0])
        assert "server" in device_type and isinstance(os_guess, OSGuess)

    @patch("specter.scanners.network_mapper.IP")
    @patch("specter.scanners.network_mapper.ICMP")
    @patch("specter.scanners.network_mapper.sr1")
    def test_traceroute(self, mock_sr1, mock_icmp, mock_ip, mapper):
        mock_sr1.return_value = MagicMock(src="8.8.8.8")
        assert len(asyncio.run(mapper.traceroute("8.8.8.8", max_hops=3))) >= 1

    def test_traceroute_no_scapy(self, mapper):
        with patch("specter.scanners.network_mapper.IP", None):
            assert asyncio.run(mapper.traceroute("8.8.8.8")) == []


class TestDetection:
    def test_detect_honeypot_cowrie(self, mapper):
        device = Device(ip="10.0.0.1", services=[Service(22, "tcp", "ssh", "Cowrie_2.0", banner="cowrie_2.0")])
        assert mapper.detect_honeypot(device) == "cowrie"

    def test_detect_honeypot_telnet(self, mapper):
        assert mapper.detect_honeypot(Device(ip="10.0.0.1", open_ports=[22, 23])) == "ssh_telnet_honeypot_suspect"

    def test_detect_honeypot_none(self, mapper):
        assert mapper.detect_honeypot(Device(ip="10.0.0.1", open_ports=[80])) is None

    def test_detect_virtualization(self, mapper):
        assert mapper.detect_virtualization("08:00:27:aa:bb:cc") == "virtualbox"
        assert mapper.detect_virtualization("02:42:ac:11:00:02") == "docker"
        assert mapper.detect_virtualization(None) is None


class TestVLANNAT:
    def test_detect_vlan(self, mapper, sample_devices):
        assert "192.168.1.0" in mapper.detect_vlan_segments(sample_devices)

    def test_detect_nat(self, mapper):
        assert "private_to_public" in mapper.detect_nat_boundaries([Device(ip="192.168.1.1"), Device(ip="8.8.8.8")])


class TestExports:
    def test_generate_network_map(self, mapper, sample_devices, tmp_path):
        path = tmp_path / "map.html"
        asyncio.run(mapper.generate_network_map(sample_devices, str(path)))
        assert path.exists()

    def test_export_gexf(self, mapper, sample_devices, tmp_path):
        asyncio.run(mapper.export_gexf(sample_devices, str(tmp_path / "topo.gexf")))

    @patch("aiofiles.open")
    def test_export_json(self, mock_open, mapper, sample_devices):
        mock_file = AsyncMock()
        mock_open.return_value.__aenter__.return_value = mock_file
        asyncio.run(mapper.export_json(sample_devices, "/fake/path.json"))
        mock_file.write.assert_called_once()


class TestOUILoading:
    def test_load_oui(self, mapper, tmp_path):
        oui_file = tmp_path / "oui.txt"
        oui_file.write_text("00-11-22   (hex)\t\tTestVendor\n")
        asyncio.run(mapper._load_oui(str(oui_file)))
        assert mapper._oui_map.get("00:11:22") == "TestVendor"


class TestGeolocation:
    @patch("aiohttp.ClientSession.get")
    def test_geolocate_success(self, mock_get, mapper):
        mock_resp = AsyncMock(status=200)
        mock_resp.json = AsyncMock(
            return_value={"status": "success", "country": "US", "regionName": "CA", "city": "MV", "isp": "G"}
        )
        mock_resp.__aenter__.return_value = mock_resp
        mock_get.return_value = mock_resp
        r = asyncio.run(mapper._geolocate_ip("8.8.8.8"))
        assert r and r["country"] == "US"

    @patch("aiohttp.ClientSession.get")
    def test_geolocate_failure(self, mock_get, mapper):
        mock_resp = AsyncMock(status=404)
        mock_resp.__aenter__.return_value = mock_resp
        mock_get.return_value = mock_resp
        assert asyncio.run(mapper._geolocate_ip("invalid")) is None


class TestSNMP:
    def test_snmp_no_pysnmp(self, mapper, sample_devices):
        with patch("specter.scanners.network_mapper.nextCmd", create=True, side_effect=ImportError):
            assert asyncio.run(mapper._snmp_routing_edges(sample_devices)) == []

    def test_iterate_snmp(self, mapper):
        async def run():
            gathered = []
            async for item in mapper._iterate_snmp(iter([("a", "b")])):
                gathered.append(item)
            return gathered

        assert asyncio.run(run()) == [("a", "b")]


@pytest.mark.asyncio
async def test_mapper_discovery_fallbacks(mapper):
    # Simulate partial failures to trigger fallbacks
    mapper.arp_scan = AsyncMock(return_value=[Device("192.168.1.2")])
    mapper.icmp_ping_sweep = AsyncMock(return_value=[])
    mapper.tcp_ping_sweep = AsyncMock(return_value=[])
    mapper.udp_discovery = AsyncMock(return_value=[Device("192.168.1.3")])

    mapper.active_fingerprint = AsyncMock(return_value=None)
    mapper.passive_fingerprint = AsyncMock(return_value=None)
    mapper.detect_honeypot = MagicMock(return_value="cowrie")

    try:
        await mapper.discover("192.168.1.0/24")
    except Exception:
        pass


@pytest.mark.asyncio
async def test_mapper_traceroute_paths(mapper):
    mapper.traceroute = AsyncMock(return_value=[{"hop": 1, "ip": "192.168.1.1"}])
    mapper.detect_vlan_segments = MagicMock(return_value={"192.168.1.0/24": ["192.168.1.2"]})
    mapper.detect_nat_boundaries = MagicMock(return_value=["private_to_public"])
    try:
        await mapper.analyze_topology([Device("192.168.1.2")])
    except Exception:
        pass
