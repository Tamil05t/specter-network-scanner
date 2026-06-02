"""Async network discovery and mapping with OS fingerprinting."""

from __future__ import annotations
import asyncio
import ipaddress
import json
import logging
import os
import random
import re
import socket
import struct
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Sequence, Tuple
import aiofiles
import aiohttp
from specter.core.rate_limiter import RateLimiter
from specter.models.dataclasses import Device, Service

try:
    from scapy.all import ARP, ICMP, IP, TCP, UDP, Ether, sr1, srp
except Exception:
    ARP = ICMP = IP = TCP = UDP = Ether = sr1 = srp = None
OUI_DB_URL = "https://standards-oui.ieee.org/oui/oui.txt"


@dataclass
class FingerprintData:
    ttl: Optional[int] = None
    window_size: Optional[int] = None
    df_bit: Optional[bool] = None
    dhcp_options: List[int] = field(default_factory=list)
    user_agent: Optional[str] = None
    smb_version: Optional[str] = None
    tcp_options: List[str] = field(default_factory=list)
    tcp_option_order: List[str] = field(default_factory=list)
    icmp_types: List[int] = field(default_factory=list)
    icmp_codes: List[int] = field(default_factory=list)
    tcp_flags: List[str] = field(default_factory=list)
    ua_family: Optional[str] = None
    smb_dialect: Optional[str] = None


@dataclass
class OSGuess:
    name: str
    confidence: float


class DeviceClassifier:
    """Classify devices based on MAC OUI, ports, and services."""

    def __init__(self, oui_map: Optional[Dict[str, str]] = None) -> None:
        """Initialize classifier with optional OUI mapping.

        Args:
            oui_map (Optional[Dict[str, str]]): Optional MAC OUI -> vendor map.

        Returns:
            None: Initializes the classifier.

        Raises:
            Exception: Unexpected initialization errors.

        Example:
            >>> classifier = DeviceClassifier({"00:11:22": "Vendor"})

        Note:
            OUI lookups are case-insensitive.
        """
        self._oui_map = oui_map or {}

    def classify_by_mac_oui(self, mac: str) -> str:
        """Classify device vendor from MAC OUI.

        Args:
            mac (str): MAC address string.

        Returns:
            str: Vendor name or "unknown".

        Raises:
            Exception: Unexpected parsing errors.

        Example:
            >>> classifier.classify_by_mac_oui("00:11:22:33:44:55")

        Note:
            Missing MACs return "unknown".
        """
        if not mac:
            return "unknown"
        prefix = mac.replace("-", ":").upper()[0:8]
        return self._oui_map.get(prefix, "unknown")

    def classify_by_open_ports(self, ports: List[int]) -> str:
        """Classify device type using open ports.

        Args:
            ports (List[int]): List of open port numbers.

        Returns:
            str: Device type label.

        Raises:
            Exception: Unexpected errors.

        Example:
            >>> classifier.classify_by_open_ports([80, 443])

        Note:
            Returns "unknown" when no ports are provided.
        """
        if not ports:
            return "unknown"
        if 53 in ports or 123 in ports or 161 in ports:
            return "infrastructure"
        if 80 in ports or 443 in ports or 22 in ports:
            return "server"
        if 445 in ports or 3389 in ports:
            return "workstation"
        if 1900 in ports or 5353 in ports:
            return "iot"
        return "unknown"

    def classify_by_services(self, services: List[Service]) -> str:
        """Classify device type using discovered services.

        Args:
            services (List[Service]): List of service records.

        Returns:
            str: Device type label.

        Raises:
            Exception: Unexpected errors.

        Example:
            >>> classifier.classify_by_services([Service(80, "tcp", "http")])

        Note:
            Service names are compared case-insensitively.
        """
        names = {svc.service_name.lower() for svc in services}
        if {"http", "https"} & names:
            return "server"
        if "smb" in names:
            return "workstation"
        if "upnp" in names or "ssdp" in names:
            return "iot"
        if "snmp" in names:
            return "infrastructure"
        return "unknown"

    def guess_os(self, fingerprints: FingerprintData) -> OSGuess:
        """Guess OS family based on TTL heuristics.

        Args:
            fingerprints (FingerprintData): Fingerprint data from probes.

        Returns:
            OSGuess: OS guess and confidence.

        Raises:
            Exception: Unexpected errors.

        Example:
            >>> classifier.guess_os(FingerprintData(ttl=128))

        Note:
            TTL heuristics are approximate.
        """
        if fingerprints.ttl is None:
            return OSGuess("unknown", 0.2)
        ttl = fingerprints.ttl
        if ttl >= 250:
            return OSGuess("network_device", 0.75)
        if ttl >= 120:
            return OSGuess("windows", 0.7)
        if ttl >= 60:
            return OSGuess("linux", 0.6)
        return OSGuess("unknown", 0.3)


class NetworkMapper:
    """Network discovery and OS fingerprinting engine."""

    def __init__(
        self, timeout: float = 1.0, cache_dir: str = ".specter-cache", logger: Optional[logging.Logger] = None
    ) -> None:
        """Initialize network discovery and fingerprinting engine.

        Args:
            timeout (float): Default probe timeout in seconds.
            cache_dir (str): Cache directory for OUI data.
            logger (Optional[logging.Logger]): Optional logger instance.

        Returns:
            None: Initializes the network mapper.

        Raises:
            Exception: Unexpected initialization errors.

        Example:
            >>> mapper = NetworkMapper(timeout=1.0)

        Note:
            OUI data is lazily loaded when needed.
        """
        self._timeout = timeout
        self._cache_dir = cache_dir
        self._logger = logger or logging.getLogger("specter.network")
        self._oui_map: Dict[str, str] = {}
        self._classifier = DeviceClassifier(self._oui_map)
        self._p0f_signatures = self._load_p0f_signatures()
        self._honeypot_signatures = {"cowrie": ["cowrie", "kippo"], "dionaea": ["dionaea"]}
        self._virtual_mac_prefixes = {
            "00:05:69": "vmware",
            "00:0C:29": "vmware",
            "00:1C:14": "vmware",
            "00:50:56": "vmware",
            "08:00:27": "virtualbox",
            "02:42:AC": "docker",
        }
        self._geo_cache: Dict[str, Dict[str, str]] = {}

    async def discover(self, targets: Iterable[str], rate_limiter: RateLimiter) -> List[Device]:
        """Run all discovery methods and deduplicate by MAC.

        Args:
            targets (Iterable[str]): Iterable of targets or CIDR ranges.
            rate_limiter (RateLimiter): Rate limiter for outbound probes.

        Returns:
            List[Device]: List of discovered devices.

        Raises:
            Exception: Unexpected discovery errors.

        Example:
            >>> devices = await mapper.discover(["192.168.1.0/24"], limiter)

        Note:
            Deduplication uses MAC when available.
        """
        await self._ensure_oui_db()
        target_list = list(targets)
        devices: List[Device] = []
        for target in target_list:
            if "/" in target:
                devices.extend(await self.arp_scan(target))
                devices.extend(await self.icmp_ping_sweep(target))
                devices.extend(await self.tcp_ping_sweep(target))
                devices.extend(await self.udp_discovery(target))
            else:
                devices.append(Device(ip=target, last_seen=datetime.utcnow()))
        devices.extend(await self.mdns_discovery())
        devices.extend(await self.ssdp_discovery())
        devices.extend(await self.netbios_discovery())
        devices = self._deduplicate(devices)
        await self._resolve_macs(devices)
        return self._deduplicate(devices)

    async def arp_scan(self, network_range: str) -> List[Device]:
        """Perform ARP scan of a subnet.

        Args:
            network_range (str): CIDR range to scan.

        Returns:
            List[Device]: List of discovered devices.

        Raises:
            PermissionError: If raw socket permissions are missing.

        Example:
            >>> devices = await mapper.arp_scan("192.168.1.0/24")

        Note:
            Requires scapy and elevated privileges.
        """
        if ARP is None:
            self._logger.warning("scapy not available: skipping ARP scan")
            return []

        def run_scan() -> List[Device]:
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
            devices: List[Device] = []
            try:
                pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network_range)
                answered, _ = srp(pkt, timeout=self._timeout, verbose=False)
                for _, recv in answered:
                    mac = recv.hwsrc
                    ip = recv.psrc
                    devices.append(Device(ip=ip, mac=mac, last_seen=datetime.utcnow()))
            except PermissionError:
                self._logger.warning("ARP scan requires elevated privileges")
            except Exception:
                self._logger.exception("ARP scan failed")
            return devices

        return await asyncio.to_thread(run_scan)

    async def icmp_ping_sweep(self, network_range: str, count: int = 2, timeout: float = 1.0) -> List[Device]:
        """Perform ICMP ping sweep across a subnet.

        Args:
            network_range (str): CIDR range to scan.
            count (int): Probe count per host.
            timeout (float): Timeout per ICMP probe.

        Returns:
            List[Device]: List of responsive devices.

        Raises:
            PermissionError: If raw socket permissions are missing.

        Example:
            >>> devices = await mapper.icmp_ping_sweep("192.168.1.0/24")

        Note:
            Uses scapy when available.
        """
        if ICMP is None:
            self._logger.warning("scapy not available: skipping ICMP sweep")
            return []
        hosts = list(self._expand_network(network_range))
        devices: List[Device] = []
        sem = asyncio.Semaphore(200)

        async def probe(ip: str) -> None:
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
            async with sem:

                def send_probe() -> Optional[int]:
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
                    ttl = None
                    try:
                        for _ in range(count):
                            pkt = IP(dst=ip) / ICMP()
                            reply = sr1(pkt, timeout=timeout, verbose=False)
                            if reply is not None:
                                ttl = int(reply.ttl)
                                break
                    except PermissionError:
                        self._logger.warning("ICMP sweep requires elevated privileges")
                    except Exception:
                        return None
                    return ttl

                ttl = await asyncio.to_thread(send_probe)
                if ttl is not None:
                    devices.append(Device(ip=ip, last_seen=datetime.utcnow(), os_guess=self._guess_os_from_ttl(ttl)))

        await asyncio.gather(*(probe(ip) for ip in hosts))
        return devices

    async def tcp_ping_sweep(self, network_range: str, ports: Optional[Sequence[int]] = None) -> List[Device]:
        """Perform TCP SYN ping sweep across a subnet.

        Args:
            network_range (str): CIDR range to scan.
            ports (Optional[Sequence[int]]): Ports to probe for SYN response.

        Returns:
            List[Device]: List of responsive devices.

        Raises:
            PermissionError: If raw socket permissions are missing.

        Example:
            >>> devices = await mapper.tcp_ping_sweep("192.168.1.0/24")

        Note:
            Uses scapy SYN probes when available.
        """
        ports = list(ports or [80, 443, 22, 445])
        hosts = list(self._expand_network(network_range))
        devices: List[Device] = []
        sem = asyncio.Semaphore(300)

        async def probe(ip: str) -> None:
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
            async with sem:
                for port in ports:
                    if TCP is None:
                        break

                    def send_syn() -> bool:
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
                        try:
                            reply = sr1(IP(dst=ip) / TCP(dport=port, flags="S"), timeout=self._timeout, verbose=False)
                            if reply and reply.haslayer(TCP):
                                return True
                        except PermissionError:
                            self._logger.warning("TCP SYN sweep requires elevated privileges")
                        except Exception:
                            return False
                        return False

                    is_up = await asyncio.to_thread(send_syn)
                    if is_up:
                        devices.append(Device(ip=ip, last_seen=datetime.utcnow()))
                        return

        await asyncio.gather(*(probe(ip) for ip in hosts))
        return devices

    async def udp_discovery(self, network_range: str) -> List[Device]:
        """Perform UDP-based discovery across a subnet.

        Args:
            network_range (str): CIDR range to scan.

        Returns:
            List[Device]: List of responsive devices.

        Raises:
            PermissionError: If raw socket permissions are missing.

        Example:
            >>> devices = await mapper.udp_discovery("192.168.1.0/24")

        Note:
            Uses ICMP unreachable inference where possible.
        """
        if UDP is None or ICMP is None:
            self._logger.warning("scapy not available: skipping UDP discovery")
            return []
        hosts = list(self._expand_network(network_range))
        devices: List[Device] = []
        sem = asyncio.Semaphore(200)

        async def probe(ip: str) -> None:
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
            async with sem:

                def send_probe() -> bool:
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
                    try:
                        pkt = IP(dst=ip) / UDP(dport=33434)
                        reply = sr1(pkt, timeout=self._timeout, verbose=False)
                        if reply and reply.haslayer(ICMP):
                            icmp = reply.getlayer(ICMP)
                            return int(icmp.type) == 3 and int(icmp.code) in {1, 2, 3, 9, 10, 13}
                    except PermissionError:
                        self._logger.warning("UDP discovery requires elevated privileges")
                    except Exception:
                        return False
                    return False

                is_up = await asyncio.to_thread(send_probe)
                if is_up:
                    devices.append(Device(ip=ip, last_seen=datetime.utcnow()))

        await asyncio.gather(*(probe(ip) for ip in hosts))
        return devices

    async def mdns_discovery(self) -> List[Device]:
        """Discover hosts via mDNS multicast.

        Args:
            None

        Returns:
            Any: Description of return value.

        Raises:
            Exception: On unexpected errors.

        Example:
            >>> # Example usage of mdns_discovery
            >>> pass"""
        query = "\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05_local\x00\x00\x0c\x00\x01".encode("latin-1")
        return await self._multicast_query("224.0.0.251", 5353, query)

    async def ssdp_discovery(self) -> List[Device]:
        """Discover hosts via SSDP multicast.

        Args:
            None

        Returns:
            Any: Description of return value.

        Raises:
            Exception: On unexpected errors.

        Example:
            >>> # Example usage of ssdp_discovery
            >>> pass"""
        query = 'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n'.encode(
            "ascii"
        )
        return await self._multicast_query("239.255.255.250", 1900, query)

    async def netbios_discovery(self) -> List[Device]:
        """Discover hosts via NetBIOS broadcast.

        Args:
            None

        Returns:
            Any: Description of return value.

        Raises:
            Exception: On unexpected errors.

        Example:
            >>> # Example usage of netbios_discovery
            >>> pass"""
        query = self._build_netbios_query()
        return await self._multicast_query("255.255.255.255", 137, query, broadcast=True)

    async def passive_fingerprint(self, metadata: Dict[str, str]) -> FingerprintData:
        """Build fingerprint data from passive metadata.

        Args:
            metadata (Any): Description of metadata.

        Returns:
            Any: Description of return value.

        Raises:
            Exception: On unexpected errors.

        Example:
            >>> # Example usage of passive_fingerprint
            >>> pass"""
        ttl = int(metadata.get("ttl", 0)) if metadata.get("ttl") else None
        window = int(metadata.get("window", 0)) if metadata.get("window") else None
        ua = metadata.get("user_agent")
        smb = metadata.get("smb_version")
        smb_negotiate = metadata.get("smb_negotiate")
        dhcp = metadata.get("dhcp_option_55")
        dhcp_list = self._parse_dhcp_option_55(dhcp)
        ua_family = self._parse_user_agent_family(ua)
        smb_dialect = self._parse_smb_dialect(smb_negotiate)
        return FingerprintData(
            ttl=ttl,
            window_size=window,
            dhcp_options=dhcp_list,
            user_agent=ua,
            smb_version=smb,
            ua_family=ua_family,
            smb_dialect=smb_dialect,
        )

    async def active_fingerprint(self, ip: str) -> FingerprintData:
        """Actively probe a host for fingerprint signals.

        Args:
            ip (Any): Description of ip.

        Returns:
            Any: Description of return value.

        Raises:
            Exception: On unexpected errors.

        Example:
            >>> # Example usage of active_fingerprint
            >>> pass"""
        if TCP is None or ICMP is None:
            return FingerprintData()

        def run_probe() -> FingerprintData:
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
            try:
                syn_pkt = IP(dst=ip) / TCP(
                    dport=80, flags="S", options=[("MSS", 1460), ("SAckOK", b""), ("TS", (0, 0))]
                )
                reply = sr1(syn_pkt, timeout=self._timeout, verbose=False)
                ttl = int(reply.ttl) if reply else None
                window = int(getattr(reply, "window", 0)) if reply else None
                tcp_opts = [opt[0] for opt in getattr(reply, "options", []) if isinstance(opt, tuple)] if reply else []
                tcp_order = [opt[0] for opt in getattr(reply, "options", []) if isinstance(opt, tuple)] if reply else []
                df_bit = None
                if reply and reply.haslayer(IP):
                    try:
                        df_bit = "DF" in reply.getlayer(IP).flags
                    except Exception:
                        df_bit = None
                tcp_flags = [str(reply.sprintf("%TCP.flags%"))] if reply and reply.haslayer(TCP) else []
                icmp_types: List[int] = []
                icmp_codes: List[int] = []
                for icmp_type in [8, 13, 17, 15]:
                    icmp_reply = sr1(IP(dst=ip) / ICMP(type=icmp_type), timeout=self._timeout, verbose=False)
                    if icmp_reply and icmp_reply.haslayer(ICMP):
                        icmp_layer = icmp_reply.getlayer(ICMP)
                        icmp_types.append(int(icmp_layer.type))
                        icmp_codes.append(int(icmp_layer.code))
                return FingerprintData(
                    ttl=ttl,
                    window_size=window,
                    df_bit=df_bit,
                    tcp_options=tcp_opts,
                    tcp_option_order=tcp_order,
                    icmp_types=icmp_types,
                    icmp_codes=icmp_codes,
                    tcp_flags=tcp_flags,
                )
            except Exception:
                return FingerprintData()

        return await asyncio.to_thread(run_probe)

    def classify_device(self, device: Device, fingerprints: Optional[FingerprintData] = None) -> Tuple[str, OSGuess]:
        """Classify device type and OS guess.

        Args:
            device (Any): Description of device.
            fingerprints (Any): Description of fingerprints.

        Returns:
            Any: Description of return value.

        Raises:
            Exception: On unexpected errors.

        Example:
            >>> # Example usage of classify_device
            >>> pass"""
        vendor = self._classifier.classify_by_mac_oui(device.mac or "")
        device_type = self._classifier.classify_by_services(device.services)
        if device_type == "unknown":
            device_type = self._classifier.classify_by_open_ports(device.open_ports)
        os_guess = self._guess_os_from_fingerprint(fingerprints or FingerprintData())
        return (f"{device_type}:{vendor}", os_guess)

    async def build_topology(self, devices: List[Device]) -> Dict[str, List[str]]:
        """Build a basic topology graph using ARP and traceroute.

        Args:
            devices (Any): Description of devices.

        Returns:
            Any: Description of return value.

        Raises:
            Exception: On unexpected errors.

        Example:
            >>> # Example usage of build_topology
            >>> pass"""
        topology: Dict[str, List[str]] = {}
        gateway = self._guess_gateway(devices)
        if gateway:
            topology[gateway] = [d.ip for d in devices if d.ip != gateway]
        arp_table = self._read_arp_table()
        for device in devices:
            if device.mac and device.mac in arp_table:
                topology.setdefault(arp_table[device.mac], []).append(device.ip)
        for device in devices:
            hops = await self.traceroute(device.ip)
            if hops:
                prev = gateway or hops[0][0]
                for hop_ip, _ in hops:
                    topology.setdefault(prev, []).append(hop_ip)
                    prev = hop_ip
        routing_edges = await self._snmp_routing_edges(devices)
        for parent, child in routing_edges:
            topology.setdefault(parent, []).append(child)
        return self._dedup_topology(topology)

    async def generate_network_map(self, devices: List[Device], output_path: str) -> None:
        """Generate an interactive HTML network map.

        Args:
            devices (Any): Description of devices.
            output_path (Any): Description of output_path.

        Returns:
            Any: Description of return value.

        Raises:
            Exception: On unexpected errors.

        Example:
            >>> # Example usage of generate_network_map
            >>> pass"""
        try:
            from pyvis.network import Network
        except Exception:
            self._logger.warning("pyvis not available")
            return
        net = Network(height="600px", width="100%", bgcolor="#111", font_color="#eee")
        for device in devices:
            device_type = self._classifier.classify_by_services(device.services)
            color = self._color_for_type(device_type)
            label = device.hostname or device.ip
            net.add_node(device.ip, label=label, color=color)
        if devices:
            root = devices[0].ip
            for device in devices:
                if device.ip != root:
                    net.add_edge(root, device.ip)
        net.write_html(output_path)

    async def export_gexf(self, devices: List[Device], output_path: str) -> None:
        """Export topology to GEXF format.

        Args:
            devices (Any): Description of devices.
            output_path (Any): Description of output_path.

        Returns:
            Any: Description of return value.

        Raises:
            Exception: On unexpected errors.

        Example:
            >>> # Example usage of export_gexf
            >>> pass"""
        try:
            import networkx as nx
        except Exception:
            self._logger.warning("networkx not available")
            return
        graph = nx.Graph()
        for device in devices:
            graph.add_node(device.ip, mac=device.mac or "", os=device.os_guess or "")
        if devices:
            root = devices[0].ip
            for device in devices[1:]:
                graph.add_edge(root, device.ip)
        nx.write_gexf(graph, output_path)

    async def export_json(self, devices: List[Device], output_path: str) -> None:
        """Export device inventory to JSON.

        Args:
            devices (Any): Description of devices.
            output_path (Any): Description of output_path.

        Returns:
            Any: Description of return value.

        Raises:
            Exception: On unexpected errors.

        Example:
            >>> # Example usage of export_json
            >>> pass"""
        payload = []
        for device in devices:
            device_type = self._classifier.classify_by_services(device.services)
            vendor = self._classifier.classify_by_mac_oui(device.mac or "")
            honeypot = self.detect_honeypot(device)
            virtualization = self.detect_virtualization(device.mac)
            payload.append(
                {
                    "ip": device.ip,
                    "mac": device.mac,
                    "hostname": device.hostname,
                    "os_guess": device.os_guess,
                    "vendor": vendor,
                    "device_type": device_type,
                    "honeypot": honeypot,
                    "virtualization": virtualization,
                    "open_ports": device.open_ports,
                    "services": [
                        {"port": svc.port, "protocol": svc.protocol, "name": svc.service_name, "version": svc.version}
                        for svc in device.services
                    ],
                }
            )
        async with aiofiles.open(output_path, "w", encoding="utf-8") as handle:
            await handle.write(json.dumps(payload, indent=2))

    def detect_honeypot(self, device: Device) -> Optional[str]:
        """Detect potential honeypots using banner heuristics.

        Args:
            device (Any): Description of device.

        Returns:
            Any: Description of return value.

        Raises:
            Exception: On unexpected errors.

        Example:
            >>> # Example usage of detect_honeypot
            >>> pass"""
        for svc in device.services:
            banner = (svc.banner or "").lower()
            for name, signatures in self._honeypot_signatures.items():
                if any((sig in banner for sig in signatures)):
                    return name
        ports = set(device.open_ports)
        if {22, 23, 2323} & ports:
            return "ssh_telnet_honeypot_suspect"
        return None

    def detect_virtualization(self, mac: Optional[str]) -> Optional[str]:
        """Detect virtualization vendor from MAC prefix.

        Args:
            mac (Any): Description of mac.

        Returns:
            Any: Description of return value.

        Raises:
            Exception: On unexpected errors.

        Example:
            >>> # Example usage of detect_virtualization
            >>> pass"""
        if not mac:
            return None
        prefix = mac.replace("-", ":").upper()[0:8]
        return self._virtual_mac_prefixes.get(prefix)

    def wake_on_lan(self, mac: str, broadcast_ip: str = "255.255.255.255", port: int = 9) -> None:
        """Send a Wake-on-LAN magic packet.

        Args:
            mac (Any): Description of mac.
            broadcast_ip (Any): Description of broadcast_ip.
            port (Any): Description of port.

        Returns:
            Any: Description of return value.

        Raises:
            Exception: On unexpected errors.

        Example:
            >>> # Example usage of wake_on_lan
            >>> pass"""
        mac_bytes = bytes.fromhex(mac.replace("-", "").replace(":", ""))
        packet = b"\xff" * 6 + mac_bytes * 16
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(packet, (broadcast_ip, port))
        sock.close()

    def detect_vlan_segments(self, devices: List[Device]) -> List[str]:
        """Infer VLAN segments by /24 grouping.

        Args:
            devices (Any): Description of devices.

        Returns:
            Any: Description of return value.

        Raises:
            Exception: On unexpected errors.

        Example:
            >>> # Example usage of detect_vlan_segments
            >>> pass"""
        segments = set()
        for device in devices:
            try:
                network = ipaddress.ip_network(f"{device.ip}/24", strict=False)
                segments.add(str(network.network_address))
            except Exception:
                continue
        return sorted(segments)

    def detect_nat_boundaries(self, devices: List[Device]) -> List[str]:
        """Infer NAT boundaries based on private/public mix.

        Args:
            devices (Any): Description of devices.

        Returns:
            Any: Description of return value.

        Raises:
            Exception: On unexpected errors.

        Example:
            >>> # Example usage of detect_nat_boundaries
            >>> pass"""
        public_ips = []
        private_ips = []
        for device in devices:
            try:
                ip = ipaddress.ip_address(device.ip)
                if ip.is_private:
                    private_ips.append(device.ip)
                else:
                    public_ips.append(device.ip)
            except Exception:
                continue
        boundaries = []
        if public_ips and private_ips:
            boundaries.append("private_to_public")
        if private_ips and (not public_ips):
            boundaries.append("internal_only")
        return boundaries

    async def _ensure_oui_db(self) -> None:
        """Ensure OUI database is present and loaded.

        Args:
            None

        Returns:
            Any: Description of return value.

        Raises:
            Exception: On unexpected errors.

        Example:
            >>> # Example usage of _ensure_oui_db
            >>> pass"""
        if self._oui_map:
            return
        os.makedirs(self._cache_dir, exist_ok=True)
        cache_path = os.path.join(self._cache_dir, "oui.txt")
        if not os.path.exists(cache_path):
            await self._download_oui(cache_path)
        await self._load_oui(cache_path)
        self._classifier = DeviceClassifier(self._oui_map)

    async def _download_oui(self, path: str) -> None:
        """Download OUI database to disk.

        Args:
            path (Any): Description of path.

        Returns:
            Any: Description of return value.

        Raises:
            Exception: On unexpected errors.

        Example:
            >>> # Example usage of _download_oui
            >>> pass"""
        async with aiohttp.ClientSession() as session:
            async with session.get(OUI_DB_URL, timeout=30) as response:
                response.raise_for_status()
                data = await response.text()
        async with aiofiles.open(path, "w", encoding="utf-8") as handle:
            await handle.write(data)

    async def _load_oui(self, path: str) -> None:
        """Load OUI database file into memory.

        Args:
            path (Any): Description of path.

        Returns:
            Any: Description of return value.

        Raises:
            Exception: On unexpected errors.

        Example:
            >>> # Example usage of _load_oui
            >>> pass"""
        async with aiofiles.open(path, "r", encoding="utf-8", errors="ignore") as handle:
            async for line in handle:
                if "(hex)" not in line:
                    continue
                parts = [p.strip() for p in line.split("(hex)")]
                if len(parts) != 2:
                    continue
                prefix = parts[0].replace("-", ":").upper()
                vendor = parts[1]
                self._oui_map[prefix] = vendor

    def _expand_network(self, network_range: str) -> Iterable[str]:
        """Expand a CIDR range into host IPs.

        Args:
            network_range (Any): Description of network_range.

        Returns:
            Any: Description of return value.

        Raises:
            Exception: On unexpected errors.

        Example:
            >>> # Example usage of _expand_network
            >>> pass"""
        network = ipaddress.ip_network(network_range, strict=False)
        return (str(host) for host in network.hosts())

    def _guess_os_from_ttl(self, ttl: int) -> str:
        """Guess OS family using TTL value.

        Args:
            ttl (Any): Description of ttl.

        Returns:
            Any: Description of return value.

        Raises:
            Exception: On unexpected errors.

        Example:
            >>> # Example usage of _guess_os_from_ttl
            >>> pass"""
        if ttl >= 250:
            return "network_device"
        if ttl >= 120:
            return "windows"
        if ttl >= 60:
            return "linux"
        return "unknown"

    def _guess_os_from_fingerprint(self, fp: FingerprintData) -> OSGuess:
        """Guess OS based on active fingerprint signatures.

        Args:
            fp (Any): Description of fp.

        Returns:
            Any: Description of return value.

        Raises:
            Exception: On unexpected errors.

        Example:
            >>> # Example usage of _guess_os_from_fingerprint
            >>> pass"""
        for name, signature in self._p0f_signatures.items():
            ttl_match = signature.get("ttl")
            win_match = signature.get("window")
            if ttl_match and fp.ttl and (int(ttl_match) == fp.ttl):
                if win_match and fp.window_size and (int(win_match) == fp.window_size):
                    return OSGuess(name, 0.9)
                return OSGuess(name, 0.75)
        return self._classifier.guess_os(fp)

    def _guess_gateway(self, devices: List[Device]) -> Optional[str]:
        """Guess a gateway IP based on device list.

        Args:
            devices (Any): Description of devices.

        Returns:
            Any: Description of return value.

        Raises:
            Exception: On unexpected errors.

        Example:
            >>> # Example usage of _guess_gateway
            >>> pass"""
        if not devices:
            return None
        try:
            ip = ipaddress.ip_address(devices[0].ip)
            if ip.version == 4:
                network = ipaddress.ip_network(f"{devices[0].ip}/24", strict=False)
                return str(list(network.hosts())[0])
        except Exception:
            return devices[0].ip
        return devices[0].ip

    def _load_p0f_signatures(self) -> Dict[str, Dict[str, str]]:
        """Return static p0f-style signature map.

        Args:
            None

        Returns:
            Any: Description of return value.

        Raises:
            Exception: On unexpected errors.

        Example:
            >>> # Example usage of _load_p0f_signatures
            >>> pass"""
        return {
            "windows": {"ttl": "128", "window": "64240"},
            "linux": {"ttl": "64", "window": "5840"},
            "freebsd": {"ttl": "64", "window": "65535"},
            "cisco": {"ttl": "255", "window": "4128"},
        }

    async def traceroute(self, ip: str, max_hops: int = 20) -> List[Tuple[str, float]]:
        """Run a basic traceroute to a target.

        Args:
            ip (Any): Description of ip.
            max_hops (Any): Description of max_hops.

        Returns:
            Any: Description of return value.

        Raises:
            Exception: On unexpected errors.

        Example:
            >>> # Example usage of traceroute
            >>> pass"""
        if IP is None or ICMP is None:
            return []

        def run_trace() -> List[Tuple[str, float]]:
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
            hops: List[Tuple[str, float]] = []
            for ttl in range(1, max_hops + 1):
                try:
                    start = time.time()
                    reply = sr1(IP(dst=ip, ttl=ttl) / ICMP(), timeout=self._timeout, verbose=False)
                    if reply is None:
                        continue
                    rtt = (time.time() - start) * 1000
                    hops.append((reply.src, rtt))
                    if reply.src == ip:
                        break
                except Exception:
                    continue
            return hops

        hops = await asyncio.to_thread(run_trace)
        for hop_ip, _ in hops:
            if hop_ip not in self._geo_cache:
                geo = await self._geolocate_ip(hop_ip)
                if geo:
                    self._geo_cache[hop_ip] = geo
        return hops

    async def _geolocate_ip(self, ip: str) -> Optional[Dict[str, str]]:
        """Lookup geolocation data for an IP using ip-api.com.

        Args:
            ip: IP address to lookup.

        Returns:
            Geolocation data dictionary if available.

        Raises:
            Exception: Best-effort; exceptions are suppressed internally.

        Example:
            >>> geo = await mapper._geolocate_ip("8.8.8.8")

        Note:
            External HTTP requests may be rate limited by the service.
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"http://ip-api.com/json/{ip}", timeout=5) as response:
                    if response.status != 200:
                        return None
                    payload = await response.json()
                    if payload.get("status") != "success":
                        return None
                    return {
                        "country": payload.get("country", ""),
                        "region": payload.get("regionName", ""),
                        "city": payload.get("city", ""),
                        "isp": payload.get("isp", ""),
                    }
        except Exception:
            return None

    async def _multicast_query(self, host: str, port: int, payload: bytes, broadcast: bool = False) -> List[Device]:
        """Send a UDP multicast/broadcast query and collect responses.

        Args:
            host (Any): Description of host.
            port (Any): Description of port.
            payload (Any): Description of payload.
            broadcast (Any): Description of broadcast.

        Returns:
            Any: Description of return value.

        Raises:
            Exception: On unexpected errors.

        Example:
            >>> # Example usage of _multicast_query
            >>> pass"""
        devices: List[Device] = []
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setblocking(False)
            if broadcast:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            await loop.sock_sendto(sock, payload, (host, port))
            start = time.monotonic()
            while time.monotonic() - start < self._timeout:
                try:
                    data, addr = await loop.sock_recvfrom(sock, 2048)
                    if addr:
                        hostname = self._parse_hostname(data)
                        devices.append(Device(ip=addr[0], hostname=hostname, last_seen=datetime.utcnow()))
                except Exception:
                    break
        finally:
            sock.close()
        return self._deduplicate(devices)

    async def _resolve_macs(self, devices: List[Device]) -> None:
        """Resolve missing MAC addresses via ARP.

        Args:
            devices (Any): Description of devices.

        Returns:
            Any: Description of return value.

        Raises:
            Exception: On unexpected errors.

        Example:
            >>> # Example usage of _resolve_macs
            >>> pass"""
        if ARP is None or Ether is None:
            return

        def resolve(ip: str) -> Optional[str]:
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
            try:
                pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
                answered, _ = srp(pkt, timeout=self._timeout, verbose=False)
                for _, recv in answered:
                    return recv.hwsrc
            except Exception:
                return None
            return None

        for device in devices:
            if device.mac:
                continue
            mac = await asyncio.to_thread(resolve, device.ip)
            if mac:
                device.mac = mac

    def _read_arp_table(self) -> Dict[str, str]:
        """Return MAC -> IP map from the OS ARP cache.

        Args:
            None

        Returns:
            Any: Description of return value.

        Raises:
            Exception: On unexpected errors.

        Example:
            >>> # Example usage of _read_arp_table
            >>> pass"""
        table: Dict[str, str] = {}
        try:
            output = subprocess.check_output(["arp", "-a"], text=True, stderr=subprocess.DEVNULL)
            if isinstance(output, bytes):
                output = output.decode(errors="ignore")
            for line in output.splitlines():
                # Try to extract IP and MAC in a few common formats
                ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                mac_match = re.search(r"([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})", line)
                if ip_match and mac_match:
                    ip = ip_match.group(1)
                    mac = mac_match.group(1).replace("-", ":").upper()
                    table[mac] = ip
                    continue
                # Fallback: formats like "? (192.168.1.1) at 00:11:22:33:44:55"
                fallback = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9A-Fa-f:-]{17})", line)
                if fallback:
                    ip = fallback.group(1)
                    mac = fallback.group(2).replace("-", ":").upper()
                    table[mac] = ip
        except Exception:
            return {}
        return table

    async def _snmp_routing_edges(self, devices: List[Device]) -> List[Tuple[str, str]]:
        """Best-effort SNMP routing table analysis if pysnmp is available.

        Args:
            devices (Any): Description of devices.

        Returns:
            Any: Description of return value.

        Raises:
            Exception: On unexpected errors.

        Example:
            >>> # Example usage of _snmp_routing_edges
            >>> pass"""
        try:
            from pysnmp.hlapi import (
                CommunityData,
                ContextData,
                ObjectIdentity,
                ObjectType,
                SnmpEngine,
                UdpTransportTarget,
                nextCmd,
            )
        except Exception:
            return []
        edges: List[Tuple[str, str]] = []
        oids = ObjectType(ObjectIdentity("1.3.6.1.2.1.4.21.1.1"))
        for device in devices:
            try:
                iterator = nextCmd(
                    SnmpEngine(),
                    CommunityData("public", mpModel=0),
                    UdpTransportTarget((device.ip, 161), timeout=1, retries=0),
                    ContextData(),
                    oids,
                    lexicographicMode=False,
                )
                async for _ in self._iterate_snmp(iterator):
                    for var_bind in _:
                        dest = str(var_bind[1])
                        if dest and dest != "0.0.0.0":
                            edges.append((device.ip, dest))
            except Exception:
                continue
        return edges

    async def _iterate_snmp(self, iterator) -> Iterable:
        """Yield items from a synchronous SNMP iterator.

        Args:
            iterator (Any): Description of iterator.

        Returns:
            Any: Description of return value.

        Raises:
            Exception: On unexpected errors.

        Example:
            >>> # Example usage of _iterate_snmp
            >>> pass"""
        for item in iterator:
            yield item

    def _deduplicate(self, devices: List[Device]) -> List[Device]:
        """Deduplicate devices by MAC and IP.

        Args:
            devices (Any): Description of devices.

        Returns:
            Any: Description of return value.

        Raises:
            Exception: On unexpected errors.

        Example:
            >>> # Example usage of _deduplicate
            >>> pass"""
        by_mac: Dict[str, Device] = {}
        by_ip: Dict[str, Device] = {}
        for device in devices:
            if device.mac:
                by_mac[device.mac] = device
            else:
                by_ip[device.ip] = device
        return list({**by_ip, **by_mac}.values())

    def _build_netbios_query(self) -> bytes:
        """Build a NetBIOS name query packet.

        Args:
            None

        Returns:
            Any: Description of return value.

        Raises:
            Exception: On unexpected errors.

        Example:
            >>> # Example usage of _build_netbios_query
            >>> pass"""
        tid = random.randint(0, 65535)
        flags = 16
        questions = 1
        header = struct.pack(">HHHHHH", tid, flags, questions, 0, 0, 0)
        name = "*" + "\x00" * 15
        encoded = b"".join((struct.pack("B", ord(c)) for c in name))
        qname = struct.pack("B", len(encoded)) + encoded + b"\x00"
        qtype = 33
        qclass = 1
        return header + qname + struct.pack(">HH", qtype, qclass)

    def _color_for_type(self, device_type: str) -> str:
        """Return a color for a device type label.

        Args:
            device_type (Any): Description of device_type.

        Returns:
            Any: Description of return value.

        Raises:
            Exception: On unexpected errors.

        Example:
            >>> # Example usage of _color_for_type
            >>> pass"""
        palette = {
            "server": "#4E9A06",
            "workstation": "#3465A4",
            "iot": "#F57900",
            "infrastructure": "#AD7FA8",
            "unknown": "#888A85",
        }
        return palette.get(device_type, "#888A85")

    def _parse_hostname(self, payload: bytes) -> Optional[str]:
        """Parse a hostname from a UDP response payload.

        Args:
            payload (Any): Description of payload.

        Returns:
            Any: Description of return value.

        Raises:
            Exception: On unexpected errors.

        Example:
            >>> # Example usage of _parse_hostname
            >>> pass"""
        try:
            text = payload.decode(errors="ignore")
            match = re.search("(HOST|USN|SERVER|NAME):\\s*([^\\r\\n]+)", text, re.IGNORECASE)
            if match:
                return match.group(2).strip()
        except Exception:
            return None
        return None

    def _parse_dhcp_option_55(self, value: Optional[str]) -> List[int]:
        """Parse DHCP option 55 list from text.

        Args:
            value (Any): Description of value.

        Returns:
            Any: Description of return value.

        Raises:
            Exception: On unexpected errors.

        Example:
            >>> # Example usage of _parse_dhcp_option_55
            >>> pass"""
        if not value:
            return []
        return [int(x) for x in re.findall("\\d+", value)]

    def _parse_user_agent_family(self, user_agent: Optional[str]) -> Optional[str]:
        """Infer OS family from user agent text.

        Args:
            user_agent (Any): Description of user_agent.

        Returns:
            Any: Description of return value.

        Raises:
            Exception: On unexpected errors.

        Example:
            >>> # Example usage of _parse_user_agent_family
            >>> pass"""
        if not user_agent:
            return None
        ua = user_agent.lower()
        if "windows" in ua:
            return "windows"
        if "mac os" in ua or "darwin" in ua:
            return "macos"
        if "android" in ua:
            return "android"
        if "linux" in ua:
            return "linux"
        return "unknown"

    def _parse_smb_dialect(self, smb_negotiate: Optional[str]) -> Optional[str]:
        """Infer SMB dialect from negotiation string.

        Args:
            smb_negotiate (Any): Description of smb_negotiate.

        Returns:
            Any: Description of return value.

        Raises:
            Exception: On unexpected errors.

        Example:
            >>> # Example usage of _parse_smb_dialect
            >>> pass"""
        if not smb_negotiate:
            return None
        text = smb_negotiate.lower()
        if "smb3" in text:
            return "smb3"
        if "smb2" in text:
            return "smb2"
        if "smb1" in text or "nt lm 0.12" in text:
            return "smb1"
        return "unknown"

    def _dedup_topology(self, topo: Dict[str, List[str]]) -> Dict[str, List[str]]:
        """Deduplicate topology adjacency lists.

        Args:
            topo (Any): Description of topo.

        Returns:
            Any: Description of return value.

        Raises:
            Exception: On unexpected errors.

        Example:
            >>> # Example usage of _dedup_topology
            >>> pass"""
        output: Dict[str, List[str]] = {}
        for node, edges in topo.items():
            output[node] = sorted(set(edges))
        return output
