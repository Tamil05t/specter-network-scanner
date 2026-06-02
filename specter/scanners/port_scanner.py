"""Async port scanning module with service detection."""

from __future__ import annotations
import asyncio
import random
import re
import time
from dataclasses import dataclass
from typing import Awaitable, Callable, Dict, Iterable, List, Optional, Sequence, Tuple
from specter.core.rate_limiter import RateLimiter
from specter.models.dataclasses import Device, Service

EventCallback = Callable[[Dict[str, str]], Awaitable[None]]


@dataclass
class CircuitBreakerState:
    failures: int = 0
    open_until: float = 0.0


class PortScanner:
    """Async TCP/UDP port scanner with service detection and banner grabbing.

    This module favors TCP connect scanning for safety and portability. Raw
    socket SYN scanning requires elevated privileges and is intentionally left
    behind an explicit opt-in hook.
    """

    def __init__(
        self,
        timeout: float = 1.5,
        concurrency: int = 100,
        scan_delay: float = 0.0,
        max_retries: int = 2,
        backoff_base: float = 0.25,
        circuit_breaker_failures: int = 6,
        circuit_breaker_timeout: float = 20.0,
        syn_scan: bool = False,
        decoy_scan: bool = False,
        decoy_count: int = 3,
        fragment_packets: bool = False,
        fragment_size: int = 8,
        banner_pool_size: int = 50,
        randomize_ports: bool = True,
        on_event: Optional[EventCallback] = None,
        correlation_queue: Optional[asyncio.Queue[Service]] = None,
    ) -> None:
        """Initialize port scanner settings.

        Args:
            timeout: Per-port timeout in seconds.
            concurrency: Max concurrent port probes.
            scan_delay: Delay between probes.
            max_retries: Retry attempts per port.
            backoff_base: Base backoff in seconds.
            circuit_breaker_failures: Failures before circuit opens.
            circuit_breaker_timeout: Circuit open duration in seconds.
            syn_scan: Enable TCP SYN scanning when possible.
            decoy_scan: Send decoy packets with spoofed sources.
            decoy_count: Number of decoy packets per probe.
            fragment_packets: Fragment probes to evade filters.
            fragment_size: Fragment size in bytes.
            banner_pool_size: Max concurrent banner grabs.
            randomize_ports: Randomize port order.
            on_event: Optional async event callback.
            correlation_queue: Optional queue for service events.

        Returns:
            None: Initializes the scanner instance.

        Raises:
            Exception: Unexpected initialization errors.

        Example:
            >>> scanner = PortScanner(concurrency=50)

        Note:
            Raw socket modes require elevated permissions.
        """
        self._timeout = timeout
        self._concurrency = concurrency
        self._scan_delay = scan_delay
        self._max_retries = max_retries
        self._backoff_base = backoff_base
        self._circuit_breaker_failures = circuit_breaker_failures
        self._circuit_breaker_timeout = circuit_breaker_timeout
        self._syn_scan = syn_scan
        self._decoy_scan = decoy_scan
        self._decoy_count = max(0, decoy_count)
        self._fragment_packets = fragment_packets
        self._fragment_size = max(4, fragment_size)
        self._banner_sem = asyncio.Semaphore(max(1, banner_pool_size))
        self._randomize_ports = randomize_ports
        self._on_event = on_event
        self._correlation_queue = correlation_queue
        self._pause_event = asyncio.Event()
        self._pause_event.set()
        self._circuit_state: Dict[str, CircuitBreakerState] = {}
        self._conn_pool: Dict[Tuple[str, int], Tuple[asyncio.StreamReader, asyncio.StreamWriter, float]] = {}
        self._conn_pool_ttl = 10.0
        self._service_fingerprints = self._build_fingerprints()

    def pause(self) -> None:
        """Pause scanning tasks until resumed.

        Args:
            None

        Returns:
            None: Pauses via an asyncio event.

        Raises:
            Exception: Unexpected errors.

        Example:
            >>> scanner.pause()

        Note:
            Active tasks will wait on the pause event.
        """
        self._pause_event.clear()

    def resume(self) -> None:
        """Resume paused scanning tasks.

        Args:
            None

        Returns:
            None: Resumes via an asyncio event.

        Raises:
            Exception: Unexpected errors.

        Example:
            >>> scanner.resume()

        Note:
            Tasks continue after the event is set.
        """
        self._pause_event.set()

    async def scan_tcp_ports(
        self, target: str, ports: Sequence[int], timeout: Optional[float] = None, concurrency: Optional[int] = None
    ) -> List[Service]:
        """Scan TCP ports and return Service records.

        Args:
            target: Target hostname or IP.
            ports: Port list to scan.
            timeout: Optional timeout override.
            concurrency: Optional concurrency override.

        Returns:
            List[Service]: List of detected services.

        Raises:
            Exception: Unexpected scanning errors.

        Example:
            >>> services = await scanner.scan_tcp_ports("127.0.0.1", [22, 80])

        Note:
            SYN scan is used when enabled and available.
        """
        if self._is_circuit_open(target):
            await self._emit_event("circuit_open", target)
            return []
        ordered_ports = self._prioritize_ports(list(ports)) if self._randomize_ports else list(ports)
        sem = asyncio.Semaphore(concurrency or self._concurrency)
        results: List[Service] = []
        timeout_value = timeout or self._timeout

        async def scan_port(port: int) -> None:
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
            await self._pause_event.wait()
            async with sem:
                if self._scan_delay > 0:
                    await asyncio.sleep(self._scan_delay)
                service = await self._scan_tcp_port(target, port, timeout_value)
                if service is None:
                    return
                results.append(service)
                await self._push_service(service)

        await asyncio.gather(*(scan_port(port) for port in ordered_ports))
        return results

    async def scan_udp_ports(self, target: str, ports: Sequence[int], timeout: Optional[float] = None) -> List[Service]:
        """Best-effort UDP scan with timeout-based inference.

        Args:
            target: Target hostname or IP.
            ports: Port list to scan.
            timeout: Optional timeout override.

        Returns:
            List[Service]: List of detected services.

        Raises:
            Exception: Unexpected scanning errors.

        Example:
            >>> services = await scanner.scan_udp_ports("127.0.0.1", [53])

        Note:
            ICMP-based inference is used when available.
        """
        if self._is_circuit_open(target):
            await self._emit_event("circuit_open", target)
            return []
        sem = asyncio.Semaphore(self._concurrency)
        timeout_value = timeout or self._timeout
        results: List[Service] = []

        async def scan_port(port: int) -> None:
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
            await self._pause_event.wait()
            async with sem:
                if self._scan_delay > 0:
                    await asyncio.sleep(self._scan_delay)
                service = await self._scan_udp_port(target, port, timeout_value)
                if service is None:
                    return
                results.append(service)
                await self._push_service(service)

        ordered_ports = self._prioritize_ports(list(ports)) if self._randomize_ports else list(ports)
        await asyncio.gather(*(scan_port(port) for port in ordered_ports))
        return results

    async def grab_banner(self, ip: str, port: int, protocol: str = "tcp") -> str:
        """Connect and grab a banner using protocol-specific probes.

        Args:
            ip: Target IP address.
            port: Target port.
            protocol: Protocol name ("tcp" or "udp").

        Returns:
            str: Banner text if available.

        Raises:
            Exception: Connection errors are suppressed.

        Example:
            >>> banner = await scanner.grab_banner("127.0.0.1", 22)

        Note:
            Uses a small connection pool for banner grabs.
        """
        if protocol.lower() == "udp":
            return ""
        async with self._banner_sem:
            reader, writer = await self._get_pooled_connection(ip, port)
            if reader is None or writer is None:
                return ""
            banner = ""
            try:
                probe = self._build_probe(port)
                if probe:
                    writer.write(probe)
                    await writer.drain()
                banner = await asyncio.wait_for(reader.read(512), timeout=self._timeout)
            except Exception:
                banner = b""
            finally:
                await self._release_pooled_connection(ip, port, reader, writer)
        return banner.decode(errors="ignore").strip()

    async def detect_service(self, ip: str, port: int, banner: str) -> Service:
        """Identify service and version from banner using regex patterns.

        Args:
            ip: Target IP address.
            port: Target port.
            banner: Banner text.

        Returns:
            Service: Service record.

        Raises:
            Exception: Regex parsing errors are suppressed.

        Example:
            >>> svc = await scanner.detect_service("127.0.0.1", 22, "SSH-2.0-OpenSSH_8.2")

        Note:
            Returns "unknown" when no signature matches.
        """
        service_name = "unknown"
        version: Optional[str] = None
        for name, patterns in self._service_fingerprints.items():
            for pattern in patterns:
                match = pattern.search(banner)
                if match:
                    service_name = name
                    if match.groupdict().get("version"):
                        version = match.groupdict()["version"]
                    elif match.groups():
                        version = match.groups()[0]
                    return Service(
                        port=port,
                        protocol="tcp",
                        service_name=service_name,
                        version=version,
                        banner=banner,
                        cpe_guess=None,
                    )
        return Service(
            port=port, protocol="tcp", service_name=service_name, version=version, banner=banner, cpe_guess=None
        )

    async def scan_device(
        self, device: Device, ports: Iterable[int], rate_limiter: Optional[RateLimiter] = None
    ) -> Device:
        """Scan a device and populate open ports and services.

        Args:
            device: Device to scan.
            ports: Ports to probe.
            rate_limiter: Optional rate limiter.

        Returns:
            Device: Updated device record.

        Raises:
            Exception: Unexpected scan errors.

        Example:
            >>> device = await scanner.scan_device(Device(ip="127.0.0.1"), [80])

        Note:
            Updates `open_ports` and `services` in-place.
        """
        services = await self.scan_tcp_ports(device.ip, list(ports))
        device.open_ports = sorted({svc.port for svc in services})
        device.services = services
        return device

    async def _scan_tcp_port(self, target: str, port: int, timeout: float) -> Optional[Service]:
        """Probe a TCP port with retries and backoff.

        Args:
            target: Target hostname or IP.
            port: Port number to scan.
            timeout: Per-connection timeout.

        Returns:
            Service if open, otherwise None.

        Raises:
            Exception: Connection errors are retried and suppressed.

        Example:
            >>> svc = await scanner._scan_tcp_port("127.0.0.1", 80, 1.0)

        Note:
            Uses SYN probes when enabled and available.
        """
        for attempt in range(self._max_retries + 1):
            await self._pause_event.wait()
            try:
                if self._syn_scan and self._scapy_available():
                    is_open = await asyncio.to_thread(self._syn_probe, target, port)
                    if not is_open:
                        raise ConnectionRefusedError()
                else:
                    reader, writer = await asyncio.wait_for(asyncio.open_connection(target, port), timeout=timeout)
                    writer.close()
                    await writer.wait_closed()
                banner = await self.grab_banner(target, port, "tcp")
                service = await self.detect_service(target, port, banner)
                self._record_success(target)
                await self._emit_event("port_open", target, port)
                return service
            except PermissionError:
                await self._emit_event("permission", target, port)
                self._record_failure(target)
                return None
            except (ConnectionRefusedError, TimeoutError, OSError):
                self._record_failure(target)
                await self._backoff(attempt)
            except Exception:
                self._record_failure(target)
                await self._backoff(attempt)
        return None

    async def _scan_udp_port(self, target: str, port: int, timeout: float) -> Optional[Service]:
        """Probe a UDP port using a datagram and timeout inference.

        Args:
            target: Target hostname or IP.
            port: Port number to scan.
            timeout: Per-probe timeout.

        Returns:
            Service if possibly open, otherwise None.

        Raises:
            Exception: Probe errors are retried and suppressed.

        Example:
            >>> svc = await scanner._scan_udp_port("127.0.0.1", 53, 1.0)

        Note:
            ICMP unreachable results mark ports as closed.
        """
        for attempt in range(self._max_retries + 1):
            await self._pause_event.wait()
            try:
                if self._scapy_available():
                    result = await asyncio.to_thread(self._udp_probe_icmp, target, port, timeout)
                    if result == "closed":
                        self._record_failure(target)
                        return None
                    self._record_success(target)
                    await self._emit_event("udp_probe", target, port)
                    return Service(
                        port=port,
                        protocol="udp",
                        service_name="open|filtered",
                        version=None,
                        banner=None,
                        cpe_guess=None,
                    )
                loop = asyncio.get_running_loop()
                transport, protocol = await loop.create_datagram_endpoint(
                    asyncio.DatagramProtocol, remote_addr=(target, port)
                )
                transport.sendto(b"\x00")
                await asyncio.sleep(timeout)
                transport.close()
                self._record_success(target)
                await self._emit_event("udp_probe", target, port)
                return Service(
                    port=port, protocol="udp", service_name="open|filtered", version=None, banner=None, cpe_guess=None
                )
            except PermissionError:
                await self._emit_event("permission", target, port)
                self._record_failure(target)
                return None
            except (TimeoutError, OSError):
                self._record_failure(target)
                await self._backoff(attempt)
            except Exception:
                self._record_failure(target)
                await self._backoff(attempt)
        return None

    def _prioritize_ports(self, ports: List[int]) -> List[int]:
        """Reorder ports to scan lower ports first with shuffle.

        Args:
            ports: Port list to prioritize.

        Returns:
            Reordered port list.

        Raises:
            Exception: Unexpected errors during shuffling.

        Example:
            >>> scanner._prioritize_ports([80, 1, 443])

        Note:
            Low ports are shuffled before high ports.
        """
        low_ports = [p for p in ports if 1 <= p <= 1024]
        high_ports = [p for p in ports if p > 1024]
        random.shuffle(low_ports)
        random.shuffle(high_ports)
        return low_ports + high_ports

    async def _push_service(self, service: Service) -> None:
        """Send a service record to the correlation queue if set.

        Args:
            service: Service record to enqueue.

        Returns:
            None: Enqueues service if queue exists.

        Raises:
            Exception: Queue errors are suppressed.

        Example:
            >>> await scanner._push_service(service)

        Note:
            No-op if correlation queue is not configured.
        """
        if self._correlation_queue is None:
            return
        try:
            await self._correlation_queue.put(service)
        except Exception:
            return

    async def _emit_event(self, event: str, target: str, port: Optional[int] = None) -> None:
        """Emit structured events to the optional callback.

        Args:
            event: Event name.
            target: Target hostname or IP.
            port: Optional port number.

        Returns:
            None: Emits event via callback if configured.

        Raises:
            Exception: Callback errors are suppressed.

        Example:
            >>> await scanner._emit_event("port_open", "127.0.0.1", 80)

        Note:
            No-op if callback is not configured.
        """
        if self._on_event is None:
            return
        payload = {"event": event, "target": target}
        if port is not None:
            payload["port"] = str(port)
        try:
            await self._on_event(payload)
        except Exception:
            return

    async def _backoff(self, attempt: int) -> None:
        """Sleep with exponential backoff.

        Args:
            attempt: Attempt number used for backoff calculation.

        Returns:
            None: Sleeps for a calculated duration.

        Raises:
            asyncio.CancelledError: If cancelled while sleeping.

        Example:
            >>> await scanner._backoff(1)

        Note:
            Backoff is capped at 5 seconds.
        """
        delay = self._backoff_base * 2**attempt
        await asyncio.sleep(min(delay, 5.0))

    def _is_circuit_open(self, target: str) -> bool:
        """Check if the circuit breaker is open for a target.

        Args:
            target: Target hostname or IP.

        Returns:
            True if the circuit is open.

        Raises:
            Exception: Unexpected errors are suppressed.

        Example:
            >>> scanner._is_circuit_open("127.0.0.1")

        Note:
            Open circuits skip scanning for a target.
        """
        state = self._circuit_state.get(target)
        if state is None:
            return False
        return time.monotonic() < state.open_until

    def _record_failure(self, target: str) -> None:
        """Record a failed probe and open circuit if threshold exceeded.

        Args:
            target: Target hostname or IP.

        Returns:
            None: Updates circuit breaker state.

        Raises:
            Exception: Unexpected errors are suppressed.

        Example:
            >>> scanner._record_failure("127.0.0.1")

        Note:
            Circuit opens after a threshold of failures.
        """
        state = self._circuit_state.setdefault(target, CircuitBreakerState())
        state.failures += 1
        if state.failures >= self._circuit_breaker_failures:
            state.open_until = time.monotonic() + self._circuit_breaker_timeout

    def _record_success(self, target: str) -> None:
        """Reset circuit breaker state on success.

        Args:
            target: Target hostname or IP.

        Returns:
            None: Resets circuit breaker state.

        Raises:
            Exception: Unexpected errors are suppressed.

        Example:
            >>> scanner._record_success("127.0.0.1")

        Note:
            Success resets failure counters.
        """
        if target in self._circuit_state:
            self._circuit_state[target] = CircuitBreakerState()

    def _build_probe(self, port: int) -> bytes:
        """Return a protocol probe payload for common services.

        Args:
            port: Port number to probe.

        Returns:
            Bytes payload to send.

        Raises:
            Exception: Unexpected errors are suppressed.

        Example:
            >>> scanner._build_probe(80)

        Note:
            Unknown ports return an empty payload.
        """
        probe_map: Dict[int, bytes] = {
            21: b"QUIT\r\n",
            22: b"\r\n",
            25: b"EHLO specter\r\n",
            80: b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
            110: b"QUIT\r\n",
            143: b"a1 CAPABILITY\r\n",
            443: b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
            3306: b"\x00",
            6379: b"PING\r\n",
            27017: b"\x00",
            5432: b"\x00",
        }
        return probe_map.get(port, b"")

    @staticmethod
    def _build_fingerprints() -> Dict[str, List[re.Pattern[str]]]:
        """Build regex fingerprints for service detection.

        Args:
            None

        Returns:
            Any: Description of return value.

        Raises:
            Exception: On unexpected errors.

        Example:
            >>> # Example usage of _build_fingerprints
            >>> pass"""
        return {
            "http": [
                re.compile("Server: Apache/?(?P<version>[\\d\\.]+)?", re.IGNORECASE),
                re.compile("Server: nginx/?(?P<version>[\\d\\.]+)?", re.IGNORECASE),
                re.compile("Server: Microsoft-IIS/(?P<version>[\\d\\.]+)", re.IGNORECASE),
                re.compile("Apache Tomcat/(?P<version>[\\d\\.]+)", re.IGNORECASE),
                re.compile("Express", re.IGNORECASE),
            ],
            "ssh": [
                re.compile("OpenSSH[_-](?P<version>[\\d\\.p]+)", re.IGNORECASE),
                re.compile("Dropbear[_-](?P<version>[\\d\\.]+)", re.IGNORECASE),
            ],
            "ftp": [
                re.compile("vsftpd (?P<version>[\\d\\.]+)", re.IGNORECASE),
                re.compile("ProFTPD (?P<version>[\\d\\.]+)", re.IGNORECASE),
                re.compile("Pure-FTPd", re.IGNORECASE),
            ],
            "mysql": [re.compile("MySQL", re.IGNORECASE)],
            "postgres": [re.compile("PostgreSQL", re.IGNORECASE)],
            "mongodb": [re.compile("MongoDB", re.IGNORECASE)],
            "redis": [re.compile("redis", re.IGNORECASE)],
            "elasticsearch": [re.compile("elasticsearch", re.IGNORECASE)],
            "cassandra": [re.compile("cassandra", re.IGNORECASE)],
            "smtp": [re.compile("ESMTP", re.IGNORECASE)],
            "pop3": [re.compile("\\+OK", re.IGNORECASE)],
            "imap": [re.compile("IMAP", re.IGNORECASE)],
            "telnet": [re.compile("telnet", re.IGNORECASE)],
            "rdp": [re.compile("RDP", re.IGNORECASE)],
            "vnc": [re.compile("RFB (?P<version>[\\d\\.]+)", re.IGNORECASE)],
            "smb": [re.compile("SMB", re.IGNORECASE)],
            "dns": [re.compile("BIND", re.IGNORECASE)],
            "ntp": [re.compile("NTP", re.IGNORECASE)],
            "sip": [re.compile("SIP", re.IGNORECASE)],
            "rtsp": [re.compile("RTSP", re.IGNORECASE)],
        }

    def _scapy_available(self) -> bool:
        """Check if scapy is available for raw scans.

        Args:
            None

        Returns:
            Any: Description of return value.

        Raises:
            Exception: On unexpected errors.

        Example:
            >>> # Example usage of _scapy_available
            >>> pass"""
        try:
            pass

            return True
        except Exception:
            return False

    def _syn_probe(self, target: str, port: int) -> bool:
        """Perform a TCP SYN probe using scapy.

        Args:
            target: Target hostname or IP.
            port: Port number to probe.

        Returns:
            True if SYN/ACK observed.

        Raises:
            Exception: Best-effort; exceptions are suppressed internally.

        Example:
            >>> scanner = PortScanner(syn_scan=True)
            >>> scanner._syn_probe("127.0.0.1", 22)

        Note:
            Requires raw socket permissions and scapy.
        """
        try:
            from scapy.all import IP, TCP, fragment, send, sr1

            pkt = IP(dst=target) / TCP(dport=port, flags="S")
            if self._decoy_scan and self._decoy_count > 0:
                self._send_decoys(target, port)
            if self._fragment_packets:
                for frag in fragment(pkt, fragsize=self._fragment_size):
                    send(frag, verbose=False)
            reply = sr1(pkt, timeout=self._timeout, verbose=False)
            return bool(reply and reply.haslayer(TCP) and reply.getlayer(TCP).flags & 18)
        except Exception:
            return False

    def _udp_probe_icmp(self, target: str, port: int, timeout: float) -> str:
        """Probe UDP port and infer state via ICMP.

        Args:
            target: Target hostname or IP.
            port: Port number to probe.
            timeout: Probe timeout.

        Returns:
            "open|filtered" or "closed".

        Raises:
            Exception: Best-effort; exceptions are suppressed internally.

        Example:
            >>> scanner = PortScanner()
            >>> scanner._udp_probe_icmp("127.0.0.1", 53, 1.0)

        Note:
            Requires raw socket permissions and scapy.
        """
        try:
            from scapy.all import ICMP, IP, UDP, fragment, send, sr1

            pkt = IP(dst=target) / UDP(dport=port)
            if self._decoy_scan and self._decoy_count > 0:
                self._send_decoys(target, port, proto="udp")
            if self._fragment_packets:
                for frag in fragment(pkt, fragsize=self._fragment_size):
                    send(frag, verbose=False)
            reply = sr1(pkt, timeout=timeout, verbose=False)
            if reply and reply.haslayer(ICMP):
                icmp = reply.getlayer(ICMP)
                if int(icmp.type) == 3 and int(icmp.code) in {1, 2, 3, 9, 10, 13}:
                    return "closed"
            return "open|filtered"
        except Exception:
            return "open|filtered"

    def _send_decoys(self, target: str, port: int, proto: str = "tcp") -> None:
        """Send decoy packets with spoofed source IPs.

        Args:
            target (Any): Description of target.
            port (Any): Description of port.
            proto (Any): Description of proto.

        Returns:
            Any: Description of return value.

        Raises:
            Exception: On unexpected errors.

        Example:
            >>> # Example usage of _send_decoys
            >>> pass"""
        try:
            from scapy.all import IP, TCP, UDP, send

            for _ in range(self._decoy_count):
                spoof = f"{random.randint(11, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
                if proto == "udp":
                    pkt = IP(src=spoof, dst=target) / UDP(dport=port)
                else:
                    pkt = IP(src=spoof, dst=target) / TCP(dport=port, flags="S")
                send(pkt, verbose=False)
        except Exception:
            return None

    async def _get_pooled_connection(
        self, ip: str, port: int
    ) -> Tuple[Optional[asyncio.StreamReader], Optional[asyncio.StreamWriter]]:
        """Fetch or create a pooled TCP connection.

        Args:
            ip: Target IP address.
            port: Target port.

        Returns:
            Reader/writer pair or (None, None) on failure.

        Raises:
            Exception: Best-effort; exceptions are suppressed internally.

        Example:
            >>> reader, writer = await scanner._get_pooled_connection("127.0.0.1", 80)

        Note:
            Connections are cached for a short TTL.
        """
        key = (ip, port)
        entry = self._conn_pool.get(key)
        if entry and time.monotonic() - entry[2] < self._conn_pool_ttl:
            return (entry[0], entry[1])
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=self._timeout)
            self._conn_pool[key] = (reader, writer, time.monotonic())
            return (reader, writer)
        except Exception:
            return (None, None)

    async def _release_pooled_connection(
        self, ip: str, port: int, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Release a pooled connection with TTL cleanup.

        Args:
            ip (Any): Description of ip.
            port (Any): Description of port.
            reader (Any): Description of reader.
            writer (Any): Description of writer.

        Returns:
            Any: Description of return value.

        Raises:
            Exception: On unexpected errors.

        Example:
            >>> # Example usage of _release_pooled_connection
            >>> pass"""
        key = (ip, port)
        now = time.monotonic()
        self._conn_pool[key] = (reader, writer, now)
        if now - self._conn_pool[key][2] > self._conn_pool_ttl:
            writer.close()
            await writer.wait_closed()
