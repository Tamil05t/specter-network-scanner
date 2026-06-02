"""Shared fixtures for Specter tests."""

from __future__ import annotations

import asyncio
from dataclasses import asdict
from typing import List

import pytest

from specter.models.dataclasses import Device, ScanResult, Service, Vulnerability


@pytest.fixture()
def sample_banners() -> dict:
    """Return sample service banners for tests.

    Args:
        None

    Returns:
        dict: Mapping of service names to banner strings.

    Raises:
        Exception: Unexpected fixture construction errors.

    Example:
        >>> banners = sample_banners()

    Note:
        Banners are synthetic and not from live services.
    """
    return {
        "http": "Server: nginx/1.18.0",
        "ssh": "SSH-2.0-OpenSSH_8.2",
        "ftp": "220 (vsFTPd 3.0.3)",
        "redis": "-NOAUTH Authentication required.",
    }


@pytest.fixture()
def sample_devices() -> List[Device]:
    """Build a sample device list for tests.

    Args:
        None

    Returns:
        List[Device]: List of synthetic device records.

    Raises:
        Exception: Unexpected fixture construction errors.

    Example:
        >>> devices = sample_devices()

    Note:
        Ports and services are static for test determinism.
    """
    devices = []
    for i in range(1, 51):
        devices.append(
            Device(
                ip=f"192.168.1.{i}",
                mac=f"00:11:22:33:44:{i:02d}",
                hostname=f"host-{i}",
                os_guess="linux" if i % 2 == 0 else "windows",
                open_ports=[22, 80],
                services=[
                    Service(port=80, protocol="tcp", service_name="http", version="1.0"),
                    Service(port=22, protocol="tcp", service_name="ssh", version="7.9"),
                ],
                vulnerabilities=[
                    Vulnerability(
                        cve_id="CVE-2020-0001",
                        description="Test vuln",
                        severity="high",
                        affected_service="http",
                        exploit_db_id=12345,
                    )
                ],
            )
        )
    return devices


@pytest.fixture()
def sample_scan_result(sample_devices: List[Device]) -> ScanResult:
    """Create a sample ScanResult fixture.

    Args:
        sample_devices (List[Device]): Device list fixture.

    Returns:
        ScanResult: Sample scan result built from fixtures.

    Raises:
        Exception: Unexpected fixture construction errors.

    Example:
        >>> result = sample_scan_result(sample_devices)

    Note:
        Uses a fixed duration and packet count.
    """
    return ScanResult(
        devices=sample_devices,
        scan_duration=12.5,
        packets_sent=5000,
        correlation_matches=10,
    )


@pytest.fixture()
def mock_exploit_db_csv(tmp_path) -> str:
    """Create a mock Exploit-DB CSV file.

    Args:
        tmp_path (pathlib.Path): Pytest temporary path.

    Returns:
        str: Path to the CSV file as a string.

    Raises:
        OSError: If the temporary file cannot be written.

    Example:
        >>> path = mock_exploit_db_csv(tmp_path)

    Note:
        Rows embed synthetic CVE identifiers for testing.
    """
    csv_path = tmp_path / "files_exploits.csv"
    header = "id,file,description,date,author,platform,type,port,verified,codes\n"
    rows = []
    for i in range(100):
        rows.append(
            f"{i},exploit-{i}.txt,Example exploit CVE-2020-{1000 + i},2020-01-01,author,linux,remote,0,1,CVE-2020-{1000 + i}\n"
        )
    csv_path.write_text(header + "".join(rows), encoding="utf-8")
    return str(csv_path)


@pytest.fixture()
async def tcp_banner_server():
    """Start a TCP server that emits an SSH banner.

    Args:
        event_loop (asyncio.AbstractEventLoop): Pytest event loop fixture.

    Returns:
        tuple: Bound address tuple for the server.

    Raises:
        OSError: If the server cannot bind the socket.

    Example:
        >>> host, port = await tcp_banner_server

    Note:
        The server is closed after the fixture yields.
    """
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle a single TCP connection with a banner response.

        Args:
            reader (asyncio.StreamReader): StreamReader for the connection.
            writer (asyncio.StreamWriter): StreamWriter for the connection.

        Returns:
            None: Writes a banner and closes the connection.

        Raises:
            Exception: Unexpected socket errors are suppressed by asyncio.

        Example:
            >>> await handler(reader, writer)

        Note:
            The banner is a fixed SSH string for tests.
        """
        writer.write(b"SSH-2.0-OpenSSH_8.2\r\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    addr = server.sockets[0].getsockname()
    yield addr
    server.close()
    await server.wait_closed()


@pytest.fixture()
async def http_test_server():
    """Start a simple HTTP server for tests.

    Args:
        event_loop (asyncio.AbstractEventLoop): Pytest event loop fixture.

    Returns:
        tuple: Bound address tuple for the server.

    Raises:
        OSError: If the server cannot bind the socket.

    Example:
        >>> host, port = await http_test_server

    Note:
        The server is closed after the fixture yields.
    """
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle a single HTTP request.

        Args:
            reader (asyncio.StreamReader): StreamReader for the connection.
            writer (asyncio.StreamWriter): StreamWriter for the connection.

        Returns:
            None: Writes a basic HTTP response.

        Raises:
            Exception: Unexpected socket errors are suppressed by asyncio.

        Example:
            >>> await handler(reader, writer)

        Note:
            Response includes a Server header for parsing.
        """
        data = await reader.read(1024)
        _ = data
        response = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "Server: TestServer/1.0\r\n\r\n"
            "<html><title>Test Router</title><body>OK</body></html>"
        )
        writer.write(response.encode("utf-8"))
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    addr = server.sockets[0].getsockname()
    yield addr
    server.close()
    await server.wait_closed()


@pytest.fixture()
async def ftp_banner_server():
    """Start a TCP server that emits an FTP banner.

    Args:
        event_loop (asyncio.AbstractEventLoop): Pytest event loop fixture.

    Returns:
        tuple: Bound address tuple for the server.

    Raises:
        OSError: If the server cannot bind the socket.

    Example:
        >>> host, port = await ftp_banner_server

    Note:
        The server is closed after the fixture yields.
    """
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle a single TCP connection with an FTP banner.

        Args:
            reader (asyncio.StreamReader): StreamReader for the connection.
            writer (asyncio.StreamWriter): StreamWriter for the connection.

        Returns:
            None: Writes a banner and closes the connection.

        Raises:
            Exception: Unexpected socket errors are suppressed by asyncio.

        Example:
            >>> await handler(reader, writer)

        Note:
            The banner is a fixed FTP string for tests.
        """
        writer.write(b"220 (vsFTPd 3.0.3)\r\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    addr = server.sockets[0].getsockname()
    yield addr
    server.close()
    await server.wait_closed()
