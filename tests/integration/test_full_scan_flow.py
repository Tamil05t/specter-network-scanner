"""Integration tests for full scan flow."""
from __future__ import annotations
import asyncio
import pytest
from specter.core.engine import EngineConfig, ScannerEngine
from specter.correlation.engine import ExploitCorrelator
from specter.reporting.html_report import generate_html_report, generate_sample_data
from specter.scanners.port_scanner import PortScanner

@pytest.mark.asyncio
async def test_full_scan_localhost():
    """Ensure scan completes on localhost.

Args:
    None

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of test_full_scan_localhost
    >>> pass"""
    engine = ScannerEngine(EngineConfig(concurrency=10, rate_limit=50))
    try:
        result = await engine.run(['127.0.0.1'])
        assert result.scan_duration >= 0
    finally:
        await engine.close()

def test_report_generation(tmp_path):
    """Ensure HTML report generation writes a file.

Args:
    tmp_path (Any): Description of tmp_path.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of test_report_generation
    >>> pass"""
    result = generate_sample_data()
    output = tmp_path / 'report.html'
    generate_html_report(result, str(output))
    assert output.exists()

@pytest.mark.asyncio
async def test_local_services_detection(http_test_server, ftp_banner_server):
    """Ensure TCP scans detect local test services.

Args:
    http_test_server (Any): Description of http_test_server.
    ftp_banner_server (Any): Description of ftp_banner_server.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of test_local_services_detection
    >>> pass"""
    http_host, http_port = http_test_server
    ftp_host, ftp_port = ftp_banner_server
    scanner = PortScanner(concurrency=10)
    services = await scanner.scan_tcp_ports('127.0.0.1', [http_port, ftp_port])
    ports = {svc.port for svc in services}
    assert http_port in ports
    assert ftp_port in ports

@pytest.mark.asyncio
async def test_correlation_pipeline(sample_scan_result, mock_exploit_db_csv, tmp_path):
    """Ensure correlation pipeline returns matches.

Args:
    sample_scan_result (Any): Description of sample_scan_result.
    mock_exploit_db_csv (Any): Description of mock_exploit_db_csv.
    tmp_path (Any): Description of tmp_path.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of test_correlation_pipeline
    >>> pass"""
    correlator = ExploitCorrelator(cache_dir=str(tmp_path))
    await correlator._parse_csv(mock_exploit_db_csv)
    correlator._build_index()
    result = await correlator.batch_correlate(sample_scan_result)
    assert result.matches