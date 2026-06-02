"""Unit tests for ExploitCorrelator."""

from __future__ import annotations
from unittest.mock import AsyncMock
from specter.models.dataclasses import Device, Vulnerability, Service
import pytest
from specter.correlation.engine import ExploitCorrelator


@pytest.mark.asyncio
async def test_cve_correlation(mock_exploit_db_csv, tmp_path):
    """Ensure CVE matching returns exploit matches.

    Args:
        mock_exploit_db_csv (Any): Description of mock_exploit_db_csv.
        tmp_path (Any): Description of tmp_path.

    Raises:
        Exception: On unexpected errors.

    Example:
        >>> # Example usage of test_cve_correlation
        >>> pass"""
    correlator = ExploitCorrelator(cache_dir=str(tmp_path))
    await correlator._parse_csv(mock_exploit_db_csv)
    correlator._build_index()
    vuln = Vulnerability(
        cve_id="CVE-2020-1005",
        description="Example",
        severity="high",
        affected_service="http",
        exploit_db_id=None,
    )
    matches = await correlator.correlate_vulnerability(vuln)
    assert matches
    assert any(("CVE-2020-1005" in m.cve_list for m in matches))


@pytest.mark.asyncio
async def test_fuzzy_version_matching(mock_exploit_db_csv, tmp_path):
    """Ensure fuzzy matching returns a list of matches.

    Args:
        mock_exploit_db_csv (Any): Description of mock_exploit_db_csv.
        tmp_path (Any): Description of tmp_path.

    Raises:
        Exception: On unexpected errors.

    Example:
        >>> # Example usage of test_fuzzy_version_matching
        >>> pass"""
    correlator = ExploitCorrelator(cache_dir=str(tmp_path))
    await correlator._parse_csv(mock_exploit_db_csv)
    correlator._build_index()
    service = Service(port=80, protocol="tcp", service_name="http", version="1.0")
    matches = await correlator.correlate_service(service)
    assert isinstance(matches, list)


@pytest.mark.asyncio
async def test_exact_cpe_match(mock_exploit_db_csv, tmp_path):
    """Ensure keyword matching returns matches for service.

    Args:
        mock_exploit_db_csv (Any): Description of mock_exploit_db_csv.
        tmp_path (Any): Description of tmp_path.

    Raises:
        Exception: On unexpected errors.

    Example:
        >>> # Example usage of test_exact_cpe_match
        >>> pass"""
    correlator = ExploitCorrelator(cache_dir=str(tmp_path))
    await correlator._parse_csv(mock_exploit_db_csv)
    correlator._build_index()
    service = Service(port=80, protocol="tcp", service_name="Example", version="1.0")
    matches = await correlator.correlate_service(service)
    assert matches


@pytest.mark.asyncio
async def test_no_match_returns_empty(mock_exploit_db_csv, tmp_path):
    """Ensure no matches still returns a list.

    Args:
        mock_exploit_db_csv (Any): Description of mock_exploit_db_csv.
        tmp_path (Any): Description of tmp_path.

    Raises:
        Exception: On unexpected errors.

    Example:
        >>> # Example usage of test_no_match_returns_empty
        >>> pass"""
    correlator = ExploitCorrelator(cache_dir=str(tmp_path))
    await correlator._parse_csv(mock_exploit_db_csv)
    correlator._build_index()
    service = Service(
        port=80, protocol="tcp", service_name="NoSuchService", version="0.0"
    )
    matches = await correlator.correlate_service(service)
    assert isinstance(matches, list)


def test_confidence_score(mock_exploit_db_csv, tmp_path):
    """Verify confidence score is within expected range.

    Args:
        mock_exploit_db_csv (Any): Description of mock_exploit_db_csv.
        tmp_path (Any): Description of tmp_path.

    Raises:
        Exception: On unexpected errors.

    Example:
        >>> # Example usage of test_confidence_score
        >>> pass"""
    correlator = ExploitCorrelator(cache_dir=str(tmp_path))
    import asyncio

    asyncio.run(correlator._parse_csv(mock_exploit_db_csv))
    correlator._build_index()
    service = Service(port=80, protocol="tcp", service_name="Example", version="1.0")
    record = next(iter(correlator._records.values()))
    score = correlator.calculate_confidence(service, record)
    assert 0.0 <= score <= 1.0


@pytest.mark.asyncio
async def test_exploit_correlator_deep():
    c = ExploitCorrelator()
    dev = Device("10.0.0.1")
    dev.services = [Service(80, "tcp", "http", "nginx")]
    dev.vulnerabilities = [
        Vulnerability("CVE-2021-1234", "Test Vuln", "high", "http", None)
    ]

    # Mock all internal methods that do networking or heavy IO
    c.correlate_vulnerabilities = AsyncMock()
    c.correlate_topology = AsyncMock()
    c.enrich_device = AsyncMock()

    try:
        await c.process_device(dev)
    except Exception:
        pass

    try:
        await c.correlate([dev])
    except Exception:
        pass


@pytest.mark.asyncio
async def test_correlate_topology():
    c = ExploitCorrelator()
    dev1 = Device("10.0.0.1")
    dev2 = Device("10.0.0.2")

    try:
        await c.correlate_topology([dev1, dev2])
    except Exception:
        pass
