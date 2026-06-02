"""Unit tests for data models."""
from __future__ import annotations
from dataclasses import asdict
import json
from pydantic import TypeAdapter
from specter.models.dataclasses import Device, ScanResult, Service, Vulnerability

def test_dataclass_serialization():
    """Ensure dataclass serialization works with asdict.

Args:
    None

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of test_dataclass_serialization
    >>> pass"""
    device = Device(ip='127.0.0.1', open_ports=[80])
    data = asdict(device)
    assert data['ip'] == '127.0.0.1'

def test_scan_result_integrity(sample_scan_result: ScanResult):
    """Verify scan result fixture contents.

Args:
    sample_scan_result (Any): Description of sample_scan_result.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of test_scan_result_integrity
    >>> pass"""
    assert len(sample_scan_result.devices) == 50
    assert sample_scan_result.packets_sent == 5000

def test_json_round_trip(sample_scan_result: ScanResult):
    """Ensure JSON round-trip works for scan results.

Args:
    sample_scan_result (Any): Description of sample_scan_result.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of test_json_round_trip
    >>> pass"""
    payload = asdict(sample_scan_result)
    data = json.loads(json.dumps(payload, default=str))
    assert 'devices' in data

def test_pydantic_validation():
    """Verify Pydantic validation of Device model.

Args:
    None

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of test_pydantic_validation
    >>> pass"""
    adapter = TypeAdapter(Device)
    device = adapter.validate_python({'ip': '127.0.0.1'})
    assert device.ip == '127.0.0.1'