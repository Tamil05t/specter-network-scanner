"""Dataclasses used throughout the scanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional


@dataclass
class Service:
    port: int
    protocol: str
    service_name: str
    version: Optional[str] = None
    banner: Optional[str] = None
    cpe_guess: Optional[str] = None


@dataclass
class Vulnerability:
    cve_id: str
    description: str
    severity: str
    affected_service: Optional[str] = None
    exploit_db_id: Optional[str] = None


@dataclass
class Device:
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    os_guess: Optional[str] = None
    open_ports: List[int] = field(default_factory=list)
    services: List[Service] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    last_seen: Optional[datetime] = None


@dataclass
class ScanResult:
    devices: List[Device]
    scan_duration: float
    packets_sent: int
    correlation_matches: int
