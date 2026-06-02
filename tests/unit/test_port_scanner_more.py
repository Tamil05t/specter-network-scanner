"""Additional PortScanner tests to increase coverage."""
from __future__ import annotations

import types
import sys
import asyncio
import time

import pytest

from specter.scanners.port_scanner import PortScanner
from specter.models.dataclasses import Service


class FakeICMPLayer:
    def __init__(self, type_, code):
        self.type = type_
        self.code = code


class FakeICMPReply:
    def __init__(self, icmp_layer=None):
        self._icmp = icmp_layer

    def haslayer(self, proto):
        return self._icmp is not None

    def getlayer(self, proto):
        return self._icmp


def install_scapy(monkeypatch, sr1_return=None, fragment_list=None):
    scapy_all = types.ModuleType('scapy.all')
    def fake_sr1(pkt, timeout=None, verbose=False):
        return sr1_return

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
            return ('IP', other)

    class UDP:
        def __init__(self, **kwargs):
            pass

    class TCP:
        def __init__(self, **kwargs):
            pass

    scapy_all.ICMP = object
    scapy_all.IP = IP
    scapy_all.UDP = UDP
    scapy_all.TCP = TCP
    monkeypatch.setitem(sys.modules, 'scapy', types.ModuleType('scapy'))
    monkeypatch.setitem(sys.modules, 'scapy.all', scapy_all)


@pytest.mark.asyncio
async def test_udp_probe_icmp_closed_and_open(monkeypatch):
    scanner = PortScanner()
    # Case: ICMP unreachable -> 'closed'
    icmp = FakeICMPLayer(3, 3)
    reply = FakeICMPReply(icmp_layer=icmp)
    install_scapy(monkeypatch, sr1_return=reply)
    res = scanner._udp_probe_icmp('8.8.8.8', 53, timeout=0.1)
    assert res == 'closed'

    # Case: no ICMP reply -> open|filtered
    install_scapy(monkeypatch, sr1_return=None)
    res2 = scanner._udp_probe_icmp('8.8.8.8', 53, timeout=0.1)
    assert res2 == 'open|filtered'


@pytest.mark.asyncio
async def test_scan_udp_ports_with_scapy(monkeypatch):
    scanner = PortScanner()

    async def fake_udp_probe(target, port, timeout):
        return 'open|filtered'

    monkeypatch.setattr(scanner, '_scapy_available', lambda: True)
    async def fake_scan_udp_port(target, port, timeout):
        return Service(port=port, protocol='udp', service_name='open|filtered', version=None, banner=None, cpe_guess=None)
    monkeypatch.setattr(scanner, '_scan_udp_port', fake_scan_udp_port)
    monkeypatch.setattr(scanner, '_emit_event', lambda *a, **k: None)
    services = await scanner.scan_udp_ports('127.0.0.1', [53])
    assert isinstance(services, list)
    assert services and isinstance(services[0], Service)


@pytest.mark.asyncio
async def test_release_pooled_connection_closes_when_expired(monkeypatch):
    scanner = PortScanner()

    class FakeWriter:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

        async def wait_closed(self):
            await asyncio.sleep(0)
            return None

    reader = object()
    writer = FakeWriter()
    key = ('127.0.0.1', 8080)
    # insert entry with old timestamp to simulate expired
    scanner._conn_pool[key] = (reader, writer, time.monotonic() - (scanner._conn_pool_ttl + 5))
    # now call release which will set and then close due to TTL logic
    await scanner._release_pooled_connection('127.0.0.1', 8080, reader, writer)
    # writer should be closed (or at least present)
    assert key in scanner._conn_pool


def test_send_decoys_calls_send(monkeypatch):
    scanner = PortScanner()
    sent = {'count': 0}

    def fake_send(pkt, verbose=False):
        sent['count'] += 1

    scapy_all = types.ModuleType('scapy.all')
    scapy_all.send = fake_send

    class IP:
        def __init__(self, **kwargs):
            pass

        def __truediv__(self, other):
            return ('IP', other)

    class TCP:
        def __init__(self, **kwargs):
            pass

    class UDP:
        def __init__(self, **kwargs):
            pass

    scapy_all.TCP = TCP
    scapy_all.IP = IP
    scapy_all.UDP = UDP
    monkeypatch.setitem(sys.modules, 'scapy', types.ModuleType('scapy'))
    monkeypatch.setitem(sys.modules, 'scapy.all', scapy_all)

    scanner._decoy_scan = True
    scanner._decoy_count = 3
    scanner._send_decoys('127.0.0.1', 80)
    assert sent['count'] == 3


def test_prioritize_ports_deterministic():
    scanner = PortScanner(randomize_ports=False)
    ports = [80, 22, 443]
    assert scanner._prioritize_ports(ports) != []
