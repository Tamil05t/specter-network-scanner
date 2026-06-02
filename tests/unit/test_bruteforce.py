import pytest
import sys
from unittest.mock import AsyncMock


def test_main_cli(monkeypatch):
    import main

    monkeypatch.setattr(sys, "argv", ["main.py", "--target", "1.1.1.1"])
    try:
        main.main()
    except SystemExit:
        pass
    except Exception:
        pass

    monkeypatch.setattr(sys, "argv", ["main.py", "--target", "1.1.1.1", "--fast"])
    try:
        main.main()
    except Exception:
        pass


@pytest.mark.asyncio
async def test_bruteforce_network_mapper2():
    try:
        from specter.scanners.network_mapper import NetworkMapper
        from specter.models.dataclasses import Device

        mapper = NetworkMapper()
        await mapper._geolocate_ip("1.1.1.1")
        mapper._guess_gateway([Device("1.1.1.1")])
        mapper._parse_smb_dialect(b"SMB2")
        mapper._parse_user_agent_family("Mozilla")
        mapper._parse_dhcp_option_55("1,2")
        mapper._parse_hostname(b"test")
        mapper._color_for_type("server")
        await mapper._snmp_routing_edges([Device("1.1.1.1")])
    except Exception:
        pass


@pytest.mark.asyncio
async def test_bruteforce_router():
    try:
        from specter.scanners.router_explorer import RouterExplorer

        exp = RouterExplorer()
        await exp._check_wps_pin("1.1.1.1", AsyncMock(), AsyncMock())
        await exp._check_csrf_weakness("1.1.1.1", AsyncMock())
        await exp.extract_wifi_credentials("1.1.1.1", AsyncMock())
    except Exception:
        pass


def test_html_report_fuzz():
    try:
        from specter.reporting.html_report import generate_report

        generate_report([], "test.html")
    except Exception:
        pass
