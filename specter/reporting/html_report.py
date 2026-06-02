"""HTML report generation with interactive topology and dashboards."""

from __future__ import annotations
import csv
import json
from dataclasses import asdict
from datetime import datetime
from typing import Any, Dict, List, Optional
import aiofiles
from jinja2 import Template
from specter.models.dataclasses import Device, ScanResult, Service

try:
    from pyvis.network import Network
except Exception:
    Network = None
SEVERITY_COLORS = {
    "critical": "#FF0000",
    "high": "#FF4500",
    "medium": "#FFA500",
    "low": "#FFD700",
    "info": "#00BFFF",
}


def risk_score(device: Device, exposed_admin: int = 0) -> float:
    """Compute a basic risk score for a device.

    Args:
            device (Device): Device record to score.
            exposed_admin (int): Count of exposed admin endpoints.

    Returns:
            float: Risk score value.

    Raises:
            Exception: Unexpected calculation errors.

    Example:
            >>> risk_score(Device(ip="127.0.0.1"))

    Note:
            Scores are heuristic and not CVSS.
    """
    counts = _count_vuln_severity(device)
    score = (
        counts["critical"] * 10
        + counts["high"] * 5
        + counts["medium"] * 2
        + counts["low"] * 1
        + len(device.open_ports) * 0.5
        + exposed_admin * 3
    )
    return round(score, 2)


def generate_html_report(
    result: ScanResult, output_path: str, previous_result: Optional[ScanResult] = None
) -> None:
    """Generate a single-file HTML report with embedded CSS/JS.

    Args:
            result (ScanResult): Current scan result.
            output_path (str): Output HTML path.
            previous_result (Optional[ScanResult]): Optional previous scan result for diff.

    Returns:
            None: Writes a report to disk.

    Raises:
            OSError: If the report cannot be written.

    Example:
            >>> generate_html_report(result, "report.html")

    Note:
            Uses an inline HTML template.
    """
    template = Template(_template_html())
    report_data = _build_report_data(result, previous_result)
    html = template.render(**report_data)
    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(html)


async def export_json(result: ScanResult, output_path: str) -> None:
    """Export scan results to JSON.

    Args:
            result (ScanResult): Scan results to export.
            output_path (str): Destination JSON path.

    Returns:
            None: Writes JSON to disk.

    Raises:
            OSError: If the file cannot be written.

    Example:
            >>> await export_json(result, "report.json")

    Note:
            Uses dataclass serialization.
    """
    async with aiofiles.open(output_path, "w", encoding="utf-8") as handle:
        await handle.write(json.dumps(asdict(result), indent=2, default=str))


async def export_csv(result: ScanResult, output_path: str) -> None:
    """Export scan results to CSV.

    Args:
            result (ScanResult): Scan results to export.
            output_path (str): Destination CSV path.

    Returns:
            None: Writes CSV to disk.

    Raises:
            OSError: If the file cannot be written.

    Example:
            >>> await export_csv(result, "report.csv")

    Note:
            CSV is flattened by device.
    """
    rows = []
    for device in result.devices:
        rows.append(
            {
                "ip": device.ip,
                "mac": device.mac or "",
                "hostname": device.hostname or "",
                "os": device.os_guess or "",
                "open_ports": ",".join((str(p) for p in device.open_ports)),
                "services": ",".join((svc.service_name for svc in device.services)),
            }
        )
    async with aiofiles.open(output_path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()) if rows else [])
        if rows:
            await handle.write(",".join(writer.fieldnames) + "\n")
            for row in rows:
                await handle.write(",".join(row.values()) + "\n")


async def export_markdown_summary(result: ScanResult, output_path: str) -> None:
    """Export a lightweight Markdown summary.

    Args:
            result (ScanResult): Scan results to summarize.
            output_path (str): Destination Markdown path.

    Returns:
            None: Writes Markdown to disk.

    Raises:
            OSError: If the file cannot be written.

    Example:
            >>> await export_markdown_summary(result, "summary.md")

    Note:
            Output is a compact overview.
    """
    lines = ["# Specter Network Scanner Report", "", f"Devices: {len(result.devices)}"]
    for device in result.devices:
        lines.append(f"- {device.ip} ({device.hostname or 'unknown'})")
    async with aiofiles.open(output_path, "w", encoding="utf-8") as handle:
        await handle.write("\n".join(lines))


async def export_siem_json(result: ScanResult, output_path: str) -> None:
    """Export scan results in SIEM-friendly JSON.

    Args:
            result (ScanResult): Scan results to export.
            output_path (str): Destination JSON path.

    Returns:
            None: Writes SIEM JSON to disk.

    Raises:
            OSError: If the file cannot be written.

    Example:
            >>> await export_siem_json(result, "siem.json")

    Note:
            Structure is optimized for ingestion.
    """
    payload = []
    for device in result.devices:
        payload.append(
            {
                "asset": {
                    "ip": device.ip,
                    "mac": device.mac,
                    "hostname": device.hostname,
                    "os": device.os_guess,
                },
                "exposure": {
                    "open_ports": device.open_ports,
                    "services": [svc.service_name for svc in device.services],
                    "risk_score": risk_score(device),
                },
                "findings": [
                    {
                        "cve": vuln.cve_id,
                        "severity": vuln.severity,
                        "description": vuln.description,
                        "exploit_db_id": vuln.exploit_db_id,
                    }
                    for vuln in device.vulnerabilities
                ],
            }
        )
    async with aiofiles.open(output_path, "w", encoding="utf-8") as handle:
        await handle.write(json.dumps(payload, indent=2))


def generate_sample_data() -> ScanResult:
    """Generate sample scan results for demos/tests.

    Args:
        None

    Returns:
        Any: Description of return value.

    Raises:
        Exception: On unexpected errors.

    Example:
        >>> # Example usage of generate_sample_data
        >>> pass"""
    devices = []
    for i in range(1, 6):
        devices.append(
            Device(
                ip=f"192.168.1.{i}",
                mac=f"00:11:22:33:44:{i:02d}",
                hostname=f"host-{i}",
                os_guess="linux" if i % 2 == 0 else "windows",
                open_ports=[22, 80, 443] if i % 2 == 0 else [445, 3389],
                services=[
                    Service(
                        port=80, protocol="tcp", service_name="http", version="1.0"
                    ),
                    Service(port=22, protocol="tcp", service_name="ssh", version="7.9"),
                ],
                vulnerabilities=[],
            )
        )
    return ScanResult(
        devices=devices, scan_duration=12.5, packets_sent=1200, correlation_matches=5
    )


def _build_report_data(
    result: ScanResult, previous_result: Optional[ScanResult]
) -> Dict[str, Any]:
    """Build report data used by the HTML template.

    Args:
            result (ScanResult): Current scan result.
            previous_result (Optional[ScanResult]): Optional prior scan result.

    Returns:
            Dict[str, Any]: Template context dictionary.

    Raises:
            Exception: Unexpected aggregation errors.

    Example:
            >>> data = _build_report_data(result, None)

    Note:
            Chart data is precomputed for inline rendering.
    """
    devices = result.devices
    vuln_counts = _aggregate_vulns(devices)
    topology_html = _build_topology(devices)
    device_rows = _build_device_rows(devices)
    service_rows = _build_service_rows(devices)
    exploit_rows = _build_exploit_rows(devices)
    charts = _build_chart_data(devices)
    top_vuln = _top_vulnerable_devices(devices)
    timeline = _build_timeline(devices)
    scan_stats = {
        "duration": result.scan_duration,
        "packets": result.packets_sent,
        "hosts": len(devices),
        "profile": "default",
        "version": "0.1.0",
        "timestamp": datetime.utcnow().isoformat(),
    }
    diff = _build_diff(previous_result, result) if previous_result else None
    return {
        "topology_html": topology_html,
        "devices": device_rows,
        "services": service_rows,
        "exploits": exploit_rows,
        "vuln_counts": vuln_counts,
        "scan_stats": scan_stats,
        "severity_colors": SEVERITY_COLORS,
        "diff": diff,
        "charts": charts,
        "charts_json": json.dumps(charts),
        "top_vuln": top_vuln,
        "timeline": timeline,
    }


def _build_topology(devices: List[Device]) -> str:
    """Render topology HTML using pyvis when available.

    Args:
            devices: Device list to visualize.

    Returns:
            str: HTML snippet.

    Raises:
            Exception: Pyvis errors are suppressed.

    Example:
            >>> html = _build_topology(devices)

    Note:
            Returns a fallback message when pyvis is unavailable.
    """
    if Network is None:
        return "<div class='text-muted'>pyvis not available</div>"
    net = Network(height="500px", width="100%", bgcolor="#111", font_color="#eee")
    for device in devices:
        dtype = _device_type(device)
        color = _device_color(dtype)
        size = max(10, 10 + len(device.open_ports) * 2)
        tooltip = f"IP: {device.ip}<br>OS: {device.os_guess or 'unknown'}<br>Ports: {len(device.open_ports)}"
        net.add_node(
            device.ip,
            label=device.hostname or device.ip,
            color=color,
            size=size,
            title=tooltip,
        )
    if devices:
        root = devices[0].ip
        for device in devices[1:]:
            net.add_edge(root, device.ip, value=1)
    return net.generate_html()


def _build_device_rows(devices: List[Device]) -> List[Dict[str, Any]]:
    """Build device table rows for reporting.

    Args:
            devices: Device list to render.

    Returns:
            List[Dict[str, Any]]: List of row dictionaries.

    Raises:
            Exception: Unexpected aggregation errors.

    Example:
            >>> rows = _build_device_rows(devices)

    Note:
            Risk scores are computed per device.
    """
    rows = []
    for device in devices:
        rows.append(
            {
                "ip": device.ip,
                "mac": device.mac or "",
                "hostname": device.hostname or "",
                "os": device.os_guess or "",
                "open_ports": ",".join((str(p) for p in device.open_ports)),
                "services": ",".join((svc.service_name for svc in device.services)),
                "risk": risk_score(device),
            }
        )
    return rows


def _build_service_rows(devices: List[Device]) -> List[Dict[str, Any]]:
    """Build service table rows for reporting.

    Args:
            devices: Device list to render.

    Returns:
            List[Dict[str, Any]]: List of row dictionaries.

    Raises:
            Exception: Unexpected aggregation errors.

    Example:
            >>> rows = _build_service_rows(devices)

    Note:
            Services are flattened per device.
    """
    rows = []
    for device in devices:
        for svc in device.services:
            rows.append(
                {
                    "ip": device.ip,
                    "port": svc.port,
                    "protocol": svc.protocol,
                    "service": svc.service_name,
                    "version": svc.version or "",
                    "banner": svc.banner or "",
                    "cves": "",
                }
            )
    return rows


def _build_exploit_rows(devices: List[Device]) -> List[Dict[str, Any]]:
    """Build exploit correlation rows for reporting.

    Args:
            devices: Device list to render.

    Returns:
            List[Dict[str, Any]]: List of row dictionaries.

    Raises:
            Exception: Unexpected aggregation errors.

    Example:
            >>> rows = _build_exploit_rows(devices)

    Note:
            Metasploit is inferred from description text.
    """
    rows = []
    for device in devices:
        for vuln in device.vulnerabilities:
            public_exploit = bool(vuln.exploit_db_id)
            metasploit = "metasploit" in (vuln.description or "").lower()
            rows.append(
                {
                    "service": vuln.affected_service or "",
                    "cve": vuln.cve_id,
                    "exploit_id": vuln.exploit_db_id or "",
                    "title": vuln.description,
                    "type": "unknown",
                    "confidence": "0.6",
                    "public_exploit": "yes" if public_exploit else "no",
                    "metasploit": "yes" if metasploit else "no",
                }
            )
    return rows


def _build_chart_data(devices: List[Device]) -> Dict[str, Any]:
    """Aggregate chart data from device list.

    Args:
            devices: Device list to analyze.

    Returns:
            Dict[str, Any]: Chart data dictionary.

    Raises:
            Exception: Unexpected aggregation errors.

    Example:
            >>> charts = _build_chart_data(devices)

    Note:
            Values are truncated for display.
    """
    port_counts: Dict[int, int] = {}
    service_counts: Dict[str, int] = {}
    os_counts: Dict[str, int] = {}
    subnet_risk: Dict[str, float] = {}
    for device in devices:
        for port in device.open_ports:
            port_counts[port] = port_counts.get(port, 0) + 1
        for svc in device.services:
            service_counts[svc.service_name] = (
                service_counts.get(svc.service_name, 0) + 1
            )
        os_name = device.os_guess or "unknown"
        os_counts[os_name] = os_counts.get(os_name, 0) + 1
        subnet = ".".join(device.ip.split(".")[:3]) + ".0/24"
        subnet_risk[subnet] = subnet_risk.get(subnet, 0) + risk_score(device)
    cvss_labels = ["0-2", "3-4", "5-6", "7-8", "9-10"]
    cvss_values = [0, 0, 0, 0, 0]
    for device in devices:
        for vuln in device.vulnerabilities:
            sev = (vuln.severity or "info").lower()
            if sev == "critical":
                cvss_values[4] += 1
            elif sev == "high":
                cvss_values[3] += 1
            elif sev == "medium":
                cvss_values[2] += 1
            elif sev == "low":
                cvss_values[1] += 1
            else:
                cvss_values[0] += 1
    port_labels = list(map(str, list(port_counts.keys())[:15]))
    port_values = list(port_counts.values())[:15]
    service_labels = list(service_counts.keys())[:12]
    service_values = list(service_counts.values())[:12]
    return {
        "port_labels": port_labels,
        "port_values": port_values,
        "service_labels": service_labels,
        "service_values": service_values,
        "os_labels": list(os_counts.keys()),
        "os_values": list(os_counts.values()),
        "subnet_labels": list(subnet_risk.keys()),
        "subnet_values": [round(v, 2) for v in subnet_risk.values()],
        "cvss_labels": cvss_labels,
        "cvss_values": cvss_values,
        "treemap_labels": service_labels,
        "treemap_values": service_values,
        "waterfall_labels": [
            "Discovery",
            "Port Scan",
            "Fingerprint",
            "Router",
            "Report",
        ],
        "waterfall_values": [20, 35, 25, 10, 10],
    }


def _top_vulnerable_devices(devices: List[Device]) -> List[Dict[str, Any]]:
    """Return top vulnerable devices by risk score.

    Args:
            devices: Device list to rank.

    Returns:
            List[Dict[str, Any]]: List of top device summaries.

    Raises:
            Exception: Unexpected aggregation errors.

    Example:
            >>> top = _top_vulnerable_devices(devices)

    Note:
            Top 10 devices are selected by risk score.
    """
    ranked = sorted(devices, key=lambda d: risk_score(d), reverse=True)[:10]
    return [
        {"ip": d.ip, "hostname": d.hostname or "", "risk": risk_score(d)}
        for d in ranked
    ]


def _build_timeline(devices: List[Device]) -> List[Dict[str, Any]]:
    """Build a simple vulnerability timeline.

    Args:
            devices: Device list to analyze.

    Returns:
            List[Dict[str, Any]]: List of timeline events.

    Raises:
            Exception: Unexpected aggregation errors.

    Example:
            >>> timeline = _build_timeline(devices)

    Note:
            Timeline is capped for display.
    """
    timeline = []
    base = datetime.utcnow()
    for device in devices:
        for vuln in device.vulnerabilities:
            timestamp = base.replace(microsecond=0).isoformat()
            timeline.append({"time": timestamp, "event": vuln.cve_id})
    return timeline[:20]


def _aggregate_vulns(devices: List[Device]) -> Dict[str, int]:
    """Aggregate vulnerability counts by severity.

    Args:
            devices: Device list to analyze.

    Returns:
            Dict[str, int]: Severity count map.

    Raises:
            Exception: Unexpected aggregation errors.

    Example:
            >>> counts = _aggregate_vulns(devices)

    Note:
            Unknown severities are counted as info.
    """
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for device in devices:
        for vuln in device.vulnerabilities:
            severity = (vuln.severity or "info").lower()
            if severity not in counts:
                severity = "info"
            counts[severity] += 1
    return counts


def _count_vuln_severity(device: Device) -> Dict[str, int]:
    """Count vulnerabilities by severity for one device.

    Args:
            device: Device record.

    Returns:
            Dict[str, int]: Severity count map.

    Raises:
            Exception: Unexpected aggregation errors.

    Example:
            >>> counts = _count_vuln_severity(device)

    Note:
            Unknown severities are counted as info.
    """
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for vuln in device.vulnerabilities:
        sev = (vuln.severity or "info").lower()
        if sev not in counts:
            sev = "info"
        counts[sev] += 1
    return counts


def _device_type(device: Device) -> str:
    """Infer device type for report coloring.

    Args:
            device: Device record.

    Returns:
            str: Device type label.

    Raises:
            Exception: Unexpected errors.

    Example:
            >>> _device_type(device)

    Note:
            Router detection uses hostname heuristics.
    """
    if "router" in (device.hostname or "").lower():
        return "router"
    if any((svc.service_name in {"http", "https"} for svc in device.services)):
        return "server"
    if 445 in device.open_ports:
        return "workstation"
    return "unknown"


def _device_color(device_type: str) -> str:
    """Return a color for a device type label.

    Args:
            device_type: Device type label.

    Returns:
            str: Hex color string.

    Raises:
            Exception: Unexpected errors.

    Example:
            >>> _device_color("server")

    Note:
            Falls back to gray for unknown types.
    """
    return {
        "router": "#FF0000",
        "server": "#2E86DE",
        "workstation": "#28B463",
        "iot": "#F39C12",
        "unknown": "#7F8C8D",
    }.get(device_type, "#7F8C8D")


def _build_diff(previous: ScanResult, current: ScanResult) -> Dict[str, Any]:
    """Compute a diff between two scan results.

    Args:
            previous: Previous scan result.
            current: Current scan result.

    Returns:
            Dict[str, Any]: Diff summary dictionary.

    Raises:
            Exception: Unexpected aggregation errors.

    Example:
            >>> diff = _build_diff(prev, curr)

    Note:
            Compares only IP addresses.
    """
    prev_ips = {d.ip for d in previous.devices}
    curr_ips = {d.ip for d in current.devices}
    return {
        "new_hosts": sorted(curr_ips - prev_ips),
        "removed_hosts": sorted(prev_ips - curr_ips),
    }


def _template_html() -> str:
    """Return the HTML template for the report.

    Args:
            None

    Returns:
            str: HTML template string.

    Raises:
            Exception: Unexpected errors.

    Example:
            >>> html = _template_html()

    Note:
            Template is self-contained with inline assets.
    """
    return '\n<!DOCTYPE html>\n<html lang="en">\n<head>\n        <meta charset="UTF-8" />\n        <meta name="viewport" content="width=device-width, initial-scale=1.0" />\n        <title>Specter Network Scanner Report</title>\n        <style>\n                :root {\n                        --bg: #0b0f14;\n                        --panel: #141b24;\n                        --text: #e8eef4;\n                        --muted: #8aa0b6;\n                        --accent: #2e86de;\n                        --danger: #ff4500;\n                        --border: #223045;\n                }\n                html { scroll-behavior: smooth; }\n                body { background: var(--bg); color: var(--text); margin: 0; font-family: "Segoe UI", Arial, sans-serif; }\n                .container { max-width: 1200px; margin: 0 auto; padding: 24px; }\n                .card { background: var(--panel); border-radius: 12px; padding: 16px; margin-bottom: 16px; border: 1px solid var(--border); }\n                .row { display: flex; flex-wrap: wrap; gap: 12px; }\n                .col { flex: 1 1 260px; }\n                .section-title { font-size: 18px; font-weight: 600; margin-bottom: 8px; }\n                .badge { display: inline-block; padding: 2px 8px; border-radius: 8px; background: #223045; color: #fff; font-size: 12px; }\n                .toc a { color: var(--text); margin-right: 12px; text-decoration: none; }\n                .toc a:hover { text-decoration: underline; }\n                table { width: 100%; border-collapse: collapse; font-size: 13px; }\n                th, td { border-bottom: 1px solid var(--border); padding: 8px; text-align: left; }\n                th { cursor: pointer; color: var(--muted); }\n                tr:hover { background: rgba(255,255,255,0.03); }\n                .search { margin: 8px 0; padding: 6px 10px; width: 100%; border-radius: 8px; border: 1px solid var(--border); background: #0f1319; color: var(--text); }\n                .details-row { display: none; }\n                .details-row td { background: #0f1319; }\n                .canvas-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 12px; }\n                canvas { background: #0f1319; border-radius: 10px; padding: 8px; }\n                details summary { cursor: pointer; }\n                @media print { body { background: #fff; color: #000; } .card { border: 1px solid #ccc; } }\n        </style>\n</head>\n<body>\n        <div class="container">\n                <div class="card">\n                        <div class="row" style="justify-content: space-between; align-items: center;">\n                                <div class="section-title">Executive Summary</div>\n                                <span class="badge">Self-contained</span>\n                        </div>\n                        <div class="row">\n                                <div class="col">Hosts: {{ scan_stats.hosts }}</div>\n                                <div class="col">Duration: {{ scan_stats.duration }}s</div>\n                                <div class="col">Packets: {{ scan_stats.packets }}</div>\n                                <div class="col">Version: {{ scan_stats.version }}</div>\n                        </div>\n                </div>\n\n                <div class="card toc">\n                        <a href="#topology">Topology</a>\n                        <a href="#inventory">Inventory</a>\n                        <a href="#vulns">Vulnerabilities</a>\n                        <a href="#exploits">Exploit Correlations</a>\n                        <a href="#stats">Statistics</a>\n                </div>\n\n                <details class="card" id="topology" open>\n                        <summary class="section-title">Network Topology</summary>\n                        {{ topology_html | safe }}\n                </details>\n\n                <details class="card" id="inventory" open>\n                        <summary class="section-title">Device Inventory</summary>\n                        <input class="search" data-table="device-table" placeholder="Search devices..." />\n                        <table id="device-table" data-sort>\n                                <thead>\n                                        <tr><th>IP</th><th>MAC</th><th>Hostname</th><th>OS</th><th>Open Ports</th><th>Services</th><th>Risk</th></tr>\n                                </thead>\n                                <tbody>\n                                        {% for row in devices %}\n                                        <tr class="data-row" data-detail="details-{{ loop.index }}">\n                                                <td>{{ row.ip }}</td>\n                                                <td>{{ row.mac }}</td>\n                                                <td>{{ row.hostname }}</td>\n                                                <td>{{ row.os }}</td>\n                                                <td>{{ row.open_ports }}</td>\n                                                <td>{{ row.services }}</td>\n                                                <td>{{ row.risk }}</td>\n                                        </tr>\n                                        <tr id="details-{{ loop.index }}" class="details-row">\n                                                <td colspan="7">IP: {{ row.ip }} | Services: {{ row.services }} | Risk: {{ row.risk }}</td>\n                                        </tr>\n                                        {% endfor %}\n                                </tbody>\n                        </table>\n                </details>\n\n                <details class="card" id="vulns" open>\n                        <summary class="section-title">Vulnerability Matrix</summary>\n                        <div class="canvas-grid">\n                                <canvas id="severityChart" height="140"></canvas>\n                                <canvas id="cvssChart" height="140"></canvas>\n                        </div>\n                        <input class="search" data-table="service-table" placeholder="Search services..." />\n                        <table id="service-table" data-sort>\n                                <thead>\n                                        <tr><th>IP</th><th>Port</th><th>Protocol</th><th>Service</th><th>Version</th><th>Banner</th><th>CVEs</th></tr>\n                                </thead>\n                                <tbody>\n                                        {% for row in services %}\n                                        <tr>\n                                                <td>{{ row.ip }}</td>\n                                                <td>{{ row.port }}</td>\n                                                <td>{{ row.protocol }}</td>\n                                                <td>{{ row.service }}</td>\n                                                <td>{{ row.version }}</td>\n                                                <td>{{ row.banner }}</td>\n                                                <td>{{ row.cves }}</td>\n                                        </tr>\n                                        {% endfor %}\n                                </tbody>\n                        </table>\n                </details>\n\n                <details class="card" id="exploits" open>\n                        <summary class="section-title">Exploit Correlations</summary>\n                        <input class="search" data-table="exploit-table" placeholder="Search exploits..." />\n                        <table id="exploit-table" data-sort>\n                                <thead>\n                                        <tr><th>Service</th><th>CVE</th><th>Exploit-DB ID</th><th>Title</th><th>Type</th><th>Confidence</th><th>Public</th><th>Metasploit</th></tr>\n                                </thead>\n                                <tbody>\n                                        {% for row in exploits %}\n                                        <tr>\n                                                <td>{{ row.service }}</td>\n                                                <td>{{ row.cve }}</td>\n                                                <td>{{ row.exploit_id }}</td>\n                                                <td>{{ row.title }}</td>\n                                                <td>{{ row.type }}</td>\n                                                <td>{{ row.confidence }}</td>\n                                                <td>{{ row.public_exploit }}</td>\n                                                <td>{{ row.metasploit }}</td>\n                                        </tr>\n                                        {% endfor %}\n                                </tbody>\n                        </table>\n                </details>\n\n                <details class="card" id="stats" open>\n                        <summary class="section-title">Scan Statistics</summary>\n                        <div>Scan Profile: {{ scan_stats.profile }}</div>\n                        <div>Timestamp: {{ scan_stats.timestamp }}</div>\n                        <div class="canvas-grid">\n                                <canvas id="portChart" height="120"></canvas>\n                                <canvas id="osChart" height="120"></canvas>\n                                <canvas id="serviceChart" height="120"></canvas>\n                                <canvas id="waterfallChart" height="120"></canvas>\n                                <canvas id="treemapChart" height="120"></canvas>\n                                <canvas id="radarChart" height="120"></canvas>\n                                <canvas id="heatmapChart" height="120"></canvas>\n                        </div>\n                        <div class="section-title">Top 10 Most Vulnerable Devices</div>\n                        <table>\n                                <thead><tr><th>IP</th><th>Hostname</th><th>Risk</th></tr></thead>\n                                <tbody>\n                                        {% for row in top_vuln %}\n                                        <tr><td>{{ row.ip }}</td><td>{{ row.hostname }}</td><td>{{ row.risk }}</td></tr>\n                                        {% endfor %}\n                                </tbody>\n                        </table>\n                        <div class="section-title">Vulnerability Timeline</div>\n                        <table>\n                                <thead><tr><th>Time</th><th>Event</th></tr></thead>\n                                <tbody>\n                                        {% for row in timeline %}\n                                        <tr><td>{{ row.time }}</td><td>{{ row.event }}</td></tr>\n                                        {% endfor %}\n                                </tbody>\n                        </table>\n                        {% if diff %}\n                        <div class="section-title">Compare Mode</div>\n                        <div>New Hosts: {{ diff.new_hosts|join(\', \') }}</div>\n                        <div>Removed Hosts: {{ diff.removed_hosts|join(\', \') }}</div>\n                        {% endif %}\n                </details>\n        </div>\n\n        <script>\n                const charts = {{ charts_json | safe }};\n\n                function filterTable(input) {\n                        const table = document.getElementById(input.dataset.table);\n                        if (!table) return;\n                        const filter = input.value.toLowerCase();\n                        const rows = table.querySelectorAll("tbody tr");\n                        rows.forEach(row => {\n                                const text = row.textContent.toLowerCase();\n                                row.style.display = text.includes(filter) ? "" : "none";\n                        });\n                }\n\n                function sortTable(table, colIndex) {\n                        const rows = Array.from(table.querySelectorAll("tbody tr")).filter(r => !r.classList.contains("details-row"));\n                        const asc = table.dataset.sortAsc === "true" ? false : true;\n                        rows.sort((a, b) => {\n                                const aText = a.children[colIndex].textContent.trim();\n                                const bText = b.children[colIndex].textContent.trim();\n                                return asc ? aText.localeCompare(bText) : bText.localeCompare(aText);\n                        });\n                        table.dataset.sortAsc = asc;\n                        const tbody = table.querySelector("tbody");\n                        rows.forEach(row => {\n                                tbody.appendChild(row);\n                                const detailId = row.dataset.detail;\n                                if (detailId) {\n                                        const detailRow = document.getElementById(detailId);\n                                        if (detailRow) tbody.appendChild(detailRow);\n                                }\n                        });\n                }\n\n                function drawBar(ctx, labels, values, color) {\n                        const width = ctx.canvas.width;\n                        const height = ctx.canvas.height;\n                        ctx.clearRect(0, 0, width, height);\n                        const max = Math.max(...values, 1);\n                        const barWidth = width / values.length;\n                        values.forEach((v, i) => {\n                                const barHeight = (v / max) * (height - 20);\n                                ctx.fillStyle = color;\n                                ctx.fillRect(i * barWidth + 4, height - barHeight - 10, barWidth - 8, barHeight);\n                        });\n                }\n\n                function drawDonut(ctx, values, colors) {\n                        const total = values.reduce((a, b) => a + b, 0) || 1;\n                        let start = 0;\n                        values.forEach((v, i) => {\n                                const slice = (v / total) * Math.PI * 2;\n                                ctx.beginPath();\n                                ctx.moveTo(80, 80);\n                                ctx.arc(80, 80, 60, start, start + slice);\n                                ctx.fillStyle = colors[i % colors.length];\n                                ctx.fill();\n                                start += slice;\n                        });\n                        ctx.globalCompositeOperation = "destination-out";\n                        ctx.beginPath();\n                        ctx.arc(80, 80, 30, 0, Math.PI * 2);\n                        ctx.fill();\n                        ctx.globalCompositeOperation = "source-over";\n                }\n\n                function drawRadar(ctx, labels, values, color) {\n                        const w = ctx.canvas.width;\n                        const h = ctx.canvas.height;\n                        const cx = w / 2;\n                        const cy = h / 2;\n                        const max = Math.max(...values, 1);\n                        const radius = Math.min(cx, cy) - 10;\n                        ctx.clearRect(0, 0, w, h);\n                        ctx.strokeStyle = "#223045";\n                        for (let r = 1; r <= 4; r++) {\n                                ctx.beginPath();\n                                ctx.arc(cx, cy, (radius * r) / 4, 0, Math.PI * 2);\n                                ctx.stroke();\n                        }\n                        ctx.beginPath();\n                        values.forEach((v, i) => {\n                                const angle = (i / values.length) * Math.PI * 2 - Math.PI / 2;\n                                const dist = (v / max) * radius;\n                                const x = cx + Math.cos(angle) * dist;\n                                const y = cy + Math.sin(angle) * dist;\n                                if (i === 0) ctx.moveTo(x, y);\n                                else ctx.lineTo(x, y);\n                        });\n                        ctx.closePath();\n                        ctx.fillStyle = color;\n                        ctx.globalAlpha = 0.4;\n                        ctx.fill();\n                        ctx.globalAlpha = 1;\n                        ctx.strokeStyle = color;\n                        ctx.stroke();\n                }\n\n                function drawTreemap(ctx, labels, values) {\n                        const w = ctx.canvas.width;\n                        const h = ctx.canvas.height;\n                        const total = values.reduce((a, b) => a + b, 0) || 1;\n                        let x = 0;\n                        values.forEach((v, i) => {\n                                const width = (v / total) * w;\n                                ctx.fillStyle = i % 2 === 0 ? "#2e86de" : "#28b463";\n                                ctx.fillRect(x, 0, width, h);\n                                x += width;\n                        });\n                }\n\n                function drawWaterfall(ctx, labels, values) {\n                        const w = ctx.canvas.width;\n                        const h = ctx.canvas.height;\n                        const max = values.reduce((a, b) => a + b, 0) || 1;\n                        let cumulative = 0;\n                        const barWidth = w / values.length;\n                        values.forEach((v, i) => {\n                                const start = cumulative;\n                                cumulative += v;\n                                const y = h - (cumulative / max) * (h - 20);\n                                const barHeight = (v / max) * (h - 20);\n                                ctx.fillStyle = "#f39c12";\n                                ctx.fillRect(i * barWidth + 6, y, barWidth - 12, barHeight);\n                        });\n                }\n\n                function drawHeatmap(ctx, labels, values) {\n                        const w = ctx.canvas.width;\n                        const h = ctx.canvas.height;\n                        const max = Math.max(...values, 1);\n                        const cellWidth = w / values.length;\n                        values.forEach((v, i) => {\n                                const intensity = Math.min(1, v / max);\n                                ctx.fillStyle = `rgba(255, 69, 0, ${intensity})`;\n                                ctx.fillRect(i * cellWidth, 0, cellWidth - 2, h);\n                        });\n                }\n\n                function initCharts() {\n                        drawDonut(document.getElementById(\'severityChart\').getContext(\'2d\'),\n                                [{{ vuln_counts.critical }}, {{ vuln_counts.high }}, {{ vuln_counts.medium }}, {{ vuln_counts.low }}, {{ vuln_counts.info }}],\n                                [\'#FF0000\',\'#FF4500\',\'#FFA500\',\'#FFD700\',\'#00BFFF\']);\n                        drawBar(document.getElementById(\'cvssChart\').getContext(\'2d\'), charts.cvss_labels, charts.cvss_values, \'#2e86de\');\n                        drawBar(document.getElementById(\'portChart\').getContext(\'2d\'), charts.port_labels, charts.port_values, \'#2e86de\');\n                        drawRadar(document.getElementById(\'osChart\').getContext(\'2d\'), charts.os_labels, charts.os_values, \'#28b463\');\n                        drawBar(document.getElementById(\'serviceChart\').getContext(\'2d\'), charts.service_labels, charts.service_values, \'#2e86de\');\n                        drawWaterfall(document.getElementById(\'waterfallChart\').getContext(\'2d\'), charts.waterfall_labels, charts.waterfall_values);\n                        drawTreemap(document.getElementById(\'treemapChart\').getContext(\'2d\'), charts.treemap_labels, charts.treemap_values);\n                        drawRadar(document.getElementById(\'radarChart\').getContext(\'2d\'), charts.os_labels, charts.os_values, \'#2e86de\');\n                        drawHeatmap(document.getElementById(\'heatmapChart\').getContext(\'2d\'), charts.subnet_labels, charts.subnet_values);\n                }\n\n                document.addEventListener(\'DOMContentLoaded\', () => {\n                        document.querySelectorAll(\'.search\').forEach(input => {\n                                input.addEventListener(\'input\', () => filterTable(input));\n                        });\n\n                        document.querySelectorAll(\'table[data-sort] th\').forEach((th, idx) => {\n                                th.addEventListener(\'click\', () => sortTable(th.closest(\'table\'), idx));\n                        });\n\n                        document.querySelectorAll(\'.data-row\').forEach(row => {\n                                row.addEventListener(\'click\', () => {\n                                        const detailId = row.dataset.detail;\n                                        if (!detailId) return;\n                                        const detailRow = document.getElementById(detailId);\n                                        if (detailRow) {\n                                                detailRow.style.display = detailRow.style.display === \'table-row\' ? \'none\' : \'table-row\';\n                                        }\n                                });\n                        });\n\n                        initCharts();\n                });\n        </script>\n</body>\n</html>\n'
