"""Compare two scan JSON reports and output differences."""

import json
from rich.table import Table
from rich.console import Console

console = Console()


def parse_json_report(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    # Re-structure to indexed maps for easy diffing
    # Assuming result format contains 'devices' list
    devices = {}

    # If the JSON structure is a raw list of devices (from export_json)
    if isinstance(data, list):
        for dev in data:
            devices[dev.get("ip")] = dev
    elif "devices" in data:
        for dev in data["devices"]:
            devices[dev.get("ip")] = dev

    return devices


def compare_scans(path1: str, path2: str):
    """Run comparison and print rich table."""
    try:
        scan1 = parse_json_report(path1)
        scan2 = parse_json_report(path2)
    except Exception as e:
        console.print(f"[bold red]Failed to read reports: {e}[/]")
        return

    table = Table(title=f"Scan Diff: {path1} -> {path2}")
    table.add_column("Host IP", style="cyan")
    table.add_column("Status", style="bold")
    table.add_column("Details")

    all_ips = set(scan1.keys()).union(set(scan2.keys()))

    for ip in sorted(all_ips):
        if ip not in scan1:
            table.add_row(
                ip,
                "[green]NEW HOST[/]",
                f"Discovered {len(scan2[ip].get('open_ports', []))} ports",
            )
            continue
        if ip not in scan2:
            table.add_row(ip, "[red]MISSING[/]", "Host not seen in scan 2")
            continue

        # Host exists in both, check ports
        p1 = set(scan1[ip].get("open_ports", []))
        p2 = set(scan2[ip].get("open_ports", []))

        added_ports = p2 - p1
        removed_ports = p1 - p2

        if added_ports:
            table.add_row(ip, "[green]PORTS ADDED[/]", f"{list(added_ports)}")
        if removed_ports:
            table.add_row(ip, "[red]PORTS REMOVED[/]", f"{list(removed_ports)}")

        # Check vulns
        v1 = {
            v.get("cve_id")
            for v in scan1[ip].get("vulnerabilities", [])
            if v.get("cve_id")
        }
        v2 = {
            v.get("cve_id")
            for v in scan2[ip].get("vulnerabilities", [])
            if v.get("cve_id")
        }

        added_vulns = v2 - v1
        removed_vulns = v1 - v2

        if added_vulns:
            table.add_row(ip, "[bold red]VULN ADDED[/]", f"{list(added_vulns)}")
        if removed_vulns:
            table.add_row(ip, "[bold green]VULN FIXED[/]", f"{list(removed_vulns)}")

    if table.row_count == 0:
        console.print("[bold green]No differences found between scans.[/]")
    else:
        console.print(table)
