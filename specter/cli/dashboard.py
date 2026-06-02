"""Live reporting dashboard for Specter Network Scanner."""

from datetime import datetime, timedelta
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.align import Align
from specter.models.dataclasses import Vulnerability


class DashboardRenderer:
    """Manages the rich.layout rendering for the live dashboard."""

    def __init__(self, targets_total: int):
        self.targets_total = targets_total
        self.hosts_discovered = 0
        self.ports_scanned = 0
        self.start_time = datetime.now()

        self.severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        self.latest_findings: list = []

    def generate_layout(self) -> Layout:
        """Create the overall dashboard layout."""
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=3),
        )

        layout["main"].split_row(
            Layout(name="stats", ratio=1), Layout(name="findings", ratio=2)
        )

        self._update_panels(layout)
        return layout

    def update_stats(self, hosts: int, ports: int):
        """Update active scan statistics."""
        self.hosts_discovered = hosts
        self.ports_scanned = ports

    def add_finding(self, finding: Vulnerability, host: str):
        """Add a new finding to the dashboard."""
        self.severity_counts[finding.severity] += 1

        color_map = {
            "critical": "[bold red]",
            "high": "[bold orange3]",
            "medium": "[bold yellow]",
            "low": "[bold blue]",
            "info": "[bold white]",
        }

        color = color_map.get(finding.severity, "[bold white]")
        entry = f"{color}{finding.severity.upper()}[/] | [cyan]{host}[/] | {finding.cve_id}: {finding.description[:60]}"

        self.latest_findings.insert(0, entry)
        if len(self.latest_findings) > 15:
            self.latest_findings = self.latest_findings[:15]

    def _update_panels(self, layout: Layout):
        """Fill layout segments with updated renderables."""

        # Header
        elapsed = datetime.now() - self.start_time
        elapsed_str = str(timedelta(seconds=int(elapsed.total_seconds())))
        header_text = Text(
            f"Specter Network Scanner | Elapsed: {elapsed_str} | Target Size: {self.targets_total}",
            justify="center",
            style="bold green",
        )
        layout["header"].update(Panel(header_text, style="green"))

        # Stats Grid
        stats_table = Table.grid(padding=(1, 2))
        stats_table.add_column("Metric", style="cyan", justify="right")
        stats_table.add_column("Value", style="white")

        stats_table.add_row("Hosts Discovered", str(self.hosts_discovered))
        stats_table.add_row("Ports Scanned", str(self.ports_scanned))
        stats_table.add_row("", "")
        stats_table.add_row("[red]Critical", str(self.severity_counts["critical"]))
        stats_table.add_row("[orange3]High", str(self.severity_counts["high"]))
        stats_table.add_row("[yellow]Medium", str(self.severity_counts["medium"]))
        stats_table.add_row("[blue]Low", str(self.severity_counts["low"]))

        layout["stats"].update(
            Panel(
                Align.center(stats_table, vertical="middle"),
                title="Scan Progress",
                border_style="cyan",
            )
        )

        # Findings Log
        findings_text = (
            "\\n".join(self.latest_findings)
            if self.latest_findings
            else "[dim]Waiting for findings...[/dim]"
        )
        layout["findings"].update(
            Panel(findings_text, title="Latest Vulnerabilities", border_style="red")
        )

        # Footer
        footer_text = Text(
            "Press Ctrl+C to abort scan safely and save state.",
            justify="center",
            style="dim white",
        )
        layout["footer"].update(Panel(footer_text, style="dim"))
