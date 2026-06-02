"""Console reporting with rich (placeholder)."""

from __future__ import annotations

from rich.console import Console

from specter.models.dataclasses import ScanResult


def print_summary(result: ScanResult) -> None:
    """Print a console summary for scan results.

    Args:
        result (ScanResult): Scan results to summarize.

    Returns:
        None: Prints to console.

    Raises:
        Exception: Printing errors are suppressed.

    Example:
        >>> print_summary(result)

    Note:
        Uses rich for colored output when available.
    """
    console = Console()
    console.print(f"Devices: {len(result.devices)}")
    console.print(f"Duration: {result.scan_duration:.2f}s")
    console.print(f"Packets: {result.packets_sent}")
