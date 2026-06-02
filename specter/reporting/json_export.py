"""JSON export utilities (placeholder)."""

from __future__ import annotations

import json
from dataclasses import asdict

from specter.models.dataclasses import ScanResult


def export_json(result: ScanResult, output_path: str) -> None:
    """Export scan results to JSON.

    Args:
        result (ScanResult): Scan results to export.
        output_path (str): Destination JSON path.

    Returns:
        None: Writes JSON to disk.

    Raises:
        OSError: If the file cannot be written.

    Example:
        >>> export_json(result, "report.json")

    Note:
        Uses dataclass serialization for output.
    """
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(asdict(result), handle, indent=2, default=str)
