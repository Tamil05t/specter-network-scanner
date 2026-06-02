"""Webhook notification sender."""

import requests
import asyncio
from rich.console import Console
from typing import Optional

console = Console()


async def send_webhook_alert(url: str, event_type: str, scan_result: Optional[dict] = None):
    """Send an async webhook notification."""
    if not url:
        return

    payload = {
        "event": event_type,
        "message": f"Specter Scan: {event_type.upper()}",
        "details": scan_result or {},
    }

    def _post():
        try:
            resp = requests.post(url, json=payload, timeout=5)
            resp.raise_for_status()
            console.print(f"[dim green]Webhook alert sent to {url}[/]")
        except Exception as e:
            console.print(f"[dim red]Failed to send webhook: {e}[/]")

    # Run requests synchronously in an async thread pool
    await asyncio.to_thread(_post)
