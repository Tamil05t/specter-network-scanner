"""Scheduled scans using apscheduler."""

import os
import json
from pathlib import Path
from apscheduler.schedulers.blocking import BlockingScheduler
from typing import Optional
from rich.console import Console

console = Console()

SCHEDULE_FILE = Path(os.path.expanduser("~/.specter/schedules.json"))


def run_scheduled_scan(target: str, **kwargs):
    """Callback function executed by the scheduler."""
    console.print(f"[bold green]Executing scheduled scan for target: {target}[/]")
    # In a full implementation, this would invoke the scan logic.
    # For now we invoke the shell command to run it isolated
    import subprocess

    cmd = ["specter", "scan", "-t", target]
    subprocess.Popen(cmd)


def add_schedule(
    schedule_type: str, time_str: str, target: str, day: Optional[str] = None, date: Optional[str] = None
):
    """Save configuration and block to run scheduler."""
    # Ensure dir exists
    SCHEDULE_FILE.parent.mkdir(parents=True, exist_ok=True)

    config = {
        "type": schedule_type,
        "time": time_str,
        "target": target,
        "day": day,
        "date": date,
    }

    # Save to disk
    schedules = []
    if SCHEDULE_FILE.exists():
        with open(SCHEDULE_FILE, "r") as f:
            try:
                schedules = json.load(f)
            except json.JSONDecodeError:
                pass
    schedules.append(config)
    with open(SCHEDULE_FILE, "w") as f:
        json.dump(schedules, f, indent=4)

    console.print(f"[bold blue]Schedule saved to {SCHEDULE_FILE}[/]")

    # Run blocking scheduler
    scheduler = BlockingScheduler()
    hour, minute = time_str.split(":")

    if schedule_type == "daily":
        scheduler.add_job(
            run_scheduled_scan, "cron", hour=hour, minute=minute, args=[target]
        )
    elif schedule_type == "weekly" and day:
        # apscheduler days: mon, tue, wed, thu, fri, sat, sun
        short_day = day[:3].lower()
        scheduler.add_job(
            run_scheduled_scan,
            "cron",
            day_of_week=short_day,
            hour=hour,
            minute=minute,
            args=[target],
        )
    elif schedule_type == "monthly" and date:
        scheduler.add_job(
            run_scheduled_scan,
            "cron",
            day=date,
            hour=hour,
            minute=minute,
            args=[target],
        )

    console.print("[bold yellow]Starting blocking scheduler. Press Ctrl+C to exit.[/]")
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        pass
