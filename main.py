"""Entry point and CLI for Specter Network Scanner."""
from __future__ import annotations
import asyncio
import contextlib
import json
import logging
import os
import pickle
import subprocess
import sys
import time
from dataclasses import dataclass
from logging.handlers import RotatingFileHandler
from typing import Any, Dict, Iterable, List, Optional
import ipaddress
import rich_click as click
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.traceback import install

from specter.core.engine import EngineConfig, ScannerEngine, install_uvloop
from specter.reporting.console import print_summary
from specter.reporting.html_report import export_csv, export_json, export_markdown_summary, generate_html_report

# --- New Modules ---
from specter.cli.dashboard import DashboardRenderer
from rich.live import Live
from specter.reporting.webhooks import send_webhook_alert

install(show_locals=False)
console = Console()

# Bonus: Beautiful Error Handling
def beautiful_excepthook(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, (KeyboardInterrupt, asyncio.CancelledError)):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    panel = Panel(
        f"[white]{str(exc_value)}[/]\\n\\n[dim]Try running with elevated privileges or check your config.[/dim]\\n[blue underline]https://docs.specter-scanner.com/errors[/]",
        title=f"[bold red]Critical Error: {exc_type.__name__}[/]",
        border_style="red"
    )
    console.print(panel)
sys.excepthook = beautiful_excepthook

@dataclass
class ScanConfig:
    targets: List[str]
    ports: List[int]
    profile: str
    output_dir: str
    output_format: str
    router_scan: bool
    exploit_lookup: bool
    os_detect: bool
    stealth: bool
    rate_limit: int
    timeout_ms: int
    concurrency: int
    scan_delay: float
    randomize_ports: bool
    fragment_packets: bool
    decoy_scan: bool
    decoy_count: int
    syn_scan: bool
    exclude: List[str]
    resume: Optional[str]
    config_path: str
    debug: bool
    verbose: int
    webhook: Optional[str] = None
    on_critical: bool = False
    on_complete: bool = False

class SpecterScanner:
    def __init__(self, config: Dict[str, Any], scan_config: ScanConfig) -> None:
        self._config = config
        self._scan_config = scan_config
        self._engine: Optional[ScannerEngine] = None
        self._state_path = os.path.join(scan_config.output_dir, 'specter_state.pkl')
        self._last_state_save = 0.0
        self._autosave_task: Optional[asyncio.Task[None]] = None
        
        self.dashboard = DashboardRenderer(len(scan_config.targets))

    async def initialize(self) -> None:
        install_uvloop()
        os.makedirs(self._scan_config.output_dir, exist_ok=True)
        self._setup_logging()
        await self._dependency_check()

    async def run_scan(self, config: ScanConfig) -> Any:
        engine_config = EngineConfig(
            concurrency=config.concurrency, rate_limit=config.rate_limit, 
            request_timeout=config.timeout_ms / 1000, scan_delay=config.scan_delay, 
            randomize_ports=config.randomize_ports, syn_scan=config.syn_scan, 
            decoy_scan=config.decoy_scan, decoy_count=config.decoy_count, 
            fragment_packets=config.fragment_packets
        )
        self._engine = ScannerEngine(engine_config)
        
        print("DEBUG: Before scanner._engine.run()")
        with Live(self.dashboard.generate_layout(), refresh_per_second=2, console=console) as live:
            # Launch dashboard mock updater as a background task so it doesn't block the engine
            async def ui_updater():
                try:
                    while True:
                        await asyncio.sleep(0.5)
                        devices = getattr(self._engine, 'current_devices', [])
                        hosts = len(devices)
                        
                        ports = 0
                        for d in devices:
                            if hasattr(d, 'open_ports') and d.open_ports:
                                ports += len(d.open_ports)
                            elif hasattr(d, 'services') and d.services:
                                ports += len(d.services)
                                
                        self.dashboard.update_stats(hosts, ports)
                        live.update(self.dashboard.generate_layout())
                except asyncio.CancelledError:
                    pass

            ui_task = asyncio.create_task(ui_updater())
            
            try:
                result = await self._engine.run(config.targets)
            except asyncio.CancelledError:
                pass  # Normal shutdown
                result = None
            finally:
                ui_task.cancel()
                
        if result:
            print(f"DEBUG: After scanner.run_scan() - result.devices count: {len(result.devices)}")
            svc_count = sum(len(d.services) for d in result.devices) if result.devices and hasattr(result.devices[0], 'services') else 0
            print(f"DEBUG: Found {svc_count} services")
            
        if self._scan_config.on_complete and self._scan_config.webhook:
            await send_webhook_alert(self._scan_config.webhook, "complete")
            
        return result

    async def generate_reports(self, result: Any) -> None:
        output_dir = self._scan_config.output_dir
        if self._scan_config.output_format in {'html', 'all'}:
            generate_html_report(result, os.path.join(output_dir, 'report.html'))
        if self._scan_config.output_format in {'json', 'all'}:
            await export_json(result, os.path.join(output_dir, 'report.json'))
        if self._scan_config.output_format in {'csv', 'all'}:
            await export_csv(result, os.path.join(output_dir, 'report.csv'))
        await export_markdown_summary(result, os.path.join(output_dir, 'summary.md'))

    async def cleanup(self) -> None:
        if self._autosave_task:
            self._autosave_task.cancel()
            try:
                await self._autosave_task
            except asyncio.CancelledError:
                pass  # Expected during shutdown
        if self._engine:
            await self._engine.close()

    def save_state(self, result: Optional[Any]=None) -> None:
        state = {'timestamp': time.time(), 'config': self._scan_config.__dict__, 'result': result}
        try:
            with open(self._state_path, 'wb') as handle:
                pickle.dump(state, handle)
        except Exception:
            with open(self._state_path.replace('.pkl', '.json'), 'w', encoding='utf-8') as handle:
                json.dump(state, handle, default=str)

    async def resume_from_state(self, state_file: str) -> Any:
        try:
            with open(state_file, 'rb') as handle:
                return pickle.load(handle)
        except Exception:
            with open(state_file.replace('.pkl', '.json'), 'r', encoding='utf-8') as handle:
                return json.load(handle)

    async def _dependency_check(self) -> None:
        if sys.version_info < (3, 9):
            raise RuntimeError('Python 3.9+ is required')
        if self._scan_config.os_detect and os.name != 'nt':
            if hasattr(os, 'geteuid') and os.geteuid() != 0:
                console.print('[yellow]OS detection may require sudo/root[/yellow]')

    def _setup_logging(self) -> None:
        log_dir = os.path.join(self._scan_config.output_dir, 'logs')
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(log_dir, 'specter.log')
        handler = RotatingFileHandler(log_path, maxBytes=10 * 1024 * 1024, backupCount=5)
        logging.basicConfig(level=logging.DEBUG if self._scan_config.debug else logging.INFO, handlers=[handler], format='%(asctime)s %(levelname)s %(message)s')

    async def start_autosave(self) -> None:
        async def autosave_loop() -> None:
            while True:
                try:
                    await asyncio.sleep(30)
                except asyncio.CancelledError:
                    return  # Exit cleanly
                self.save_state()
        self._autosave_task = asyncio.create_task(autosave_loop())

def load_config(path: str) -> Dict[str, Any]:
    with open(path, 'r', encoding='utf-8') as handle:
        return yaml.safe_load(handle) or {}

def apply_profile(config: Dict[str, Any], profile: str) -> Dict[str, Any]:
    profile_cfg = config.get('profiles', {}).get(profile, {})
    merged = dict(config.get('scan_defaults', {}))
    merged.update(profile_cfg)
    return merged

def parse_ports(value: str) -> List[int]:
    ports: List[int] = []
    for part in value.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            start, end = part.split('-', 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))

def filter_targets(targets: List[str], exclude: List[str]) -> List[str]:
    excluded = set((t.strip() for t in exclude if t.strip()))
    return [t for t in targets if t not in excluded]

def estimate_target_count(targets: Iterable[str]) -> int:
    count = 0
    for target in targets:
        try:
            if '/' in target:
                count += ipaddress.ip_network(target, strict=False).num_addresses
            else:
                count += 1
        except Exception:
            count += 1
    return count

@click.group(invoke_without_command=True)
@click.option('--config', default='config.yaml', help='Custom config file path')
@click.option('--debug', is_flag=True, help='Enable debug logging')
@click.option('--no-color', is_flag=True, help='Disable colored output')
@click.option('-v', '--verbose', count=True, help='Increase verbosity')
@click.option('--version', is_flag=True, help='Show version and exit')
def cli(config: str, debug: bool, no_color: bool, verbose: int, version: bool) -> None:
    """Root CLI entry point for Specter."""
    global console
    if no_color:
        click.rich_click.COLOR_SYSTEM = None
        console = Console(color_system=None, force_terminal=False)
    if version:
        try:
            cfg = load_config(config)
        except Exception:
            cfg = {}
        console.print(cfg.get('specter', {}).get('version', '0.0.0'))
        raise SystemExit(0)

# --- Feature 3: Scan Diff Command ---
@cli.command("diff")
@click.argument("scan1_json")
@click.argument("scan2_json")
def diff_cmd(scan1_json: str, scan2_json: str):
    """Compare two scan JSON files."""
    from specter.cli.diff import compare_scans
    compare_scans(scan1_json, scan2_json)

@cli.command()
@click.option('-t', '--target', required=False, help='Target IP, range, or CIDR')
@click.option('-p', '--ports', default=None, help='Port range (e.g., 1-1000,22,80,443)')
@click.option('--profile', default='standard', help='Scan profile')
@click.option('-o', '--output', default='./reports', help='Output directory')
@click.option('--format', 'output_format', type=click.Choice(['json', 'csv', 'html', 'all']), default='html')
@click.option('--router-scan', is_flag=True, help='Enable router vulnerability testing')
@click.option('--exploit-lookup', is_flag=True, help='Enable Exploit-DB correlation')
@click.option('--os-detect', is_flag=True, help='Enable OS fingerprinting')
@click.option('--stealth', is_flag=True, help='Enable stealth scanning techniques')
@click.option('--rate-limit', default=100, type=int, help='Max packets per second')
@click.option('--timeout', 'timeout_ms', default=2000, type=int, help='Timeout per probe in ms')
@click.option('--concurrency', default=100, type=int, help='Max concurrent tasks')
@click.option('--exclude', default='', help='IPs to exclude (comma-separated)')
@click.option('--resume', default=None, help='Resume from saved state file')
@click.option('--config', 'config_path', default='config.yaml', help='Custom config file path')
@click.option('--debug', is_flag=True, help='Enable debug logging')
@click.option('-v', '--verbose', count=True, help='Increase verbosity (-v, -vv, -vvv)')

@click.option('--schedule', type=click.Choice(['daily', 'weekly', 'monthly']), help='Schedule a scan')
@click.option('--time', 'schedule_time', default='00:00', help='Time to schedule (HH:MM)')
@click.option('--day', default=None, help='Day of the week for weekly schedule')
@click.option('--date', default=None, help='Day of the month for monthly schedule')
@click.option('--webhook', default=None, help='Webhook URL to alert')
@click.option('--on-critical', is_flag=True, help='Alert webhook on critical findings')
@click.option('--on-complete', is_flag=True, help='Alert webhook on scan complete')
def scan(target: Optional[str], ports: Optional[str], profile: str, output: str, output_format: str, 
         router_scan: bool, exploit_lookup: bool, os_detect: bool, stealth: bool, rate_limit: int, 
         timeout_ms: int, concurrency: int, exclude: str, resume: Optional[str], config_path: str, 
         debug: bool, verbose: int, schedule: str, schedule_time: str, day: str, 
         date: str, webhook: str, on_critical: bool, on_complete: bool) -> None:
    
    if not target:
        console.print("[red]Missing target. Provide --target[/]")
        return
        
    # Feature 4: Scheduled Scans
    if schedule:
        from specter.cli.scheduler import add_schedule
        add_schedule(schedule, schedule_time, target, day, date)
        return
        
    config = load_config(config_path)
    profile_cfg = apply_profile(config, profile)
    port_spec = ports or profile_cfg.get('ports') or config.get('scan_defaults', {}).get('ports', '1-1000')
    port_list = parse_ports(port_spec)
    targets = filter_targets([target], exclude.split(','))
    
    scan_config = ScanConfig(
        targets=targets, ports=port_list, profile=profile, output_dir=output, 
        output_format=output_format, router_scan=router_scan, exploit_lookup=exploit_lookup, 
        os_detect=os_detect, stealth=stealth, rate_limit=rate_limit, timeout_ms=timeout_ms, 
        concurrency=concurrency, scan_delay=0, randomize_ports=True, fragment_packets=False, 
        decoy_scan=False, decoy_count=3, syn_scan=False, exclude=[], resume=resume, 
        config_path=config_path, debug=debug, verbose=verbose,
        webhook=webhook, on_critical=on_critical, on_complete=on_complete
    )

    async def runner() -> None:
        scanner = SpecterScanner(config, scan_config)
        await scanner.initialize()
        try:
            await scanner.start_autosave()
            if scan_config.resume:
                await scanner.resume_from_state(scan_config.resume)
            result = await scanner.run_scan(scan_config)
            scanner.save_state(result)
            await scanner.generate_reports(result)
            print_summary(result)
        except Exception as exc:
            # Let beautiful_excepthook catch this if it leaks out
            scanner.save_state()
            raise
        finally:
            await scanner.cleanup()
            
    asyncio.run(runner())

if __name__ == '__main__':
    cli()