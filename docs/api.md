# API Reference

Specter can be used as a library. The main entry point is `ScannerEngine`.

```python
from specter.core.engine import EngineConfig, ScannerEngine

engine = ScannerEngine(EngineConfig(concurrency=100, rate_limit=200))
result = await engine.run(["127.0.0.1"])
await engine.close()
```

## Core Engine

### EngineConfig

Configuration for the runtime engine.

- `concurrency` (int): Max concurrent tasks.
- `rate_limit` (float): Tokens per second.
- `bucket_capacity` (int): Token bucket size.
- `request_timeout` (float): HTTP timeout in seconds.
- `scan_ports` (List[int] | None): Ports to scan (defaults apply if None).
- `thread_workers` (int): Thread pool size for blocking work.
- `scan_delay` (float): Delay between probes in seconds.
- `randomize_ports` (bool): Randomize port scan order.
- `syn_scan` (bool): Enable SYN probes with raw sockets.
- `decoy_scan` (bool): Send decoy packets where supported.
- `decoy_count` (int): Number of decoy packets.
- `fragment_packets` (bool): Fragment raw packets where supported.
- `fragment_size` (int): Fragment size in bytes.

### ScannerEngine

Orchestrates discovery, scanning, and fingerprinting.

Methods:

- `run(targets: Iterable[str]) -> ScanResult`
  Runs the full workflow and returns a `ScanResult`.
- `close() -> None`
  Shuts down internal executors and resources.

Example:

```python
from specter.core.engine import EngineConfig, ScannerEngine

engine = ScannerEngine(EngineConfig())
try:
	result = await engine.run(["192.168.1.0/24"])
finally:
	await engine.close()
```

## Scanners

### PortScanner

Asynchronous TCP/UDP scanner with banner grabbing.

Methods:

- `scan_tcp_ports(target: str, ports: Sequence[int]) -> List[Service]`
- `scan_udp_ports(target: str, ports: Sequence[int]) -> List[Service]`
- `grab_banner(ip: str, port: int, protocol: str = "tcp") -> str`
- `detect_service(ip: str, port: int, banner: str) -> Service`
- `scan_device(device: Device, ports: Iterable[int]) -> Device`
- `pause() -> None`
- `resume() -> None`

Example:

```python
from specter.scanners.port_scanner import PortScanner

scanner = PortScanner(concurrency=50)
services = await scanner.scan_tcp_ports("127.0.0.1", [22, 80, 443])
```

### NetworkMapper

Discovery and OS fingerprinting.

Key methods:

- `discover(targets: Iterable[str], rate_limiter: RateLimiter) -> List[Device]`
- `arp_scan(network_range: str) -> List[Device]`
- `icmp_ping_sweep(network_range: str) -> List[Device]`
- `tcp_ping_sweep(network_range: str, ports: Optional[Sequence[int]]) -> List[Device]`
- `udp_discovery(network_range: str) -> List[Device]`
- `mdns_discovery() -> List[Device]`
- `ssdp_discovery() -> List[Device]`
- `netbios_discovery() -> List[Device]`
- `passive_fingerprint(metadata: Dict[str, str]) -> FingerprintData`
- `active_fingerprint(ip: str) -> FingerprintData`
- `classify_device(device: Device, fingerprints: Optional[FingerprintData]) -> Tuple[str, OSGuess]`
- `build_topology(devices: List[Device]) -> Dict[str, List[str]]`
- `generate_network_map(devices: List[Device], output_path: str) -> None`
- `export_gexf(devices: List[Device], output_path: str) -> None`
- `export_json(devices: List[Device], output_path: str) -> None`
- `detect_honeypot(device: Device) -> Optional[str]`
- `detect_virtualization(mac: Optional[str]) -> Optional[str]`
- `wake_on_lan(mac: str, broadcast_ip: str = "255.255.255.255", port: int = 9) -> None`
- `detect_vlan_segments(devices: List[Device]) -> List[str]`
- `detect_nat_boundaries(devices: List[Device]) -> List[str]`
- `traceroute(ip: str) -> List[Tuple[str, float]]`

### VulnerabilityFingerprinter

Lightweight HTTP header checks.

- `fingerprint(device: Device, session: aiohttp.ClientSession, rate_limiter: RateLimiter) -> Device`

### RouterExplorer

Router discovery, fingerprinting, and checks.

Methods:

- `explore(device: Device, session: aiohttp.ClientSession, rate_limiter: RateLimiter) -> Device`
- `discover_gateway() -> Optional[str]`
- `upnp_discover() -> List[Dict[str, str]]`
- `detect_admin_panels(ip: str, session: aiohttp.ClientSession, rate_limiter: RateLimiter) -> List[str]`
- `grab_router_fingerprint(ip: str, port: int, session: aiohttp.ClientSession) -> RouterFingerprint`
- `test_default_credentials(ip: str, vendor: str, session: aiohttp.ClientSession, rate_limiter: RateLimiter) -> Optional[Tuple[str, str]]`
- `router_vuln_checks(ip: str, session: aiohttp.ClientSession, rate_limiter: RateLimiter) -> List[Vulnerability]`

## Correlation

### ExploitCorrelator

Correlates services and vulnerabilities with Exploit-DB data.

Methods:

- `load_exploit_db() -> None`
- `correlate_service(service: Service) -> List[ExploitMatch]`
- `correlate_vulnerability(vuln: Vulnerability) -> List[ExploitMatch]`
- `batch_correlate(scan_results: ScanResult) -> CorrelatedResult`
- `calculate_confidence(service: Service, exploit: ExploitRecord) -> float`
- `fetch_nvd_cve(cve_id: str) -> Optional[dict]`

Example:

```python
from specter.correlation.engine import ExploitCorrelator
from specter.models.dataclasses import Service

correlator = ExploitCorrelator()
await correlator.load_exploit_db()
matches = await correlator.correlate_service(Service(port=80, protocol="tcp", service_name="http"))
```

## Reporting

HTML and export utilities are in `specter.reporting.html_report`.

- `generate_html_report(result: ScanResult, output_path: str) -> None`
- `export_json(result: ScanResult, output_path: str) -> None`
- `export_csv(result: ScanResult, output_path: str) -> None`
- `export_markdown_summary(result: ScanResult, output_path: str) -> None`
- `export_siem_json(result: ScanResult, output_path: str) -> None`
- `generate_sample_data() -> ScanResult`
- `risk_score(device: Device, exposed_admin: int = 0) -> float`

Example:

```python
from specter.reporting.html_report import generate_html_report, generate_sample_data

result = generate_sample_data()
generate_html_report(result, "report.html")
```

## Data Models

Common dataclasses live in `specter.models.dataclasses`:

- `Device`
- `Service`
- `Vulnerability`
- `ScanResult`

## CLI Integration

If you want to run the scanner programmatically with the CLI configuration:

```python
from main import ScanConfig, SpecterScanner, load_config

config = load_config("config.yaml")
scan_config = ScanConfig(
	targets=["127.0.0.1"],
	ports=[22, 80, 443],
	profile="standard",
	output_dir="./reports",
	output_format="html",
	router_scan=False,
	exploit_lookup=False,
	os_detect=False,
	stealth=False,
	rate_limit=100,
	timeout_ms=2000,
	concurrency=100,
	exclude=[],
	resume=None,
	config_path="config.yaml",
	debug=False,
	verbose=0,
)

scanner = SpecterScanner(config, scan_config)
await scanner.initialize()
try:
	result = await scanner.run_scan(scan_config)
	await scanner.generate_reports(result)
finally:
	await scanner.cleanup()
```
