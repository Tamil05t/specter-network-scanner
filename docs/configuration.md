# Configuration

The configuration is stored in config.yaml.

## Top-Level Keys

- specter
- scan_defaults
- profiles
- exploit_db
- output
- safety

## Example

```yaml
specter:
  version: "1.0.0"
scan_defaults:
  ports: "1-1000,443"
  timeout: 2000
  syn_scan: false
  decoy_count: 3
## Scan Profile Flags

- scan_delay: Delay between probes in milliseconds.
- randomize_ports: Randomize port order.
- fragment_packets: Fragment probes to evade filters.
- decoy_scan: Send decoy packets where supported.
- syn_scan: Attempt TCP SYN probes when raw sockets are available.
```
