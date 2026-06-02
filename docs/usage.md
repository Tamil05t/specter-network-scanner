# Usage

## CLI Reference

```
python main.py scan [OPTIONS] -t TARGET

Options:
  -t, --target TEXT            Target IP, range, or CIDR [required]
  -p, --ports TEXT             Port range (e.g., 1-1000,22,80,443)
  --profile TEXT               Scan profile: stealth|standard|aggressive|comprehensive
  -o, --output PATH            Output directory for reports
  --format [json|csv|html|all] Report format
  --router-scan                Enable router vulnerability testing
  --exploit-lookup             Enable Exploit-DB correlation
  --os-detect                  Enable OS fingerprinting
  --stealth                    Enable stealth scanning techniques
  --rate-limit INTEGER         Max packets per second (default: 100)
  --timeout INTEGER            Timeout per probe in ms (default: 2000)
  --concurrency INTEGER        Max concurrent tasks (default: 100)
  --exclude TEXT               IPs to exclude (comma-separated)
  --resume PATH                Resume from saved state file
  --config PATH                Custom config file path
  --debug                      Enable debug logging
  --no-color                   Disable colored output
  -v, --verbose                Increase verbosity (-v, -vv, -vvv)
  --version                    Show version and exit
```
