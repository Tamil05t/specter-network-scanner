# Installation

## Linux/macOS

```bash
./install.sh
```

Verify dependencies:
- Python 3.11+
- nmap (optional)
- libpcap/tcpdump (optional)

## Windows

```powershell
.\install.ps1
```

## Docker

```bash
docker build -t specter .
docker run --rm --network host specter scan -t 127.0.0.1
```
