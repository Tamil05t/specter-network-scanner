#!/usr/bin/env sh
set -e

if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 is required."
  exit 1
fi

if ! command -v pip3 >/dev/null 2>&1; then
  echo "pip is required."
  exit 1
fi

if ! command -v nmap >/dev/null 2>&1; then
  echo "nmap not found. Install nmap for enhanced scanning."
fi

if ! command -v tcpdump >/dev/null 2>&1; then
  echo "tcpdump not found. libpcap tools recommended."
fi

python3 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

echo "Add API keys in .env (never hardcode) if needed."
echo "Installation complete. Activate with: . .venv/bin/activate"
