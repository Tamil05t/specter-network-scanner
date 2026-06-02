$ErrorActionPreference = "Stop"

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
  Write-Host "Python 3 is required."
  exit 1
}

if (-not (Get-Command pip -ErrorAction SilentlyContinue)) {
  Write-Host "pip is required."
  exit 1
}

python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt

Write-Host "Add API keys in .env (never hardcode) if needed."
Write-Host "Installation complete. Activate with: .\.venv\Scripts\Activate.ps1"
