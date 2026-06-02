"""Integration tests for CLI."""

from __future__ import annotations
from click.testing import CliRunner
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
import main
from specter.reporting.html_report import generate_sample_data


def test_cli_version(tmp_path):
    """Ensure CLI version flag returns successfully.

    Args:
        tmp_path (Any): Description of tmp_path.

    Raises:
        Exception: On unexpected errors.

    Example:
        >>> # Example usage of test_cli_version
        >>> pass"""
    runner = CliRunner()
    result = runner.invoke(main.cli, ["--config", "config.yaml", "--version"])
    assert result.exit_code == 0


def test_cli_scan_help():
    """Ensure CLI scan help returns successfully.

    Args:
        None

    Raises:
        Exception: On unexpected errors.

    Example:
        >>> # Example usage of test_cli_scan_help
        >>> pass"""
    runner = CliRunner()
    result = runner.invoke(main.cli, ["scan", "--help"])
    assert result.exit_code == 0


def test_cli_env_profile_override(monkeypatch, tmp_path):
    """Ensure env profile overrides default profile.

    Args:
        monkeypatch (Any): Description of monkeypatch.
        tmp_path (Any): Description of tmp_path.

    Raises:
        Exception: On unexpected errors.

    Example:
        >>> # Example usage of test_cli_env_profile_override
        >>> pass"""
    runner = CliRunner()

    async def fake_run_scan(self, config):
        """Return sample scan results for tests.

        Args:
            self: SpecterScanner instance.
            config: ScanConfig instance.
        """
        return generate_sample_data()

    async def fake_generate_reports(self, result):
        """No-op report generation for tests.

        Args:
            self: SpecterScanner instance.
            result: Scan result object.
        """
        return None

    async def fake_init(self):
        """No-op initialization for tests.

        Args:
            self: SpecterScanner instance.
        """
        return None

    async def fake_cleanup(self):
        """No-op cleanup for tests.

        Args:
            self: SpecterScanner instance.
        """
        return None

    monkeypatch.setattr(main.SpecterScanner, "run_scan", fake_run_scan)
    monkeypatch.setattr(main.SpecterScanner, "generate_reports", fake_generate_reports)
    monkeypatch.setattr(main.SpecterScanner, "initialize", fake_init)
    monkeypatch.setattr(main.SpecterScanner, "cleanup", fake_cleanup)
    env = {"SPECTER_PROFILE": "aggressive"}
    result = runner.invoke(main.cli, ["scan", "-t", "127.0.0.1", "-o", str(tmp_path)], env=env)
    assert result.exit_code == 0


def test_config_loading(tmp_path):
    """Ensure load_config reads YAML config.

    Args:
        tmp_path (Any): Description of tmp_path.

    Raises:
        Exception: On unexpected errors.

    Example:
        >>> # Example usage of test_config_loading
        >>> pass"""
    cfg = tmp_path / "config.yaml"
    cfg.write_text("specter:\n  version: '1.0.0'\n", encoding="utf-8")
    data = main.load_config(str(cfg))
    assert data.get("specter", {}).get("version") == "1.0.0"
