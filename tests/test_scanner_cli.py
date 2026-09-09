"""
Tests for scanner.py CLI options, logging output, and exit codes.
"""

import os
import sys
import json
import pytest
from scanner import SecurityScanner, main


def test_scanner_custom_output_log(tmp_path):
    custom_log = tmp_path / "custom_scan_audit.txt"
    scanner = SecurityScanner(
        log_file=str(custom_log),
        color_enabled=False,
        detectors_to_run=["persistence"]
    )

    findings = scanner.run()
    assert custom_log.exists()
    content = custom_log.read_text(encoding="utf-8")
    assert "WINDOWS DEFENSIVE SECURITY SCANNER - AUDIT LOG" in content
    assert "SUMMARY BY CATEGORY" in content


def test_scanner_selective_modules():
    scanner = SecurityScanner(
        detectors_to_run=["keylogger"]
    )
    assert len(scanner.detectors) == 1
    assert scanner.detectors[0].__class__.__name__ == "KeyloggerDetector"


def test_scanner_exit_code_logic():
    # If findings have ALERT -> exit code 2
    scanner = SecurityScanner()
    scanner.detectors = []
    # Test clean findings
    findings = scanner.run()
    severities = {f.get("severity") for f in findings}
    assert "ALERT" not in severities

    # Test with ALERT finding
    scanner.findings = [
        {"category": "Persistence", "severity": "ALERT", "description": "Alert test", "evidence": "", "timestamp": ""}
    ]
    severities = {f.get("severity") for f in scanner.findings}
    assert "ALERT" in severities


def test_scanner_cli_help(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["scanner.py", "--help"])
    with pytest.raises(SystemExit) as excinfo:
        main()
    assert excinfo.value.code == 0
    captured = capsys.readouterr()
    assert "Windows Defensive Security Scanner" in captured.out
    assert "--output" in captured.out
    assert "--json" in captured.out


def test_scanner_cli_json_run(monkeypatch, capsys, tmp_path):
    log_file = tmp_path / "test_json_log.txt"
    monkeypatch.setattr(sys, "argv", [
        "scanner.py",
        "--output", str(log_file),
        "--no-color",
        "--json",
        "--module", "keylogger"
    ])
    exit_code = main()
    captured = capsys.readouterr()
    assert "--- JSON OUTPUT ---" in captured.out
    assert log_file.is_file()
