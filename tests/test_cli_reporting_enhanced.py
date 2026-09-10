"""
Unit and Integration Tests for CLI and Reporting (Phase 7).

Verifies:
1. Human-readable report formatting conforming to required summary structure:
   - Host, Scan type, Duration
   - CRITICAL, HIGH, MEDIUM, LOW breakdown
   - Finding details: Finding ID, Rule ID, Severity, Confidence, Risk score, Description, Evidence, Recommendation
2. Clean machine-readable JSON output mode:
   - Suppresses human-readable banners, progress logs, and summary tables from stdout.
   - Outputs machine-readable JSON array.
3. Consistent ISO-8601 UTC timestamps across all findings.
4. Scriptable exit codes (0 for clean, 1 for WARN, 2 for ALERT/CRITICAL).
"""

import sys
import json
import pytest
from scanner import SecurityScanner, main
from detectors.base_detector import BaseDetector
from detectors.finding import Finding


def test_human_readable_report_format(capsys, tmp_path):
    """Verify human-readable summary output structure matches required format."""
    log_file = tmp_path / "summary_test_log.txt"
    scanner = SecurityScanner(
        log_file=str(log_file),
        color_enabled=False,
        detectors_to_run=["persistence"]
    )
    scanner.detectors = []

    # Inject mock findings with all severities
    scanner.findings = [
        Finding(
            category="Credential Theft",
            severity="CRITICAL",
            description="Active Mimikatz execution",
            evidence="PID: 100",
            rule_id="RULE-CRED-TOOL",
            confidence=0.98,
            risk_score=95,
            recommendation="Isolate endpoint immediately"
        ),
        Finding(
            category="Process Spoofing / AV Evasion",
            severity="ALERT",
            description="Process masquerading as svchost",
            evidence="PID: 200",
            rule_id="RULE-PROC-MASQUERADE",
            confidence=0.90,
            risk_score=85,
            recommendation="Terminate process"
        ),
        Finding(
            category="Persistence",
            severity="WARN",
            description="Unquoted path with spaces",
            evidence="Path: C:\\Program Files\\App\\svc.exe",
            rule_id="RULE-PERSIST-RUN-UNQUOTED",
            confidence=0.55,
            risk_score=35,
            recommendation="Quote executable path"
        ),
        Finding(
            category="General",
            severity="INFO",
            description="Informational event",
            evidence="Boot time",
            rule_id="RULE-INFO",
            confidence=0.30,
            risk_score=10,
            recommendation="No action required"
        ),
    ]

    scanner.render_report(duration=1.23)
    captured = capsys.readouterr()
    output = captured.out

    # Check Required Header and Metadata
    assert "Windows Defensive Security Scanner" in output
    assert "Host:" in output
    assert "Scan type:" in output
    assert "Duration:  1.23s" in output

    # Check Required Severity Breakdown
    assert "Findings" in output
    assert "CRITICAL: 1" in output
    assert "HIGH:     1" in output
    assert "MEDIUM:   1" in output
    assert "LOW:      1" in output

    # Check Required Finding Detail Fields
    assert "Finding ID:" in output
    assert "Rule ID:" in output
    assert "Severity:" in output
    assert "Confidence:" in output
    assert "Risk score:" in output
    assert "Description:" in output
    assert "Evidence:" in output
    assert "Recommendation:" in output


def test_json_mode_suppresses_human_readable_stdout(monkeypatch, capsys, tmp_path):
    """
    Verify that in --json mode, human-readable banner, progress messages,
    and summary tables are NOT printed to stdout, ensuring machine readability.
    """
    log_file = tmp_path / "clean_json_log.txt"
    monkeypatch.setattr(sys, "argv", [
        "scanner.py",
        "--output", str(log_file),
        "--no-color",
        "--json",
        "--module", "keylogger"
    ])

    exit_code = main()
    captured = capsys.readouterr()

    # Must NOT have human-readable banner or findings details in stdout
    assert "Mode: Read-Only / Non-Destructive" not in captured.out
    assert "SCAN FINDINGS DETAILS" not in captured.out
    assert "SCAN SUMMARY" not in captured.out
    assert "[+] Full findings log successfully saved" not in captured.out

    # Must contain machine-readable JSON
    assert "--- JSON OUTPUT ---" in captured.out
    json_part = captured.out.split("--- JSON OUTPUT ---")[-1].strip()
    parsed = json.loads(json_part)
    assert isinstance(parsed, list)


def test_consistent_iso_timestamp_format():
    """Verify that all findings use consistent ISO-8601 UTC timestamps."""
    detector = BaseDetector()
    f1 = detector.create_finding("Persistence", "WARN", "desc", "ev")
    assert "T" in f1.timestamp
    # ISO-8601 UTC format check
    from datetime import datetime
    parsed_dt = datetime.fromisoformat(f1.timestamp)
    assert parsed_dt.tzinfo is not None


def test_exit_codes_with_all_severities(monkeypatch, tmp_path):
    """Verify exit code 2 for CRITICAL/ALERT, 1 for WARN, and 0 for clean."""
    log_file = tmp_path / "exit_code_log.txt"

    # 1. Clean scan -> exit 0
    monkeypatch.setattr(sys, "argv", ["scanner.py", "-o", str(log_file), "--no-color"])
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(SecurityScanner, "run", lambda self: [])
        assert main() == 0

    # 2. WARN findings -> exit 1
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(SecurityScanner, "run", lambda self: [{"severity": "WARN"}])
        assert main() == 1

    # 3. ALERT findings -> exit 2
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(SecurityScanner, "run", lambda self: [{"severity": "ALERT"}])
        assert main() == 2

    # 4. CRITICAL findings -> exit 2
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(SecurityScanner, "run", lambda self: [{"severity": "CRITICAL"}])
        assert main() == 2
