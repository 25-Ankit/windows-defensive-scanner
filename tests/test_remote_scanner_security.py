"""
Tests for Remote Scanner Security and Credential Handling (Phase 2).

Verifies:
1. Credentials are never exposed on command line arguments of subprocesses.
2. Credentials are passed via private subprocess environment and scrubbed.
3. Error messages and logs redact cleartext passwords.
4. CLI supports DEFSCAN_PASSWORD environment variable.
5. CLI supports interactive getpass prompt when TTY is attached.
6. Support for passwordless integrated authentication (Kerberos/SSO).
7. Consolidated audit logs and JSON findings never leak passwords.
"""

import os
import sys
import json
import pytest
from unittest.mock import patch, MagicMock

from remote_scanner import RemoteScannerOrchestrator, main


def test_remote_scanner_never_exposes_password_in_cli_cmd(monkeypatch):
    """
    Verify that cmd passed to subprocess.run does NOT contain the password string.
    """
    secret_pass = "P@ssw0rd!SuperSecret#99"
    orchestrator = RemoteScannerOrchestrator(
        targets=["TARGET-SEC01"],
        username="DOMAIN\\Admin",
        password=secret_pass
    )

    captured_cmds = []
    captured_envs = []

    def mock_subprocess_run(cmd, input=None, env=None, capture_output=True, text=True, timeout=120, check=False):
        captured_cmds.append(list(cmd))
        captured_envs.append(dict(env) if env else {})
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "--- JSON OUTPUT ---\n[]"
        mock_proc.stderr = ""
        return mock_proc

    monkeypatch.setattr("subprocess.run", mock_subprocess_run)

    result = orchestrator.execute_remote_scan("TARGET-SEC01")
    assert result["status"] == "SUCCESS"

    # 1. Password must NEVER be in command line arguments
    assert len(captured_cmds) == 1
    for arg in captured_cmds[0]:
        assert secret_pass not in arg, f"Cleartext password found in command line arg: {arg}"

    # 2. Password must have been passed via private subprocess environment variable
    assert len(captured_envs) == 1
    assert captured_envs[0].get("DEFSCAN_TARGET_PASS") == secret_pass


def test_remote_scanner_error_sanitization_redacts_password(monkeypatch):
    """
    Verify that if a remote error (stderr or exception) contains the password,
    it is sanitized and replaced with [REDACTED].
    """
    secret_pass = "LeakedPass123!"
    orchestrator = RemoteScannerOrchestrator(
        targets=["TARGET-FAIL"],
        username="Admin",
        password=secret_pass
    )

    def mock_failing_subprocess(cmd, input=None, env=None, capture_output=True, text=True, timeout=120, check=False):
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        # Simulate stderr echoing script line with password
        mock_proc.stdout = ""
        mock_proc.stderr = f"Authentication failure with credentials for Admin using LeakedPass123!"
        return mock_proc

    monkeypatch.setattr("subprocess.run", mock_failing_subprocess)

    result = orchestrator.execute_remote_scan("TARGET-FAIL")
    assert result["status"] == "ERROR"
    assert secret_pass not in result["error"], "Cleartext password leaked in error message"
    assert "[REDACTED]" in result["error"]


def test_remote_scanner_exception_sanitization_redacts_password(monkeypatch):
    """
    Verify that if an exception message contains the password, it is redacted.
    """
    secret_pass = "TopSecretErrorPass"
    orchestrator = RemoteScannerOrchestrator(
        targets=["TARGET-EXC"],
        username="Admin",
        password=secret_pass
    )

    def mock_exception_subprocess(*args, **kwargs):
        raise RuntimeError(f"Connection failed with password TopSecretErrorPass")

    monkeypatch.setattr("subprocess.run", mock_exception_subprocess)

    result = orchestrator.execute_remote_scan("TARGET-EXC")
    assert result["status"] == "ERROR"
    assert secret_pass not in result["error"]
    assert "[REDACTED]" in result["error"]


def test_remote_scanner_password_from_env_var(monkeypatch, tmp_path):
    """
    Verify that remote_scanner main() reads DEFSCAN_PASSWORD from environment when -p is omitted.
    """
    out_file = tmp_path / "env_scan.txt"
    monkeypatch.setenv("DEFSCAN_PASSWORD", "EnvSecretPass2026")
    monkeypatch.setattr(sys, "argv", [
        "remote_scanner.py",
        "TARGET-ENV",
        "-u", "Admin",
        "-o", str(out_file)
    ])

    captured_passwords = []

    def mock_run_all(self):
        captured_passwords.append(self.password)
        return {"TARGET-ENV": {"status": "SUCCESS", "findings": []}}

    monkeypatch.setattr(RemoteScannerOrchestrator, "run_all", mock_run_all)

    exit_code = main()
    assert exit_code == 0
    assert captured_passwords == ["EnvSecretPass2026"]


def test_remote_scanner_password_interactive_prompt(monkeypatch, tmp_path):
    """
    Verify that when stdin is a tty and no password is provided, getpass.getpass is called.
    """
    out_file = tmp_path / "prompt_scan.txt"
    monkeypatch.delenv("DEFSCAN_PASSWORD", raising=False)
    monkeypatch.setattr(sys, "argv", [
        "remote_scanner.py",
        "TARGET-PROMPT",
        "-u", "DomainAdmin",
        "-o", str(out_file)
    ])
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

    prompt_called = []

    def mock_getpass(prompt=""):
        prompt_called.append(prompt)
        return "PromptedSecretPass"

    monkeypatch.setattr("getpass.getpass", mock_getpass)

    captured_passwords = []

    def mock_run_all(self):
        captured_passwords.append(self.password)
        return {"TARGET-PROMPT": {"status": "SUCCESS", "findings": []}}

    monkeypatch.setattr(RemoteScannerOrchestrator, "run_all", mock_run_all)

    exit_code = main()
    assert exit_code == 0
    assert len(prompt_called) == 1
    assert "DomainAdmin" in prompt_called[0]
    assert captured_passwords == ["PromptedSecretPass"]


def test_remote_scanner_integrated_auth_when_no_password(monkeypatch):
    """
    Verify that when no password is provided, Invoke-Command does not include -Credential,
    allowing Integrated Windows Authentication / Kerberos ticket delegation.
    """
    orchestrator = RemoteScannerOrchestrator(
        targets=["TARGET-KERB"]
        # username and password are None
    )

    captured_inputs = []

    def mock_subprocess_run(cmd, input=None, env=None, capture_output=True, text=True, timeout=120, check=False):
        captured_inputs.append(input or "")
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "--- JSON OUTPUT ---\n[]"
        mock_proc.stderr = ""
        return mock_proc

    monkeypatch.setattr("subprocess.run", mock_subprocess_run)

    result = orchestrator.execute_remote_scan("TARGET-KERB")
    assert result["status"] == "SUCCESS"
    assert len(captured_inputs) == 1
    # In integrated auth mode, -Credential must NOT be present
    assert "-Credential" not in captured_inputs[0]
    assert "Invoke-Command -ComputerName 'TARGET-KERB'" in captured_inputs[0]


def test_consolidated_log_never_contains_password(tmp_path):
    """
    Verify that the consolidated log file produced by RemoteScannerOrchestrator
    never leaks credentials.
    """
    out_file = tmp_path / "consolidated_audit.txt"
    secret_pass = "NeverLogThisPassword"

    orchestrator = RemoteScannerOrchestrator(
        targets=["TARGET-LOG"],
        username="Admin",
        password=secret_pass,
        output_file=str(out_file)
    )

    # Mock runner that simulates an error and finding
    def mock_runner(target):
        return {
            "target": target,
            "status": "ERROR",
            "findings": [
                {
                    "category": "Credential Theft",
                    "severity": "ALERT",
                    "description": "LSASS access detected",
                    "evidence": "PID: 500",
                    "timestamp": "2026-09-10T12:00:00Z"
                }
            ],
            "error": "Failed authentication [REDACTED]"
        }

    orchestrator.command_runner = mock_runner
    orchestrator.run_all()

    assert out_file.is_file()
    log_text = out_file.read_text(encoding="utf-8")
    assert secret_pass not in log_text
    assert "LSASS access detected" in log_text


def test_remote_scanner_findings_redact_password(monkeypatch):
    """
    Verify that if remote JSON findings inadvertently contain the password string,
    it is recursively redacted from the findings list and evidence.
    """
    secret_pass = "AccidentalLeakSecret987"
    orchestrator = RemoteScannerOrchestrator(
        targets=["TARGET-LEAK"],
        username="Admin",
        password=secret_pass
    )

    def mock_subprocess_run(cmd, input=None, env=None, capture_output=True, text=True, timeout=120, check=False):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        leaked_findings = [
            {
                "category": "Process Spoofing / AV Evasion",
                "severity": "ALERT",
                "description": f"Process started with secret {secret_pass}",
                "evidence": f"cmdline: evil.exe -p {secret_pass}",
                "timestamp": "2026-09-10T12:00:00Z"
            }
        ]
        mock_proc.stdout = f"--- JSON OUTPUT ---\n{json.dumps(leaked_findings)}"
        mock_proc.stderr = ""
        return mock_proc

    monkeypatch.setattr("subprocess.run", mock_subprocess_run)

    result = orchestrator.execute_remote_scan("TARGET-LEAK")
    assert result["status"] == "SUCCESS"
    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    assert secret_pass not in finding["description"]
    assert secret_pass not in finding["evidence"]
    assert "[REDACTED]" in finding["description"]
    assert "[REDACTED]" in finding["evidence"]


def test_remote_scanner_target_validation_invalid_chars():
    """
    Verify that targets with shell metacharacters or command injection characters
    are rejected before subprocess execution.
    """
    orchestrator = RemoteScannerOrchestrator(
        targets=["BAD;TARGET", "HOST&whoami", "TARGET' `rm -rf`", ""]
    )

    for bad_target in ["BAD;TARGET", "HOST&whoami", "TARGET' `rm -rf`"]:
        res = orchestrator.execute_remote_scan(bad_target)
        assert res["status"] == "ERROR"
        assert "Invalid target identifier" in res["error"]


def test_remote_scanner_username_validation_invalid_chars():
    """
    Verify that usernames with disallowed injection characters are rejected.
    """
    orchestrator = RemoteScannerOrchestrator(
        targets=["VALID-HOST"],
        username="Admin\nmalicious_command; #"
    )

    res = orchestrator.execute_remote_scan("VALID-HOST")
    assert res["status"] == "ERROR"
    assert "Invalid username format" in res["error"]


def test_remote_scanner_cli_password_warning(monkeypatch, caplog):
    """
    Verify that providing -p / --password via CLI produces a security warning.
    """
    import logging
    monkeypatch.setattr(sys, "argv", [
        "remote_scanner.py",
        "TARGET-WARN",
        "-u", "Admin",
        "-p", "CliExposedPass123"
    ])

    captured_passwords = []

    def mock_run_all(self):
        captured_passwords.append(self.password)
        return {"TARGET-WARN": {"status": "SUCCESS", "findings": []}}

    monkeypatch.setattr(RemoteScannerOrchestrator, "run_all", mock_run_all)

    with caplog.at_level(logging.WARNING):
        exit_code = main()

    assert exit_code == 0
    assert captured_passwords == ["CliExposedPass123"]
    assert any("SECURITY WARNING" in record.message for record in caplog.records)

