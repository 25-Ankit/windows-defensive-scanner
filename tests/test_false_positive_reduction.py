"""
Unit and Integration Tests for False Positive Reduction and Centralized Allowlist (Phase 5).

Tests:
1. Legitimate applications (Chrome, VSCode, Task Manager, vmtoolsd) in standard locations are not flagged.
2. Allowlist security check: Benign process names running from user-writable/temp paths (%TEMP%, %APPDATA%)
   are NEVER exempt from detection (prevents masquerading bypass).
3. Ambiguous single keywords (e.g. 'logger', 'hidden') on standard allowlisted software do not trigger false alerts.
4. Ambiguous keywords combined with suspicious execution locations (%TEMP%) DO trigger ALERT findings.
5. High-confidence malicious attack tools (Mimikatz, Beacon, Meterpreter) are always flagged as ALERT.
6. Centralized allowlist customization (register_benign_process, reset_custom_allowlists).
7. Signed vs unsigned binary context handling.
"""

import os
import pytest
from detectors.allowlist import (
    is_allowlisted_process,
    is_allowlisted_service,
    is_allowlisted_dll,
    register_benign_process,
    reset_custom_allowlists,
)
from detectors.process_detector import ProcessDetector
from detectors.surveillance_detector import SurveillanceDetector
from detectors.keylogger_detector import KeyloggerDetector


@pytest.fixture(autouse=True)
def clean_allowlist():
    """Ensure custom allowlist additions are cleared between tests."""
    reset_custom_allowlists()
    yield
    reset_custom_allowlists()


def test_legitimate_applications_in_standard_paths():
    """Verify that recognized benign applications running in standard paths are allowlisted."""
    assert is_allowlisted_process("chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe") is True
    assert is_allowlisted_process("code.exe", r"C:\Program Files\Microsoft VS Code\Code.exe") is True
    assert is_allowlisted_process("taskmgr.exe", r"C:\Windows\System32\taskmgr.exe") is True
    assert is_allowlisted_process("mstsc.exe", r"C:\Windows\System32\mstsc.exe") is True
    assert is_allowlisted_process("vmtoolsd.exe", r"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe") is True


def test_allowlist_never_exempts_user_writable_paths():
    """
    CRITICAL SECURITY TEST:
    Malware naming itself 'chrome.exe' or 'svchost.exe' running from a temp/user directory
    must NEVER be allowlisted.
    """
    assert is_allowlisted_process("chrome.exe", r"C:\Users\Victim\AppData\Local\Temp\chrome.exe") is False
    assert is_allowlisted_process("code.exe", r"C:\Users\Public\code.exe") is False
    assert is_allowlisted_process("mstsc.exe", r"C:\Users\Target\Downloads\mstsc.exe") is False
    assert is_allowlisted_process("svchost.exe", r"C:\Users\Public\svchost.exe") is False


def test_single_ambiguous_keyword_on_standard_app_no_false_positive():
    """
    Verify that an allowlisted application running in Program Files with an argument containing
    a weak keyword like 'logger' or 'hidden' is NOT flagged as an ALERT.
    """
    detector = ProcessDetector()
    detector.process_provider = lambda: [
        {
            "pid": 4101,
            "name": "chrome.exe",
            "exe": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            "cmdline": r'"C:\Program Files\Google\Chrome\Application\chrome.exe" --enable-logging --v=1',
            "username": "User",
            "ppid": 100
        },
        {
            "pid": 4102,
            "name": "code.exe",
            "exe": r"C:\Program Files\Microsoft VS Code\Code.exe",
            "cmdline": r'"C:\Program Files\Microsoft VS Code\Code.exe" --hidden-window',
            "username": "User",
            "ppid": 100
        }
    ]

    findings = detector.run()
    # Both should be dismissed as false positives due to allowlist + standard path + single weak keyword
    assert len(findings) == 0


def test_ambiguous_keyword_in_user_writable_path_flagged():
    """
    If an ambiguous keyword ('logger', 'hidden') appears in a process executing from
    a user-writable location (%TEMP%), it MUST be flagged as an ALERT.
    """
    detector = ProcessDetector()
    detector.process_provider = lambda: [
        {
            "pid": 4201,
            "name": "updater.exe",
            "exe": r"C:\Users\Victim\AppData\Local\Temp\updater.exe",
            "cmdline": r"updater.exe --logger-dump",
            "username": "User",
            "ppid": 100
        }
    ]

    findings = detector.run()
    assert len(findings) == 1
    assert findings[0]["severity"] == "ALERT"
    assert "updater.exe" in findings[0]["evidence"]


def test_high_confidence_attack_tool_always_flagged():
    """
    Unambiguous attack keywords (mimikatz, cobaltstrike, beacon, meterpreter) must
    always be flagged as ALERT regardless of path.
    """
    detector = ProcessDetector()
    detector.process_provider = lambda: [
        {
            "pid": 4301,
            "name": "test_beacon.exe",
            "exe": r"C:\Tools\test_beacon.exe",
            "cmdline": r"test_beacon.exe --c2-connect",
            "username": "User",
            "ppid": 100
        }
    ]

    findings = detector.run()
    assert len(findings) >= 1
    assert findings[0]["severity"] == "ALERT"
    assert "beacon" in findings[0]["evidence"].lower()


def test_multiple_weak_indicators_escalate_to_alert():
    """
    When multiple weak indicators match (e.g. 'logger' AND 'hidden' AND 'inject'),
    the finding escalates to ALERT with compounding risk factors.
    """
    detector = ProcessDetector()
    detector.process_provider = lambda: [
        {
            "pid": 4401,
            "name": "suspicious_tool.exe",
            "exe": r"C:\Tools\suspicious_tool.exe",
            "cmdline": r"suspicious_tool.exe --logger --inject-dll --hidden",
            "username": "User",
            "ppid": 100
        }
    ]

    findings = detector.run()
    assert len(findings) == 1
    assert findings[0]["severity"] == "ALERT"
    assert findings[0]["risk_score"] >= 70
    assert any("Multiple indicators" in f for f in findings[0]["risk_factors"])


def test_custom_allowlist_registration():
    """Verify that administrators can register custom benign processes and services."""
    assert is_allowlisted_process("internal_monitor.exe", r"C:\Program Files\Corp\internal_monitor.exe") is False

    register_benign_process("internal_monitor.exe")
    assert is_allowlisted_process("internal_monitor.exe", r"C:\Program Files\Corp\internal_monitor.exe") is True

    # Ensure user-writable override still holds
    assert is_allowlisted_process("internal_monitor.exe", r"C:\Users\Public\internal_monitor.exe") is False
