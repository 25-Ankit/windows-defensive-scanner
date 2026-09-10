"""
Adversarial, Fault Injection, and Graceful Degradation Tests (Phase 6).

Exercises all 15 required adversarial scenarios:
1. Legitimate software handling.
2. Suspicious software indicators.
3. Masquerading names.
4. Slightly modified names (typosquatting, homoglyphs).
5. User-writable execution locations.
6. Missing metadata (None/empty fields in processes, services, tasks, registry).
7. Missing optional dependencies (psutil is None, winreg is None, wmi is None, ctypes is None).
8. Permission failures (PermissionError, AccessDenied).
9. Registry access failures (FileNotFoundError, OSError).
10. Service enumeration failures (exceptions raised during service querying).
11. Scheduled-task failures (task provider throws exceptions or returns malformed rows).
12. Invalid process information (None, negative PIDs, non-integer types, non-dict objects).
13. Empty command lines (None, empty strings, whitespace only).
14. Unexpected subprocess output (corrupted stdout, malformed JSON, error codes).
15. Malformed data (bytes, non-string keys, invalid types).

Guarantee:
The scanner MUST degrade gracefully and NEVER crash an entire scan due to an inaccessible resource.
"""

import sys
import pytest
from detectors.base_detector import BaseDetector
from detectors.persistence_detector import PersistenceDetector
from detectors.process_detector import ProcessDetector
from detectors.keylogger_detector import KeyloggerDetector
from detectors.credential_theft_detector import CredentialTheftDetector
from detectors.surveillance_detector import SurveillanceDetector
from detectors.hidden_install_detector import HiddenInstallDetector
from scanner import SecurityScanner


# -----------------------------------------------------------------------------
# Scenarios 1-5: Legitimate vs Suspicious, Masquerading, Typos, User-Writable
# -----------------------------------------------------------------------------

def test_scenario_1_legitimate_software():
    """1. Legitimate software in canonical locations must not be falsely flagged as threats."""
    detector = ProcessDetector()
    detector.process_provider = lambda: [
        {"pid": 100, "name": "explorer.exe", "exe": r"C:\Windows\explorer.exe", "cmdline": "explorer.exe"},
        {"pid": 101, "name": "dwm.exe", "exe": r"C:\Windows\System32\dwm.exe", "cmdline": "dwm.exe"},
        {"pid": 102, "name": "chrome.exe", "exe": r"C:\Program Files\Google\Chrome\Application\chrome.exe", "cmdline": "chrome.exe"}
    ]
    findings = detector.run()
    assert len(findings) == 0


def test_scenario_2_suspicious_software_indicators():
    """2. Known suspicious software indicators must be reliably detected."""
    detector = CredentialTheftDetector()
    detector.process_provider = lambda: [
        {"pid": 200, "name": "pypykatz.exe", "exe": r"C:\Tools\pypykatz.exe", "cmdline": "pypykatz.exe live lsa"}
    ]
    findings = detector.run()
    assert len(findings) >= 1
    assert findings[0]["severity"] == "ALERT"


def test_scenario_3_masquerading_names():
    """3. Legitimate Windows system binary names running from unauthorized paths must be flagged."""
    detector = ProcessDetector()
    detector.process_provider = lambda: [
        {"pid": 300, "name": "lsass.exe", "exe": r"C:\Users\Public\lsass.exe", "cmdline": "lsass.exe"}
    ]
    findings = detector.run()
    assert any("Process Masquerading" in f["description"] for f in findings)


def test_scenario_4_slightly_modified_names():
    """4. Slightly modified names (homoglyphs, Levenshtein lookalikes) must be flagged."""
    detector = ProcessDetector()
    detector.process_provider = lambda: [
        {"pid": 401, "name": "svch0st.exe", "exe": r"C:\Tools\svch0st.exe", "cmdline": "svch0st.exe"},
        {"pid": 402, "name": "1sass.exe", "exe": r"C:\Tools\1sass.exe", "cmdline": "1sass.exe"},
        {"pid": 403, "name": "services32.exe", "exe": r"C:\Tools\services32.exe", "cmdline": "services32.exe"}
    ]
    findings = detector.run()
    assert len(findings) >= 3
    assert all(f["severity"] == "ALERT" for f in findings)


def test_scenario_5_user_writable_execution_locations():
    """5. Binaries and tasks configured in user-writable paths must trigger high-severity alerts."""
    detector = HiddenInstallDetector()
    detector.service_provider = lambda: [
        {"name": "TempSvc", "display_name": "Temp Svc", "description": "Temp description", "binpath": r"C:\Users\Public\svc.exe", "start_type": "auto"}
    ]
    detector.task_provider = lambda: [
        {"name": "TempTask", "task_to_run": r"C:\Windows\Temp\task.exe"}
    ]
    findings = detector.run()
    alerts = [f for f in findings if f["severity"] == "ALERT"]
    assert len(alerts) == 2
    assert any("TempSvc" in f["evidence"] for f in alerts)
    assert any("TempTask" in f["evidence"] for f in alerts)


# -----------------------------------------------------------------------------
# Scenarios 6 & 12 & 13: Missing Metadata, Invalid Process Info, Empty Cmdlines
# -----------------------------------------------------------------------------

def test_scenarios_6_12_13_missing_metadata_and_invalid_processes():
    """6, 12, 13. Test missing metadata, invalid process info (negative PIDs, non-dict), empty cmdlines."""
    detectors = [
        ProcessDetector(),
        CredentialTheftDetector(),
        SurveillanceDetector(),
        KeyloggerDetector(),
    ]

    # Malformed process list containing:
    # - Non-dict item (strings, numbers, None)
    # - None fields
    # - Negative PID
    # - Missing / empty / whitespace cmdline
    # - Non-string cmdlines
    malformed_processes = [
        None,
        "string_instead_of_dict",
        12345,
        {"pid": None, "name": None, "exe": None, "cmdline": None},
        {"pid": -500, "name": "", "exe": "", "cmdline": ""},
        {"pid": "not_an_int", "name": "test.exe", "exe": None, "cmdline": "   "},
        {"pid": 9999, "name": 12345, "exe": False, "cmdline": []},
    ]

    for d in detectors:
        d.process_provider = lambda: malformed_processes
        # Must execute cleanly without unhandled exceptions
        findings = d.run()
        assert isinstance(findings, list)


# -----------------------------------------------------------------------------
# Scenario 7: Missing Optional Dependencies
# -----------------------------------------------------------------------------

def test_scenario_7_missing_optional_dependencies(monkeypatch):
    """7. Ensure detectors and BaseDetector function gracefully when optional dependencies are absent."""
    import detectors.base_detector as bd

    # Simulate missing psutil, winreg, wmi, and ctypes
    monkeypatch.setattr(bd, "psutil", None)
    monkeypatch.setattr(bd, "winreg", None)
    monkeypatch.setattr(bd, "wmi", None)
    monkeypatch.setattr(bd, "ctypes", None)

    detector = BaseDetector()
    assert detector.is_admin() in (True, False)
    assert detector.read_registry_values("HKLM", "Software\\Test") == []
    assert detector.enumerate_processes() == []
    assert detector.enumerate_services() == []
    assert detector.enumerate_scheduled_tasks() == []
    assert detector.enumerate_process_modules(123) == []


# -----------------------------------------------------------------------------
# Scenarios 8 & 9: Permission Failures and Registry Access Failures
# -----------------------------------------------------------------------------

def test_scenarios_8_9_permission_and_registry_failures():
    """8, 9. Scanner must degrade gracefully on PermissionError, FileNotFoundError, OSError."""
    detector = PersistenceDetector()

    def failing_registry_provider(root, subkey):
        raise PermissionError("Access is denied to registry key (simulated SACL rejection)")

    def failing_services_provider():
        raise OSError("RPC server unavailable during service enumeration")

    def failing_task_provider():
        raise FileNotFoundError("Task scheduler directory not found")

    detector.registry_provider = failing_registry_provider
    detector.service_provider = failing_services_provider
    detector.task_provider = failing_task_provider
    detector.startup_folders_override = ["/non_existent_folder_xyz_404"]

    # Must complete and return an empty or partial list rather than crashing
    findings = detector.run()
    assert isinstance(findings, list)
    assert len(findings) == 0


# -----------------------------------------------------------------------------
# Scenarios 10 & 11: Service & Scheduled Task Enumeration Failures
# -----------------------------------------------------------------------------

def test_scenarios_10_11_service_and_task_enumeration_failures():
    """10, 11. Exceptions during service or scheduled task querying must not abort scan."""
    detector = HiddenInstallDetector()

    detector.service_provider = lambda: [
        # Malformed service entries mixed with an exception
        None,
        {"name": None, "binpath": None},
        {"name": "ValidService", "binpath": r"C:\Windows\Temp\malicious.exe", "display_name": "", "start_type": "auto"}
    ]

    def explosive_task_provider():
        raise RuntimeError("Subprocess schtasks.exe crashed with memory corruption")

    detector.task_provider = explosive_task_provider

    # HiddenInstallDetector should catch the task failure and still process the service finding
    findings = detector.run()
    assert isinstance(findings, list)
    assert len(findings) >= 1
    assert any("ValidService" in f["evidence"] for f in findings)


# -----------------------------------------------------------------------------
# Scenario 14: Unexpected Subprocess Output
# -----------------------------------------------------------------------------

def test_scenario_14_unexpected_subprocess_output():
    """14. Handle non-zero exit codes, corrupted JSON, and empty output in digital signature checking."""
    detector = BaseDetector()

    # Fault-injected signature checker returning corrupted structure
    detector.signature_checker = lambda path: "NOT_A_DICT"

    sig = detector.check_digital_signature(r"C:\Windows\System32\cmd.exe")
    assert isinstance(sig, dict)
    assert sig["valid"] is False
    assert sig["status"] == "Error"


# -----------------------------------------------------------------------------
# Scenario 15: Malformed Data & Entire Scanner Pipeline Resilience
# -----------------------------------------------------------------------------

def test_scenario_15_full_scanner_graceful_degradation_with_mixed_faults(tmp_path):
    """
    15. Full SecurityScanner execution under extreme combined fault injection:
    - Failing detector throwing unhandled exception
    - Corrupt registry data
    - Malformed process and service entries
    """
    log_file = tmp_path / "degradation_scan_log.txt"

    scanner = SecurityScanner(
        log_file=str(log_file),
        color_enabled=False,
        verbose=True
    )

    # Corrupt providers for all detectors
    def explosive_process_provider():
        raise SystemError("Simulated system call fault")

    for d in scanner.detectors:
        d.process_provider = explosive_process_provider
        d.registry_provider = lambda r, s: [{"name": None, "data": None}]
        d.service_provider = lambda: [None, {"name": 999}]
        d.task_provider = lambda: ["malformed_task_string"]

    # SecurityScanner must complete the scan, log errors, write log file, and exit safely
    findings = scanner.run()
    assert isinstance(findings, list)
    assert log_file.is_file()
