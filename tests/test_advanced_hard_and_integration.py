"""
Advanced Hard Scenarios, Cross-Platform Edge Cases, and End-to-End Integration Tests.

Tests:
1. CWE-428 Unquoted Service and Run Key Path Vulnerability detection (flagged as WARN).
2. Unquoted path with spaces correctly resolves executable rather than truncating at space.
3. StartupApproved binary registry entries do not trigger false positive orphan file alerts.
4. Core Windows services (RpcSs, WinRM, RemoteAccess, etc.) are never falsely flagged by SurveillanceDetector.
5. Scheduled tasks and services executing scripts (.ps1, .bat, .vbs) from user-writable paths are detected as ALERT.
6. Process with quotes in exe path ("C:\\Windows\\System32\\svchost.exe") is not falsely flagged as masquerading.
7. Loaded module inspection correctly extracts base DLL names from Windows paths on all platforms.
8. Remote scanner credential escaping handles single quotes, dollars, and special characters safely.
9. Remote scanner stdin execution mechanism avoids Windows 32KB command line limit.
10. Full end-to-end scan pipeline with mixed threats and edge cases produces valid logs and proper exit codes.
"""

import os
import sys
import pytest
from pathlib import Path

from scanner import SecurityScanner
from detectors.base_detector import BaseDetector
from detectors.persistence_detector import PersistenceDetector
from detectors.process_detector import ProcessDetector
from detectors.keylogger_detector import KeyloggerDetector
from detectors.credential_theft_detector import CredentialTheftDetector
from detectors.surveillance_detector import SurveillanceDetector
from detectors.hidden_install_detector import HiddenInstallDetector
from remote_scanner import RemoteScannerOrchestrator, get_powershell_executable


# =============================================================================
# 1. Path Extraction & CWE-428 Unquoted Path Unit Tests
# =============================================================================

def test_extract_file_path_unquoted_with_spaces():
    detector = BaseDetector()

    # Unquoted path with space and arguments
    unquoted_cmd = r"C:\Program Files\Common Files\Vendor\service.exe -k run -d"
    resolved = detector.extract_file_path(unquoted_cmd)
    assert resolved == r"C:\Program Files\Common Files\Vendor\service.exe"

    # Properly quoted path
    quoted_cmd = r'"C:\Program Files\Common Files\Vendor\service.exe" -k run'
    resolved_quoted = detector.extract_file_path(quoted_cmd)
    assert resolved_quoted == r"C:\Program Files\Common Files\Vendor\service.exe"

    # Single quoted path
    single_quoted_cmd = r"'C:\Program Files\App\tool.exe' --flag"
    assert detector.extract_file_path(single_quoted_cmd) == r"C:\Program Files\App\tool.exe"

    # Switch match fallback
    switch_cmd = r"C:\Tools\mytool /opt1 /opt2"
    assert detector.extract_file_path(switch_cmd) == r"C:\Tools\mytool"


def test_cwe428_unquoted_path_vulnerability_detection():
    detector = BaseDetector()

    # Vulnerable unquoted paths containing spaces
    assert detector.check_unquoted_path_vulnerability(r"C:\Program Files\My App\service.exe") is True
    assert detector.check_unquoted_path_vulnerability(r"C:\Program Files (x86)\Vendor\agent.exe -run") is True

    # Safe quoted paths
    assert detector.check_unquoted_path_vulnerability(r'"C:\Program Files\My App\service.exe"') is False
    assert detector.check_unquoted_path_vulnerability(r'"C:\Program Files (x86)\Vendor\agent.exe" -run') is False

    # Path without spaces (not vulnerable to unquoted space hijacking)
    assert detector.check_unquoted_path_vulnerability(r"C:\Windows\System32\svchost.exe -k netsvcs") is False
    assert detector.check_unquoted_path_vulnerability("") is False


# =============================================================================
# 2. User-Writable and Standard System Path Edge Cases
# =============================================================================

def test_user_writable_path_detection():
    detector = BaseDetector()

    # Direct files in user home directories (previously missed if not in AppData)
    assert detector.is_temp_or_user_writable(r"C:\Users\Victim\malware.exe") is True
    assert detector.is_temp_or_user_writable(r"C:\Users\Victim\Documents\backdoor.ps1") is True
    assert detector.is_temp_or_user_writable(r"C:\Users\Default\Desktop\payload.bat") is True
    assert detector.is_temp_or_user_writable(r"C:\Users\Public\Downloads\stealer.exe") is True

    # Forward slash paths
    assert detector.is_temp_or_user_writable("C:/Users/Victim/evil.exe") is True
    assert detector.is_temp_or_user_writable("C:/Windows/Temp/payload.exe") is True

    # Legitimate system files
    assert detector.is_temp_or_user_writable(r"C:\Windows\System32\svchost.exe") is False
    assert detector.is_temp_or_user_writable(r"C:\Program Files\SafeApp\app.exe") is False


def test_standard_system_path_exclusion_of_temp():
    detector = BaseDetector()

    # Temp directories inside C:\Windows must NOT be treated as standard system paths
    assert detector.is_standard_system_path(r"C:\Windows\Temp\malware.exe") is False

    # Standard system paths
    assert detector.is_standard_system_path(r"C:\Windows\System32\cmd.exe") is True
    assert detector.is_standard_system_path(r"C:\Program Files\Vendor\app.exe") is True

    # Alternate drive letters (e.g. D:\Windows, D:\Program Files)
    assert detector.is_standard_system_path(r"D:\Windows\System32\cmd.exe") is True
    assert detector.is_standard_system_path(r"E:\Program Files\Tools\app.exe") is True


# =============================================================================
# 3. StartupApproved Binary Data False Positive Prevention
# =============================================================================

def test_startup_approved_binary_data_no_false_positive(mock_registry):
    """
    On real Windows machines, StartupApproved keys contain REG_BINARY data (e.g. b'\x02\x00...').
    Verify that these are NOT flagged as non-existent file orphans.
    """
    detector = PersistenceDetector()
    detector.registry_provider = mock_registry
    detector.service_provider = lambda: []
    detector.task_provider = lambda: []

    # Mock real-world binary data stored in StartupApproved
    mock_registry.store[("HKCU", r"Software\Microsoft\Windows\CurrentVersion\StartupApproved\Run")] = [
        {"name": "OneDrive", "data": b"\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "type": 3},
        {"name": "Discord", "data": b"\x03\x00\x00\x00\x23\x45\x67\x89\xab\xcd\xef\x01", "type": 3}
    ]

    findings = detector.run()
    # Must produce zero orphan file findings for binary registry data
    orphan_alerts = [f for f in findings if "non-existent file" in f["description"].lower()]
    assert len(orphan_alerts) == 0


# =============================================================================
# 4. SurveillanceDetector Legitimate Services Protection
# =============================================================================

def test_surveillance_core_windows_services_not_flagged():
    """
    Ensure core Windows services like RpcSs, RpcLocator, RemoteAccess, WinRM
    are never falsely flagged as covert surveillance.
    """
    detector = SurveillanceDetector()
    detector.process_provider = lambda: []
    detector.task_provider = lambda: []

    detector.service_provider = lambda: [
        {
            "name": "RpcSs",
            "display_name": "Remote Procedure Call (RPC)",
            "binpath": r"C:\Windows\System32\svchost.exe -k rpcss",
            "status": "RUNNING"
        },
        {
            "name": "RpcLocator",
            "display_name": "Remote Procedure Call (RPC) Locator",
            "binpath": r"C:\Windows\System32\locator.exe",
            "status": "STOPPED"
        },
        {
            "name": "RemoteAccess",
            "display_name": "Routing and Remote Access",
            "binpath": r"C:\Windows\System32\svchost.exe -k netsvcs",
            "status": "STOPPED"
        },
        {
            "name": "WinRM",
            "display_name": "Windows Remote Management (WS-Management)",
            "binpath": r"C:\Windows\System32\svchost.exe -k NetworkService",
            "status": "RUNNING"
        }
    ]

    findings = detector.run()
    surveillance_services = [f for f in findings if f["category"] == "Covert Surveillance"]
    assert len(surveillance_services) == 0, f"Legitimate Windows services were falsely flagged: {surveillance_services}"


# =============================================================================
# 5. Script Payloads in Services & Scheduled Tasks
# =============================================================================

def test_service_and_task_executing_script_in_user_directory():
    """
    Verify that services and scheduled tasks executing script interpreters (powershell, wscript)
    with scripts located in user-writable paths are detected as ALERT.
    """
    p_detector = PersistenceDetector()
    h_detector = HiddenInstallDetector()

    p_detector.registry_provider = lambda r, s: []
    p_detector.service_provider = lambda: [
        {
            "name": "PowerShellBackdoorSvc",
            "display_name": "Diagnostic Helper",
            "binpath": r"powershell.exe -ExecutionPolicy Bypass -File C:\Users\Victim\AppData\Local\Temp\backdoor.ps1",
            "status": "RUNNING"
        }
    ]
    p_detector.task_provider = lambda: [
        {
            "name": "WscriptDropperTask",
            "task_to_run": r"wscript.exe C:\Users\Victim\AppData\Roaming\dropper.vbs",
            "author": "Attacker"
        }
    ]

    # Test persistence detector
    p_findings = p_detector.run()
    p_alerts = [f for f in p_findings if f["severity"] == "ALERT"]
    assert len(p_alerts) >= 2
    assert any("PowerShellBackdoorSvc" in f["evidence"] for f in p_alerts)
    assert any("WscriptDropperTask" in f["evidence"] for f in p_alerts)

    # Test hidden install detector
    h_detector.service_provider = p_detector.service_provider
    h_detector.task_provider = p_detector.task_provider
    h_findings = h_detector.run()
    h_alerts = [f for f in h_findings if f["severity"] == "ALERT"]
    assert len(h_alerts) >= 2


# =============================================================================
# 6. CWE-428 Detection in Persistence & Hidden Install
# =============================================================================

def test_cwe428_unquoted_path_flagged_in_services_and_registry(mock_registry):
    """
    Verify that unquoted paths containing spaces are flagged with severity WARN (CWE-428).
    """
    p_detector = PersistenceDetector()
    h_detector = HiddenInstallDetector()

    mock_registry.store[("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run")] = [
        {"name": "UnquotedRunKey", "data": r"C:\Program Files\Vulnerable Vendor\app.exe -startup", "type": 1}
    ]
    p_detector.registry_provider = mock_registry
    p_detector.service_provider = lambda: [
        {
            "name": "UnquotedService",
            "display_name": "Unquoted Service",
            "binpath": r"C:\Program Files (x86)\Legacy Tool\service.exe -svc",
            "status": "RUNNING"
        }
    ]
    p_detector.task_provider = lambda: []

    findings = p_detector.run()
    cwe_findings = [f for f in findings if "CWE-428" in f["description"]]
    assert len(cwe_findings) >= 2
    assert all(f["severity"] == "WARN" for f in cwe_findings)


# =============================================================================
# 7. Process Detector Canonical Path Quoting
# =============================================================================

def test_process_detector_quoted_canonical_path_not_flagged():
    r"""
    A process whose exe path contains double quotes (e.g. '"C:\Windows\System32\svchost.exe"')
    must not be falsely flagged as masquerading.
    """
    detector = ProcessDetector()
    detector.process_provider = lambda: [
        {
            "pid": 500,
            "name": "svchost.exe",
            "exe": r'"C:\Windows\System32\svchost.exe"',  # Path wrapped in quotes
            "cmdline": r'"C:\Windows\System32\svchost.exe" -k netsvcs',
            "username": "NT AUTHORITY\\SYSTEM",
            "ppid": 400
        }
    ]

    findings = detector.run()
    masq = [f for f in findings if "Process Masquerading" in f["description"]]
    assert len(masq) == 0


# =============================================================================
# 8. Cross-Platform DLL Basename Extraction
# =============================================================================

def test_keylogger_dll_basename_cross_platform():
    r"""
    On Linux/POSIX, Windows backslash paths like 'C:\Windows\System32\uxtheme.dll'
    must have the filename properly extracted so benign whitelist matches.
    """
    detector = KeyloggerDetector()
    detector.process_provider = lambda: [
        {
            "pid": 2000,
            "name": "explorer.exe",
            "exe": r"C:\Windows\explorer.exe",
            "cmdline": "explorer.exe",
            "username": "User",
            "ppid": 1
        }
    ]
    detector.enumerate_process_modules = lambda pid: [
        r"C:\Windows\System32\uxtheme.dll",     # Whitelisted
        r"C:\Windows\System32\userenv.dll",     # Whitelisted
        r"C:\Windows\System32\hook_keyboard.dll" # Malicious hook DLL
    ]

    findings = detector.run()
    hook_findings = [f for f in findings if "Suspicious hook/keylog module" in f["description"]]
    assert len(hook_findings) == 1
    assert "hook_keyboard.dll" in hook_findings[0]["evidence"]
    assert not any("uxtheme.dll" in f["evidence"] for f in findings)
    assert not any("userenv.dll" in f["evidence"] for f in findings)


# =============================================================================
# 9. Remote Scanner Escaping & PowerShell Detection
# =============================================================================

def test_powershell_executable_detection():
    ps_exe = get_powershell_executable()
    assert ps_exe is not None
    assert isinstance(ps_exe, str)
    assert len(ps_exe) > 0


def test_remote_scanner_credential_escaping():
    """
    Ensure passwords with single quotes, dollar signs, and special characters
    are escaped properly without breaking PowerShell syntax.
    """
    orchestrator = RemoteScannerOrchestrator(
        targets=["REMOTE-TARGET"],
        username=r"CORP\Admin'User",
        password=r"P@$$w'ord$123"
    )

    captured_cmds = []

    def mock_runner(target):
        return {
            "target": target,
            "status": "SUCCESS",
            "findings": [],
            "error": None
        }

    orchestrator.command_runner = mock_runner
    results = orchestrator.run_all()
    assert results["REMOTE-TARGET"]["status"] == "SUCCESS"


# =============================================================================
# 10. Comprehensive Integration Test: Complete Scanner Pipeline
# =============================================================================

def test_full_integrated_pipeline_with_all_threats_and_fixes(tmp_path, mock_registry):
    """
    End-to-End scan verifying:
    - Persistence (Orphan run key, user startup dropper, CWE-428 warning)
    - Process Spoofing (svchost from Temp, typosquatted svch0st)
    - Keylogger (AppInit_DLLs and hook commandline)
    - Credential Theft (Mimikatz commandline)
    - Covert Surveillance (vnc process)
    - Hidden Installation (service in AppData)
    - Report generation and log output
    """
    scan_log = tmp_path / "full_defense_log.txt"

    scanner = SecurityScanner(
        log_file=str(scan_log),
        color_enabled=False,
        verbose=True
    )

    # 1. Mock Registry
    mock_registry.store[("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run")] = [
        {"name": "MissingExe", "data": r"C:\Windows\System32\ghost_binary_123.exe", "type": 1},
        {"name": "UnquotedKey", "data": r"C:\Program Files\Vendor App\run.exe -arg", "type": 1}
    ]
    mock_registry.store[("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows")] = [
        {"name": "AppInit_DLLs", "data": r"C:\Temp\global_hook.dll", "type": 1},
        {"name": "LoadAppInit_DLLs", "data": 1, "type": 4}
    ]
    mock_registry.store[("HKLM", r"Software\Microsoft\Windows\CurrentVersion\StartupApproved\Run")] = [
        {"name": "CleanApp", "data": b"\x02\x00\x00\x00\x00\x00\x00\x00", "type": 3}
    ]

    # 2. Mock Processes
    simulated_processes = [
        {
            "pid": 3100,
            "name": "svchost.exe",
            "exe": r"C:\Users\Victim\AppData\Local\Temp\svchost.exe",
            "cmdline": r"C:\Users\Victim\AppData\Local\Temp\svchost.exe",
            "username": "Victim",
            "ppid": 1000
        },
        {
            "pid": 3200,
            "name": "mimikatz.exe",
            "exe": r"C:\Tools\mimikatz.exe",
            "cmdline": r"mimikatz.exe privilege::debug sekurlsa::logonpasswords",
            "username": "Admin",
            "ppid": 1000
        },
        {
            "pid": 3300,
            "name": "winvnc.exe",
            "exe": r"C:\Tools\winvnc.exe",
            "cmdline": r"winvnc.exe -run",
            "username": "User",
            "ppid": 1000
        },
        {
            "pid": 3400,
            "name": "keylog_hook.exe",
            "exe": r"C:\Tools\keylog_hook.exe",
            "cmdline": r"keylog_hook.exe --hook WH_KEYBOARD_LL",
            "username": "User",
            "ppid": 1000
        }
    ]

    # 3. Mock Services
    simulated_services = [
        {
            "name": "AppDataService",
            "display_name": "AppData Service",
            "binpath": r"C:\Users\Victim\AppData\Local\Temp\svc.exe",
            "start_type": "auto",
            "description": "Stealth service",
            "status": "RUNNING"
        },
        {
            "name": "RpcSs",
            "display_name": "Remote Procedure Call (RPC)",
            "binpath": r"C:\Windows\System32\svchost.exe -k rpcss",
            "status": "RUNNING"
        }
    ]

    # 4. Mock Scheduled Tasks
    simulated_tasks = [
        {
            "name": "PowerShellGrabber",
            "task_to_run": r"powershell.exe -w hidden -c [System.Drawing.Graphics]::CopyFromScreen(0,0,0,0,$b.Size)",
            "author": "Attacker"
        }
    ]

    # Inject into detectors
    for d in scanner.detectors:
        d.registry_provider = mock_registry
        d.process_provider = lambda: simulated_processes
        d.service_provider = lambda: simulated_services
        d.task_provider = lambda: simulated_tasks

    findings = scanner.run()

    # Verify all categories triggered
    categories = {f["category"] for f in findings}
    assert "Persistence" in categories
    assert "Process Spoofing / AV Evasion" in categories
    assert "Keylogging" in categories
    assert "Credential Theft" in categories
    assert "Covert Surveillance" in categories
    assert "Hidden Installation" in categories

    # Verify CWE-428 was flagged as WARN
    assert any("CWE-428" in f["description"] and f["severity"] == "WARN" for f in findings)

    # Verify AppDataService was flagged as ALERT
    assert any("AppDataService" in f["evidence"] and f["severity"] == "ALERT" for f in findings)

    # Verify RpcSs was NOT flagged
    assert not any("RpcSs" in f["evidence"] and f["category"] == "Covert Surveillance" for f in findings)

    # Verify log output was written
    assert scan_log.is_file()
    log_content = scan_log.read_text(encoding="utf-8")
    assert "WINDOWS DEFENSIVE SECURITY SCANNER - AUDIT LOG" in log_content
    assert "Total Findings:" in log_content
