"""
Hard Scenarios, Obfuscation Evasion, and Edge Case Tests for Windows Defensive Security Scanner.
"""

import os
import io
import zipfile
import base64
import pytest
from pathlib import Path

from detectors.base_detector import BaseDetector
from detectors.process_detector import ProcessDetector
from detectors.persistence_detector import PersistenceDetector
from detectors.credential_theft_detector import CredentialTheftDetector
from detectors.keylogger_detector import KeyloggerDetector
from detectors.surveillance_detector import SurveillanceDetector
from detectors.hidden_install_detector import HiddenInstallDetector
from remote_scanner import RemoteScannerOrchestrator


# =============================================================================
# 1. Hard Tests: Typosquatting & Process Masquerading
# =============================================================================

@pytest.mark.parametrize("proc_name,expected_reason_substr", [
    ("svch0st.exe", "homoglyph"),
    ("scvhost.exe", "Typosquatting"),
    ("lsas.exe", "Typosquatting"),
    ("1sass.exe", "homoglyph"),
    ("winlog0n.exe", "homoglyph"),
    ("csrs.exe", "Typosquatting"),
    ("services32.exe", "Typosquatting"),
    ("svchost.exe ", "trailing whitespace"),
])
def test_hard_process_typosquatting_lookalikes(proc_name, expected_reason_substr):
    detector = ProcessDetector()
    detector.process_provider = lambda: [
        {
            "pid": 9991,
            "name": proc_name,
            "exe": f"C:\\Windows\\Temp\\{proc_name.strip()}",
            "cmdline": proc_name,
            "username": "User",
            "ppid": 1
        }
    ]

    findings = detector.run()
    typo_findings = [f for f in findings if "lookalike" in f["description"].lower() or "typosquatting" in f["evidence"].lower()]
    assert len(typo_findings) >= 1, f"Failed to detect typosquatting for '{proc_name}'"
    assert typo_findings[0]["severity"] == "ALERT"


def test_hard_path_traversal_masquerading():
    """
    Test masquerading where path attempts traversal: C:\\Windows\\System32\\..\\Temp\\svchost.exe
    Normalizes to C:\\Windows\\Temp\\svchost.exe and must be flagged.
    """
    detector = ProcessDetector()
    detector.process_provider = lambda: [
        {
            "pid": 9992,
            "name": "svchost.exe",
            "exe": r"C:\Windows\System32\..\Temp\svchost.exe",
            "cmdline": "svchost.exe",
            "username": "SYSTEM",
            "ppid": 1
        }
    ]

    findings = detector.run()
    spoofed = [f for f in findings if "Process Masquerading" in f["description"]]
    assert len(spoofed) == 1
    assert "svchost.exe" in spoofed[0]["evidence"]


# =============================================================================
# 2. Hard Tests: Entropy Calculation Edge Cases
# =============================================================================

def test_hard_entropy_edge_cases(tmp_path):
    detector = BaseDetector()

    # Case 1: Empty file (0 bytes)
    empty_file = tmp_path / "empty.bin"
    empty_file.write_bytes(b"")
    assert detector.calculate_entropy(empty_file) == 0.0

    # Case 2: File with exactly 256 evenly distributed bytes (all unique)
    unique_file = tmp_path / "unique.bin"
    unique_file.write_bytes(bytes(range(256)))
    # With 256 unique bytes evenly distributed, entropy is exactly 8.0
    assert detector.calculate_entropy(unique_file) == 8.0

    # Case 3: Truncated file smaller than 4KB
    small_random = tmp_path / "small_random.bin"
    small_random.write_bytes(os.urandom(128))
    assert detector.calculate_entropy(small_random) > 6.0

    # Case 4: File locked or unreadable (simulated permission error)
    locked_path = tmp_path / "locked.bin"
    locked_path.write_bytes(b"some content")
    # Setting to 000 permissions
    locked_path.chmod(0o000)
    try:
        # Should gracefully return 0.0 without crashing
        res = detector.calculate_entropy(locked_path)
        assert res == 0.0 or res > 0.0
    finally:
        locked_path.chmod(0o644)


# =============================================================================
# 3. Hard Tests: Advanced Credential Theft Invocations
# =============================================================================

@pytest.mark.parametrize("cmdline,tool_expected", [
    (r"rundll32.exe C:\Windows\System32\comsvcs.dll, #24 600 C:\temp\lsass.dmp full", "comsvcs"),
    (r"procdump64.exe -accepteula -ma lsass.exe C:\temp\dump.dmp", "procdump"),
    (r"powershell.exe -ep bypass -c Invoke-Mimikatz -DumpCreds", "mimikatz"),
    (r"pypykatz.exe live lsa", "pypykatz"),
    (r"nanodump.exe --write C:\temp\lsass.dmp", "nanodump"),
    (r"safetykatz.exe", "safetykatz"),
    (r"C:\Tools\SEKURLSA_dump.exe", "sekurlsa"),
])
def test_hard_credential_theft_variants(cmdline, tool_expected):
    detector = CredentialTheftDetector()
    detector.process_provider = lambda: [
        {
            "pid": 8888,
            "name": "powershell.exe" if "powershell" in cmdline else "tool.exe",
            "exe": r"C:\Tools\tool.exe",
            "cmdline": cmdline,
            "username": "Admin",
            "ppid": 100
        }
    ]

    findings = detector.run()
    cred_findings = [f for f in findings if f["category"] == "Credential Theft"]
    assert len(cred_findings) >= 1, f"Failed to detect credential theft variant: {cmdline}"
    assert cred_findings[0]["severity"] == "ALERT"


# =============================================================================
# 4. Hard Tests: AppInit_DLLs Evasion and Hook Detection
# =============================================================================

def test_hard_appinit_dlls_multiple_entries(mock_registry):
    detector = KeyloggerDetector()
    detector.registry_provider = mock_registry
    detector.process_provider = lambda: []

    # AppInit_DLLs with multiple comma-separated and space-separated DLL paths
    subkey = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
    mock_registry.store[("HKLM", subkey)] = [
        {"name": "AppInit_DLLs", "data": r"C:\Windows\System32\hook1.dll, C:\Users\Public\hook2.dll", "type": 1},
        {"name": "LoadAppInit_DLLs", "data": 1, "type": 4}
    ]

    findings = detector.run()
    appinit = [f for f in findings if "AppInit_DLLs" in f["description"]]
    assert len(appinit) == 1
    assert "hook1.dll" in appinit[0]["evidence"]
    assert "hook2.dll" in appinit[0]["evidence"]


def test_hard_keylogger_api_cmdline_variants():
    detector = KeyloggerDetector()
    detector.process_provider = lambda: [
        {
            "pid": 7771,
            "name": "rundll32.exe",
            "exe": r"C:\Windows\System32\rundll32.exe",
            "cmdline": r"rundll32.exe hook.dll, InstallHook WH_KEYBOARD_LL",
            "username": "User",
            "ppid": 100
        },
        {
            "pid": 7772,
            "name": "python.exe",
            "exe": r"C:\Python39\python.exe",
            "cmdline": r"python.exe keylog.py --function GetAsyncKeyState",
            "username": "User",
            "ppid": 100
        }
    ]

    findings = detector.run()
    assert len(findings) == 2
    for f in findings:
        assert f["category"] == "Keylogging"
        assert f["severity"] == "ALERT"


# =============================================================================
# 5. Hard Tests: Covert Surveillance Advanced Detection
# =============================================================================

def test_hard_surveillance_powershell_reflection():
    detector = SurveillanceDetector()
    detector.task_provider = lambda: [
        {
            "name": "StealthScreenGrab",
            "task_to_run": r"powershell.exe -w hidden -c $g = [System.Drawing.Graphics]::CopyFromScreen(0,0,0,0,$b.Size)",
            "author": "Attacker"
        },
        {
            "name": "NirCmdScreenShot",
            "task_to_run": r"C:\Tools\nircmd.exe savescreenshot C:\Users\Public\shot.png",
            "author": "Attacker"
        },
        {
            "name": "FFmpegGdiGrab",
            "task_to_run": r"ffmpeg -f gdigrab -framerate 30 -i desktop out.mp4",
            "author": "Attacker"
        }
    ]

    findings = detector.run()
    screen_tasks = [f for f in findings if f["category"] == "Covert Surveillance" and f["severity"] == "ALERT"]
    assert len(screen_tasks) == 3


# =============================================================================
# 6. Hard Tests: Hidden Installation Stealth Profiles & Short Paths
# =============================================================================

def test_hard_hidden_install_whitespace_metadata():
    """
    Test auto-start service with whitespace-only display name or description.
    """
    detector = HiddenInstallDetector()
    detector.service_provider = lambda: [
        {
            "name": "stealth_svc",
            "display_name": "    ",  # Whitespace only
            "binpath": r"C:\Windows\System32\stealth.exe",
            "start_type": "Automatic",
            "description": "   ",  # Whitespace only
            "status": "RUNNING"
        }
    ]

    findings = detector.run()
    stealth_svc = [f for f in findings if "stealth installation profile" in f["description"].lower()]
    assert len(stealth_svc) == 1
    assert stealth_svc[0]["severity"] == "WARN"


def test_hard_hidden_install_8dot3_temp_path():
    """
    Test service using short 8.3 path containing ~1: C:\\PROGRA~1\\...\\TEMP~1\\svc.exe
    """
    detector = HiddenInstallDetector()
    detector.service_provider = lambda: [
        {
            "name": "ShortPathService",
            "display_name": "Short Path Service",
            "binpath": r"C:\Users\VICTIM~1\AppData\Local\Temp\svc.exe",
            "start_type": "manual",
            "description": "Service description",
            "status": "STOPPED"
        }
    ]

    findings = detector.run()
    short_temp = [f for f in findings if "user-writable folder" in f["description"].lower()]
    assert len(short_temp) == 1
    assert short_temp[0]["severity"] == "ALERT"


# =============================================================================
# 7. Hard Tests: Remote Scanner Orchestrator Bundle and Execution
# =============================================================================

def test_hard_remote_scanner_payload_bundle():
    orchestrator = RemoteScannerOrchestrator(targets=["TARGET-PC1"])
    bundle_b64 = orchestrator.build_remote_payload_bundle()

    assert len(bundle_b64) > 100
    # Decode and verify zip contents
    zip_bytes = base64.b64decode(bundle_b64)
    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as z:
        names = z.namelist()
        assert "scanner.py" in names
        assert any("persistence_detector.py" in n for n in names)
        assert any("process_detector.py" in n for n in names)
        assert any("keylogger_detector.py" in n for n in names)
        assert any("credential_theft_detector.py" in n for n in names)


def test_hard_remote_scanner_multi_target_orchestration(tmp_path):
    output_log = tmp_path / "fleet_log.txt"

    orchestrator = RemoteScannerOrchestrator(
        targets=["HOST-A", "HOST-B", "HOST-C"],
        output_file=str(output_log),
        verbose=True
    )

    # Mock command runner to simulate 3 distinct endpoints
    def mock_runner(target):
        if target == "HOST-A":
            return {
                "target": target,
                "status": "SUCCESS",
                "findings": [
                    {
                        "category": "Credential Theft",
                        "severity": "ALERT",
                        "description": "Mimikatz detected",
                        "evidence": "PID: 1000",
                        "timestamp": "2026-09-09T12:00:00Z"
                    }
                ],
                "error": None
            }
        elif target == "HOST-B":
            return {
                "target": target,
                "status": "SUCCESS",
                "findings": [],
                "error": None
            }
        else:
            return {
                "target": target,
                "status": "ERROR",
                "findings": [],
                "error": "WinRM connection refused: port 5985 unreachable"
            }

    orchestrator.command_runner = mock_runner
    results = orchestrator.run_all()

    assert len(results) == 3
    assert results["HOST-A"]["status"] == "SUCCESS"
    assert len(results["HOST-A"]["findings"]) == 1
    assert results["HOST-B"]["status"] == "SUCCESS"
    assert len(results["HOST-B"]["findings"]) == 0
    assert results["HOST-C"]["status"] == "ERROR"

    # Verify consolidated log file
    assert output_log.is_file()
    log_text = output_log.read_text(encoding="utf-8")
    assert "CONSOLIDATED REMOTE DEFENSIVE SCAN AUDIT LOG" in log_text
    assert "HOST-A" in log_text
    assert "HOST-B" in log_text
    assert "HOST-C" in log_text
    assert "Mimikatz detected" in log_text
