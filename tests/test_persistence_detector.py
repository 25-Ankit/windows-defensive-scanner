"""
Unit tests for PersistenceDetector.
"""

import os
import pytest
from detectors.persistence_detector import PersistenceDetector


def test_registry_run_key_non_existent_file(mock_registry):
    detector = PersistenceDetector()
    detector.registry_provider = mock_registry

    # Add a Run key pointing to a non-existent file
    mock_registry.store[("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run")] = [
        {"name": "GhostPayload", "data": r"C:\Windows\System32\definitely_non_existent_binary_12345.exe"}
    ]

    findings = detector.run()
    assert len(findings) >= 1
    found = any(
        f["category"] == "Persistence" and "non-existent file" in f["description"].lower()
        for f in findings
    )
    assert found is True


def test_registry_run_key_user_writable_path(mock_registry, tmp_path):
    detector = PersistenceDetector()
    detector.registry_provider = mock_registry

    # Create an actual file in a simulated temp path
    fake_temp_exe = tmp_path / "temp_payload.exe"
    fake_temp_exe.write_bytes(b"MZfakebinary")

    # Set mock registry to point to temp path
    mock_registry.store[("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run")] = [
        {"name": "TempPersist", "data": f"C:\\Users\\Victim\\AppData\\Local\\Temp\\temp_payload.exe"}
    ]

    findings = detector.run()
    alert_found = any(
        f["category"] == "Persistence" and f["severity"] == "ALERT" and "user-writable" in f["description"]
        for f in findings
    )
    assert alert_found is True


def test_startup_folder_non_shortcut_file(tmp_path):
    detector = PersistenceDetector()

    # Create a fake startup folder with a direct .exe, a script, and a valid .lnk
    startup_dir = tmp_path / "Startup"
    startup_dir.mkdir()

    direct_exe = startup_dir / "dropped_miner.exe"
    direct_exe.write_bytes(b"MZfakeexecutablecontent")

    direct_bat = startup_dir / "stealth_script.bat"
    direct_bat.write_text("powershell -enc ...")

    legit_lnk = startup_dir / "legit_app.lnk"
    legit_lnk.write_bytes(b"\x4c\x00\x00\x00")  # Windows Shell Link header (low entropy)

    desktop_ini = startup_dir / "desktop.ini"
    desktop_ini.write_text("[.ShellClassInfo]\nIconIndex=0")

    detector.startup_folders_override = [str(startup_dir)]

    findings = detector._scan_startup_folders()

    # Should detect direct_exe and direct_bat, but not legit_lnk or desktop.ini
    flagged_evidences = [f["evidence"] for f in findings]
    assert any("dropped_miner.exe" in ev for ev in flagged_evidences)
    assert any("stealth_script.bat" in ev for ev in flagged_evidences)
    assert not any("desktop.ini" in ev for ev in flagged_evidences)


def test_services_and_tasks_persistence():
    detector = PersistenceDetector()

    detector.service_provider = lambda: [
        {
            "name": "LegitSvc",
            "display_name": "Legitimate Service",
            "binpath": r"C:\Windows\System32\svchost.exe -k netsvcs",
            "status": "RUNNING"
        },
        {
            "name": "MaliciousSvc",
            "display_name": "Deceptive Service",
            "binpath": r"C:\Users\User\AppData\Local\Temp\evil_svc.exe",
            "status": "RUNNING"
        },
        {
            "name": "SpoofedSvc",
            "display_name": "Masquerading Svchost",
            "binpath": r"C:\Users\Public\svchost.exe",
            "status": "STOPPED"
        }
    ]

    detector.task_provider = lambda: [
        {
            "name": "CleanTask",
            "task_to_run": r"C:\Windows\System32\cleanmgr.exe /sagerun:1",
            "author": "Microsoft"
        },
        {
            "name": "SuspiciousTempTask",
            "task_to_run": r"C:\Users\Default\AppData\Roaming\update.exe",
            "author": "Attacker"
        }
    ]

    findings = detector.run()

    # Check that MaliciousSvc and SpoofedSvc are flagged
    service_alerts = [f for f in findings if "Service" in f["description"] or "mimics" in f["description"]]
    assert len(service_alerts) >= 2

    # Check that SuspiciousTempTask is flagged
    task_alerts = [f for f in findings if "Scheduled task" in f["description"]]
    assert len(task_alerts) >= 1
