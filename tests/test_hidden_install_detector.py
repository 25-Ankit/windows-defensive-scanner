"""
Unit tests for HiddenInstallDetector.
"""

import pytest
from detectors.hidden_install_detector import HiddenInstallDetector


def test_service_in_temp_directory():
    detector = HiddenInstallDetector()

    detector.service_provider = lambda: [
        {
            "name": "TempPayloadService",
            "display_name": "Temporary Service",
            "binpath": r"C:\Windows\Temp\malicious_service.exe",
            "start_type": "manual",
            "description": "Legit sounding description",
            "status": "STOPPED"
        },
        {
            "name": "LegitService",
            "display_name": "Windows Defender",
            "binpath": r"C:\Program Files\Windows Defender\MsMpEng.exe",
            "start_type": "auto",
            "description": "Antivirus service",
            "status": "RUNNING"
        }
    ]

    findings = detector.run()
    temp_findings = [f for f in findings if "user-writable folder" in f["description"].lower()]
    assert len(temp_findings) == 1
    assert "TempPayloadService" in temp_findings[0]["evidence"]
    assert temp_findings[0]["severity"] == "ALERT"


def test_autostart_service_missing_metadata():
    detector = HiddenInstallDetector()

    detector.service_provider = lambda: [
        {
            "name": "stealth_implant",
            "display_name": "",  # Missing display name
            "binpath": r"C:\Windows\System32\implant.exe",
            "start_type": "Automatic",
            "description": "",  # Missing description
            "status": "RUNNING"
        },
        {
            "name": "NormalService",
            "display_name": "Normal Service Display",
            "binpath": r"C:\Program Files\Normal\service.exe",
            "start_type": "Automatic",
            "description": "Normal service description",
            "status": "RUNNING"
        }
    ]

    findings = detector.run()
    stealth_findings = [f for f in findings if "stealth installation profile" in f["description"].lower()]
    assert len(stealth_findings) == 1
    assert "stealth_implant" in stealth_findings[0]["evidence"]


def test_scheduled_task_in_user_directory():
    detector = HiddenInstallDetector()

    detector.task_provider = lambda: [
        {
            "name": "FakeGoogleUpdate",
            "task_to_run": r"C:\Users\Target\AppData\Roaming\Google\update_fake.exe --run",
            "author": "Google"
        }
    ]

    findings = detector.run()
    task_findings = [f for f in findings if "Scheduled task executes from a temporary" in f["description"]]
    assert len(task_findings) == 1
    assert "FakeGoogleUpdate" in task_findings[0]["evidence"]
    assert task_findings[0]["severity"] == "ALERT"
