"""
Unit tests for SurveillanceDetector.
"""

import pytest
from detectors.surveillance_detector import SurveillanceDetector


def test_surveillance_process_detection():
    detector = SurveillanceDetector()

    detector.process_provider = lambda: [
        {
            "pid": 9101,
            "name": "winvnc.exe",
            "exe": r"C:\Tools\winvnc.exe",
            "cmdline": r"winvnc.exe -run",
            "username": "User",
            "ppid": 100
        },
        {
            "pid": 9102,
            "name": "covert_screen_recorder.exe",
            "exe": r"C:\Users\Public\recorder.exe",
            "cmdline": r"recorder.exe --screen-capture --fps 30",
            "username": "User",
            "ppid": 100
        },
        {
            "pid": 9103,
            "name": "mstsc.exe",
            "exe": r"C:\Windows\System32\mstsc.exe",
            "cmdline": r"mstsc.exe /v:server01",
            "username": "User",
            "ppid": 100
        },
        {
            "pid": 9104,
            "name": "vmtoolsd.exe",
            "exe": r"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe",
            "cmdline": r"vmtoolsd.exe",
            "username": "SYSTEM",
            "ppid": 500
        }
    ]

    findings = detector.run()

    # VNC and screen recorder should be flagged
    vnc_findings = [f for f in findings if "winvnc" in f["evidence"].lower()]
    assert len(vnc_findings) >= 1

    recorder_findings = [f for f in findings if "covert_screen_recorder" in f["evidence"].lower()]
    assert len(recorder_findings) >= 1

    # Legitimate mstsc.exe and vmtoolsd.exe must NOT be flagged
    assert not any("mstsc.exe" in f["evidence"].lower() for f in findings)
    assert not any("vmtoolsd.exe" in f["evidence"].lower() for f in findings)


def test_scheduled_task_screen_capture():
    detector = SurveillanceDetector()

    detector.task_provider = lambda: [
        {
            "name": "PeriodicScreenGrabber",
            "task_to_run": r"powershell.exe -w hidden -c [Drawing.Graphics]::CopyFromScreen(0,0,0,0,$b.Size)",
            "author": "Hacker"
        },
        {
            "name": "StandardDiskDefrag",
            "task_to_run": r"defrag.exe C: -v",
            "author": "Microsoft"
        }
    ]

    findings = detector.run()
    task_findings = [f for f in findings if "screen capture" in f["description"].lower()]
    assert len(task_findings) == 1
    assert "PeriodicScreenGrabber" in task_findings[0]["evidence"]
    assert task_findings[0]["severity"] == "ALERT"
