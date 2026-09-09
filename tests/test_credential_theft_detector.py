"""
Unit tests for CredentialTheftDetector.
"""

import pytest
from detectors.credential_theft_detector import CredentialTheftDetector


def test_known_dumping_tools_cmdline():
    detector = CredentialTheftDetector()

    detector.process_provider = lambda: [
        {
            "pid": 8001,
            "name": "mimikatz.exe",
            "exe": r"C:\Tools\mimikatz.exe",
            "cmdline": r'"C:\Tools\mimikatz.exe" "privilege::debug" "sekurlsa::logonpasswords" exit',
            "username": "Admin",
            "ppid": 100
        },
        {
            "pid": 8002,
            "name": "procdump.exe",
            "exe": r"C:\Sysinternals\procdump.exe",
            "cmdline": r"procdump.exe -ma lsass.exe lsass.dmp",
            "username": "Admin",
            "ppid": 100
        },
        {
            "pid": 8003,
            "name": "rundll32.exe",
            "exe": r"C:\Windows\System32\rundll32.exe",
            "cmdline": r"rundll32.exe C:\windows\system32\comsvcs.dll, MiniDump 600 C:\temp\dump.bin full",
            "username": "Admin",
            "ppid": 100
        },
        {
            "pid": 8004,
            "name": "chrome.exe",
            "exe": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            "cmdline": r'"C:\Program Files\Google\Chrome\Application\chrome.exe" --profile-directory=Default',
            "username": "User",
            "ppid": 100
        }
    ]

    findings = detector.run()

    # Find mimikatz detection
    mimi = [f for f in findings if "mimikatz" in f["evidence"].lower()]
    assert len(mimi) >= 1
    assert mimi[0]["severity"] == "ALERT"

    # Find procdump detection
    procdump_found = [f for f in findings if "procdump" in f["evidence"].lower()]
    assert len(procdump_found) >= 1

    # Find comsvcs LOLBAS detection
    comsvcs_found = [f for f in findings if "comsvcs" in f["evidence"].lower()]
    assert len(comsvcs_found) >= 1

    # Ensure chrome was not flagged
    chrome_found = [f for f in findings if "chrome.exe" in f["evidence"].lower()]
    assert len(chrome_found) == 0


def test_lsass_heuristic_tester():
    detector = CredentialTheftDetector()

    # Provide custom mock tester for LSASS access heuristic
    detector.lsass_tester = lambda: [
        detector.create_finding(
            category="Credential Theft",
            severity="ALERT",
            description="Suspicious process attempting access to LSASS with debug privileges",
            evidence="PID: 9001 | Target: lsass.exe (PID: 600) | Requested Access: PROCESS_VM_READ"
        )
    ]

    findings = detector.run()
    heuristic_alerts = [f for f in findings if "access to LSASS" in f["description"]]
    assert len(heuristic_alerts) == 1
    assert heuristic_alerts[0]["severity"] == "ALERT"
