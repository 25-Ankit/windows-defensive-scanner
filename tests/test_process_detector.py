"""
Unit tests for ProcessDetector.
"""

import pytest
from detectors.process_detector import ProcessDetector


def test_process_spoofing_masquerade():
    detector = ProcessDetector()

    detector.process_provider = lambda: [
        {
            "pid": 2048,
            "name": "svchost.exe",
            "exe": r"C:\Users\Attacker\AppData\Local\Temp\svchost.exe",
            "cmdline": r"C:\Users\Attacker\AppData\Local\Temp\svchost.exe",
            "username": "Attacker",
            "ppid": 1000
        },
        {
            "pid": 2050,
            "name": "svchost.exe",
            "exe": r"C:\Windows\System32\svchost.exe",
            "cmdline": r"C:\Windows\System32\svchost.exe -k netsvcs",
            "username": "NT AUTHORITY\\SYSTEM",
            "ppid": 600
        }
    ]

    findings = detector.run()
    spoofed = [f for f in findings if "Process Masquerading" in f["description"]]
    assert len(spoofed) == 1
    assert "2048" in spoofed[0]["evidence"]
    assert "2050" not in spoofed[0]["evidence"]


def test_suspicious_keywords_in_name_or_cmdline():
    detector = ProcessDetector()

    detector.process_provider = lambda: [
        {
            "pid": 3001,
            "name": "keylogger_v2.exe",
            "exe": r"C:\Tools\keylogger_v2.exe",
            "cmdline": r"keylogger_v2.exe --stealth",
            "username": "User",
            "ppid": 100
        },
        {
            "pid": 3002,
            "name": "powershell.exe",
            "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "cmdline": r"powershell.exe -w hidden -enc JABiAGUAYQBjAG8AbgA= --rat-inject",
            "username": "User",
            "ppid": 3001
        }
    ]

    findings = detector.run()
    kw_findings = [f for f in findings if "suspicious malware indicators" in f["description"]]
    assert len(kw_findings) == 2


def test_high_entropy_detection(high_entropy_file, low_entropy_file):
    detector = ProcessDetector()

    detector.process_provider = lambda: [
        {
            "pid": 4001,
            "name": "packed_proc.exe",
            "exe": high_entropy_file,
            "cmdline": high_entropy_file,
            "username": "User",
            "ppid": 1
        },
        {
            "pid": 4002,
            "name": "plain_proc.exe",
            "exe": low_entropy_file,
            "cmdline": low_entropy_file,
            "username": "User",
            "ppid": 1
        }
    ]

    findings = detector.run()
    entropy_findings = [f for f in findings if "high entropy" in f["description"].lower()]
    assert len(entropy_findings) == 1
    assert high_entropy_file in entropy_findings[0]["evidence"]


def test_unsigned_binary_in_system32(monkeypatch):
    detector = ProcessDetector()

    # Mock signature checker to return unsigned status
    detector.signature_checker = lambda path: {"is_signed": False, "valid": False, "status": "NotSigned"}

    # Mock os.path.isfile to simulate that the binary exists in System32
    monkeypatch.setattr("os.path.isfile", lambda p: True)

    detector.process_provider = lambda: [
        {
            "pid": 5001,
            "name": "unsigned_sys.exe",
            "exe": r"C:\Windows\System32\unsigned_sys.exe",
            "cmdline": r"C:\Windows\System32\unsigned_sys.exe",
            "username": "SYSTEM",
            "ppid": 1
        }
    ]

    findings = detector.run()
    unsigned_findings = [f for f in findings if "Unsigned or untrusted binary" in f["description"]]
    assert len(unsigned_findings) == 1
    assert "5001" in unsigned_findings[0]["evidence"]

