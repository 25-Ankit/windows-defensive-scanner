"""
Unit tests for KeyloggerDetector.
"""

import pytest
from detectors.keylogger_detector import KeyloggerDetector


def test_appinit_dlls_detection(mock_registry):
    detector = KeyloggerDetector()
    detector.registry_provider = mock_registry
    detector.process_provider = lambda: []

    # Mock AppInit_DLLs entry
    subkey = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
    mock_registry.store[("HKLM", subkey)] = [
        {"name": "AppInit_DLLs", "data": r"C:\Windows\System32\injected_hook.dll", "type": 1},
        {"name": "LoadAppInit_DLLs", "data": 1, "type": 4}
    ]

    findings = detector.run()
    appinit_findings = [f for f in findings if "AppInit_DLLs" in f["description"]]
    assert len(appinit_findings) >= 1
    assert appinit_findings[0]["severity"] == "ALERT"
    assert "injected_hook.dll" in appinit_findings[0]["evidence"]


def test_appinit_dlls_empty_not_flagged(mock_registry):
    detector = KeyloggerDetector()
    detector.registry_provider = mock_registry

    subkey = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
    mock_registry.store[("HKLM", subkey)] = [
        {"name": "AppInit_DLLs", "data": "", "type": 1},
        {"name": "LoadAppInit_DLLs", "data": 0, "type": 4}
    ]

    findings = detector._check_appinit_dlls()
    assert len(findings) == 0


def test_process_keyboard_hook_cmdline():
    detector = KeyloggerDetector()

    detector.process_provider = lambda: [
        {
            "pid": 6001,
            "name": "powershell.exe",
            "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "cmdline": r"powershell.exe -c Add-Type -TypeDefinition '...SetWindowsHookEx...WH_KEYBOARD...'",
            "username": "User",
            "ppid": 100
        },
        {
            "pid": 6002,
            "name": "notepad.exe",
            "exe": r"C:\Windows\notepad.exe",
            "cmdline": r"notepad.exe",
            "username": "User",
            "ppid": 100
        }
    ]

    findings = detector.run()
    hook_cmd_findings = [f for f in findings if "keyboard hook" in f["description"].lower()]
    assert len(hook_cmd_findings) == 1
    assert "6001" in hook_cmd_findings[0]["evidence"]


def test_loaded_modules_hook_detection(monkeypatch):
    detector = KeyloggerDetector()

    detector.process_provider = lambda: [
        {
            "pid": 7001,
            "name": "explorer.exe",
            "exe": r"C:\Windows\explorer.exe",
            "cmdline": r"explorer.exe",
            "username": "User",
            "ppid": 1
        }
    ]

    # Mock enumerate_process_modules
    def mock_modules(pid):
        if pid == 7001:
            return [
                r"C:\Windows\System32\ntdll.dll",
                r"C:\Windows\System32\kernel32.dll",
                r"C:\Users\Public\GlobalKeyboardHook.dll",
                r"C:\Windows\System32\uxtheme.dll"  # in benign whitelist
            ]
        return []

    monkeypatch.setattr(detector, "enumerate_process_modules", mock_modules)

    findings = detector.run()
    mod_findings = [f for f in findings if "Suspicious hook/keylog module" in f["description"]]
    assert len(mod_findings) == 1
    assert "GlobalKeyboardHook.dll" in mod_findings[0]["evidence"]
