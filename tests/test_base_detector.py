"""
Unit tests for BaseDetector class and utility methods.
"""

import os
import pytest
from detectors.base_detector import BaseDetector


def test_calculate_entropy_low_and_high(low_entropy_file, high_entropy_file):
    detector = BaseDetector()

    # All zeros should have 0.0 entropy
    low_h = detector.calculate_entropy(low_entropy_file)
    assert low_h == 0.0

    # Random bytes should have entropy > 7.5 (close to 8.0)
    high_h = detector.calculate_entropy(high_entropy_file)
    assert high_h > 7.5
    assert high_h <= 8.0

    # In-memory byte array
    assert detector.calculate_entropy(b"") == 0.0
    assert detector.calculate_entropy(b"A" * 100) == 0.0
    assert detector.calculate_entropy(os.urandom(1024)) > 7.0

    # Non-existent file
    assert detector.calculate_entropy("C:\\non_existent_file_path_xyz.exe") == 0.0


def test_create_finding():
    detector = BaseDetector()
    finding = detector.create_finding(
        category="Persistence",
        severity="alert",
        description="Suspicious run key detected",
        evidence="HKCU\\Run\\evil -> C:\\Temp\\evil.exe"
    )

    assert finding["category"] == "Persistence"
    assert finding["severity"] == "ALERT"
    assert finding["description"] == "Suspicious run key detected"
    assert "evil.exe" in finding["evidence"]
    assert "T" in finding["timestamp"]  # ISO-8601 format check

    # Test severity coercion
    invalid_sev_finding = detector.create_finding("Test", "invalid_level", "desc", "evid")
    assert invalid_sev_finding["severity"] == "WARN"


def test_extract_file_path():
    detector = BaseDetector()

    # Quoted path with arguments
    cmd1 = r'"C:\Program Files\Vendor\app.exe" --silent -v'
    assert detector.extract_file_path(cmd1) == r"C:\Program Files\Vendor\app.exe"

    # Unquoted simple command
    cmd2 = r"C:\Windows\System32\cmd.exe /c start"
    assert detector.extract_file_path(cmd2) == r"C:\Windows\System32\cmd.exe"

    # Empty command
    assert detector.extract_file_path("") is None
    assert detector.extract_file_path(None) is None


def test_is_temp_or_user_writable():
    detector = BaseDetector()

    assert detector.is_temp_or_user_writable(r"C:\Windows\Temp\payload.exe") is True
    assert detector.is_temp_or_user_writable(r"C:\Users\JohnDoe\AppData\Local\Temp\malware.exe") is True
    assert detector.is_temp_or_user_writable(r"C:\Users\Public\test.exe") is True
    assert detector.is_temp_or_user_writable(r"%TEMP%\script.vbs") is True

    # Legitimate system directories
    assert detector.is_temp_or_user_writable(r"C:\Windows\System32\svchost.exe") is False
    assert detector.is_temp_or_user_writable(r"C:\Program Files\App\service.exe") is False


def test_is_standard_system_path():
    detector = BaseDetector()

    assert detector.is_standard_system_path(r"C:\Windows\System32\cmd.exe") is True
    assert detector.is_standard_system_path(r"C:\Program Files\Git\bin\bash.exe") is True
    assert detector.is_standard_system_path(r"C:\Program Files (x86)\Common\lib.dll") is True

    assert detector.is_standard_system_path(r"C:\Users\User\app.exe") is False
    assert detector.is_standard_system_path(r"D:\Tools\mimikatz.exe") is False
