"""
Shared Pytest Fixtures and Mock Data for Defensive Security Scanner.
"""

import os
import sys
import tempfile
import pytest
from pathlib import Path
from typing import Dict, Any, List

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


@pytest.fixture
def mock_registry():
    r"""
    In-memory registry mock store.
    Format:
    {
        ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"): [
            {"name": "BadEntry", "data": r"C:\Temp\malware.exe", "type": 1, "root": "HKLM", "subkey": "..."},
        ]
    }
    """
    store = {}

    def provider(root: str, subkey: str) -> List[Dict[str, Any]]:
        key = (root.upper(), subkey)
        return store.get(key, [])

    provider.store = store
    return provider


@pytest.fixture
def high_entropy_file(tmp_path):
    """
    Generates a 4KB file with high Shannon entropy (> 7.5) using pseudorandom bytes.
    """
    file_path = tmp_path / "packed_binary.exe"
    # os.urandom provides maximum entropy (~7.9+)
    random_bytes = os.urandom(4096)
    file_path.write_bytes(random_bytes)
    return str(file_path)


@pytest.fixture
def low_entropy_file(tmp_path):
    """
    Generates a 4KB file with low Shannon entropy (~0.0 to 1.0) using uniform bytes.
    """
    file_path = tmp_path / "plain_binary.exe"
    file_path.write_bytes(b"\x00" * 4096)
    return str(file_path)


@pytest.fixture
def sample_processes():
    """
    Sample process listing for test scenarios.
    """
    return [
        {
            "pid": 4,
            "name": "System",
            "exe": "",
            "cmdline": "",
            "username": "NT AUTHORITY\\SYSTEM",
            "ppid": 0
        },
        {
            "pid": 600,
            "name": "services.exe",
            "exe": r"C:\Windows\System32\services.exe",
            "cmdline": r"C:\Windows\System32\services.exe",
            "username": "NT AUTHORITY\\SYSTEM",
            "ppid": 500
        },
        {
            "pid": 800,
            "name": "svchost.exe",
            "exe": r"C:\Windows\System32\svchost.exe",
            "cmdline": r"C:\Windows\System32\svchost.exe -k netsvcs",
            "username": "NT AUTHORITY\\SYSTEM",
            "ppid": 600
        },
        {
            "pid": 1200,
            "name": "explorer.exe",
            "exe": r"C:\Windows\explorer.exe",
            "cmdline": r"C:\Windows\explorer.exe",
            "username": "DOMAIN\\User",
            "ppid": 1100
        }
    ]
