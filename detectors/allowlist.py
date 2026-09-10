"""
Centralized Allowlist and False Positive Reduction Mechanism.

Provides standardized allowlists for legitimate Windows system components,
approved software, benign development tools, and known legitimate services.

Design Principles:
1. Context-Aware: An allowlisted name is NOT exempt if running from an untrusted,
   temporary, or user-writable directory (prevents masquerading bypass).
2. Centralized: All detectors query this module rather than maintaining fragmented sets.
3. Extensible: Supports programmatic registration and resetting for custom environments and tests.
"""

import os
import re
from typing import Set, Optional, Dict, Any
from pathlib import PureWindowsPath


# Legitimate core Windows system binaries and their expected canonical locations
CORE_SYSTEM_BINARIES: Dict[str, Set[str]] = {
    "svchost.exe": {"c:\\windows\\system32\\svchost.exe", "c:\\windows\\syswow64\\svchost.exe"},
    "lsass.exe": {"c:\\windows\\system32\\lsass.exe"},
    "csrss.exe": {"c:\\windows\\system32\\csrss.exe"},
    "winlogon.exe": {"c:\\windows\\system32\\winlogon.exe"},
    "services.exe": {"c:\\windows\\system32\\services.exe"},
    "smss.exe": {"c:\\windows\\system32\\smss.exe"},
    "wininit.exe": {"c:\\windows\\system32\\wininit.exe"},
    "spoolsv.exe": {"c:\\windows\\system32\\spoolsv.exe"},
    "taskhostw.exe": {"c:\\windows\\system32\\taskhostw.exe"},
    "conhost.exe": {"c:\\windows\\system32\\conhost.exe"},
    "explorer.exe": {"c:\\windows\\explorer.exe", "c:\\windows\\syswow64\\explorer.exe"},
}

# Standard benign third-party software (browsers, editors, virtualization, IT tools)
DEFAULT_BENIGN_PROCESSES: Set[str] = {
    # Browsers
    "chrome.exe", "chrome",
    "msedge.exe", "msedge",
    "firefox.exe", "firefox",
    "brave.exe", "brave",
    "chrome_crashpad_handler",

    # Editors & IDEs
    "code.exe", "code",
    "devenv.exe",
    "notepad.exe",
    "notepad++.exe",

    # Windows Administrative & Remote Utilities
    "mstsc.exe",            # Microsoft Remote Desktop Connection
    "rdpclip.exe",          # RDP Clipboard synchronization
    "dwm.exe",              # Desktop Window Manager
    "perfmon.exe",          # Performance Monitor
    "resmon.exe",           # Resource Monitor
    "taskmgr.exe",          # Task Manager
    "wmiapsrv.exe",         # WMI Performance Adapter
    "msiexec.exe",          # Windows Installer
    "dllhost.exe",          # COM Surrogate

    # Virtualization Guest Services
    "vmware-vmx.exe",
    "vmtoolsd.exe",
    "vboxservice.exe",
    "vboxtray.exe",
}

# Known legitimate Windows services associated with networking, RPC, remote administration, and display
DEFAULT_BENIGN_SERVICES: Set[str] = {
    "termservice",          # Remote Desktop Services
    "sessionenv",           # Remote Desktop Configuration
    "umrdpservice",         # Remote Desktop Device Redirector
    "dispbrokerdesktopsvc", # Remote Desktop Display Broker
    "lanmanserver",         # Server service (SMB)
    "lanmanworkstation",    # Workstation service (SMB client)
    "remoteregistry",       # Remote Registry service
    "rpcss",                # Remote Procedure Call
    "rpclocator",           # RPC Locator
    "remoteaccess",         # Routing and Remote Access
    "winrm",                # Windows Remote Management
    "rpcendpointmapper",    # RPC Endpoint Mapper
    "dcomlaunch",           # DCOM Server Process Launcher
    "bthserv",              # Bluetooth Support Service
    "eventlog",             # Windows Event Log
    "netman",               # Network Connections
    "dnscache",             # DNS Client
    "dhcp",                 # DHCP Client
    "spoolsv",              # Print Spooler
    "wuauserv",             # Windows Update
    "windefend",            # Microsoft Defender Antivirus
    "mpssvc",               # Windows Defender Firewall
    "bfe",                  # Base Filtering Engine
    "wsearch",              # Windows Search
}

# Known benign system DLLs that may contain 'hook' in their filename or routines
DEFAULT_BENIGN_DLLS: Set[str] = {
    "userenv.dll",
    "uxtheme.dll",
    "ntdll.dll",
    "kernel32.dll",
    "user32.dll",
    "gdi32.dll",
    "shell32.dll",
    "ole32.dll",
    "advapi32.dll",
    "ws2_32.dll",
    "msvcrt.dll",
    "comctl32.dll",
    "shlwapi.dll",
}

# Runtime custom registrations
_CUSTOM_BENIGN_PROCESSES: Set[str] = set()
_CUSTOM_BENIGN_SERVICES: Set[str] = set()
_CUSTOM_BENIGN_DLLS: Set[str] = set()


def register_benign_process(name: str) -> None:
    """Register a custom process name as benign."""
    if name:
        _CUSTOM_BENIGN_PROCESSES.add(name.lower().strip())


def register_benign_service(name: str) -> None:
    """Register a custom service name as benign."""
    if name:
        _CUSTOM_BENIGN_SERVICES.add(name.lower().strip())


def register_benign_dll(name: str) -> None:
    """Register a custom DLL name as benign."""
    if name:
        _CUSTOM_BENIGN_DLLS.add(name.lower().strip())


def reset_custom_allowlists() -> None:
    """Reset all runtime custom allowlist additions."""
    _CUSTOM_BENIGN_PROCESSES.clear()
    _CUSTOM_BENIGN_SERVICES.clear()
    _CUSTOM_BENIGN_DLLS.clear()


def is_user_writable_path(path: str) -> bool:
    """
    Check whether a path resides in user-writable or temporary locations.
    Allowlists will NEVER exempt a binary running from these locations.
    """
    if not path:
        return False
    norm = os.path.normpath(str(path)).lower().replace("/", "\\")
    user_indicators = [
        "\\temp\\", "\\tmp\\", "\\appdata\\", "\\users\\public\\",
        "\\downloads\\", "\\desktop\\", "%temp%", "%tmp%", "%appdata%"
    ]
    if any(ind in norm for ind in user_indicators):
        return True
    if norm.startswith("c:\\users\\") or "\\users\\" in norm:
        return True
    return False


def is_allowlisted_process(name: str, exe_path: Optional[str] = None) -> bool:
    """
    Check if a process is on the legitimate software allowlist.

    CRITICAL SECURITY CHECK:
    If exe_path is provided and resides in a temporary or user-writable directory
    (%TEMP%, %APPDATA%, C:\\Users\\*), this function returns False even if the process
    name matches a benign entry (preventing process masquerading bypasses).
    """
    if not name:
        return False

    clean_name = PureWindowsPath(name.strip('"\';, ')).name.lower()

    # Never allowlist if executing from temporary or user-writable locations
    if exe_path and is_user_writable_path(exe_path):
        return False

    # Check against core system binaries (must be in canonical path if path is supplied)
    if clean_name in CORE_SYSTEM_BINARIES:
        if exe_path:
            norm_exe = os.path.normpath(os.path.expandvars(exe_path.strip('"\''))).lower().replace("/", "\\")
            return norm_exe in CORE_SYSTEM_BINARIES[clean_name]
        return True

    if clean_name in DEFAULT_BENIGN_PROCESSES or clean_name in _CUSTOM_BENIGN_PROCESSES:
        return True

    return False


def is_allowlisted_service(name: str, binpath: Optional[str] = None) -> bool:
    """
    Check if a Windows service is recognized as standard and benign.
    Never allowlists services executing from user-writable paths.
    """
    if not name:
        return False

    clean_name = name.lower().strip()

    if binpath and is_user_writable_path(binpath):
        return False

    if clean_name in DEFAULT_BENIGN_SERVICES or clean_name in _CUSTOM_BENIGN_SERVICES:
        return True

    return False


def is_allowlisted_dll(module_path_or_name: str) -> bool:
    """
    Check if a loaded module or DLL is a recognized benign system library.
    """
    if not module_path_or_name:
        return False

    clean_base = PureWindowsPath(module_path_or_name.strip('"\';, ')).name.lower()

    if clean_base in DEFAULT_BENIGN_DLLS or clean_base in _CUSTOM_BENIGN_DLLS:
        return True

    return False
