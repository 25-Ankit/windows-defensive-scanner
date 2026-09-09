"""
Base Detector Class for Windows Defensive Security Scanner.

Provides core abstractions, standardized finding generation, logging,
and shared helper methods (process enumeration, entropy calculation,
digital signature verification, registry querying, service and scheduled task enumeration).
"""

import os
import sys
import math
import shlex
import logging
import platform
import subprocess
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Union, Tuple
from pathlib import Path

# Attempt to import optional Windows-specific and third-party libraries
try:
    import psutil
except ImportError:
    psutil = None

try:
    import winreg
except ImportError:
    winreg = None

try:
    import wmi
except ImportError:
    wmi = None

try:
    import ctypes
except ImportError:
    ctypes = None


class BaseDetector:
    """
    Abstract base class for all security detection modules.

    All detectors must subclass BaseDetector and implement the run() method,
    returning a list of standardized finding dictionaries:
    {
        "category": str,
        "severity": str ("INFO", "WARN", "ALERT"),
        "description": str,
        "evidence": str,
        "timestamp": str (ISO 8601 UTC)
    }
    """

    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize the base detector with a logger and optional mock providers.
        """
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        # Configurable providers for unit testing and dependency injection
        self.process_provider = None
        self.registry_provider = None
        self.service_provider = None
        self.task_provider = None
        self.signature_checker = None

    def run(self) -> List[Dict[str, Any]]:
        """
        Execute the detection logic. Must be implemented by subclasses.
        Returns a list of finding dicts.
        """
        raise NotImplementedError("Each detector must implement the run() method.")

    # -------------------------------------------------------------------------
    # Finding & Logging Helpers
    # -------------------------------------------------------------------------

    def create_finding(
        self,
        category: str,
        severity: str,
        description: str,
        evidence: Any
    ) -> Dict[str, Any]:
        """
        Generate a standardized finding object.
        Severities:
            - INFO: Informational observation or low-risk anomaly.
            - WARN: Suspicious anomaly requiring analyst attention.
            - ALERT: High-confidence threat or indicator of malicious activity.
        """
        severity_clean = severity.upper().strip()
        if severity_clean not in ("INFO", "WARN", "ALERT"):
            severity_clean = "WARN"

        timestamp_str = datetime.now(timezone.utc).isoformat()
        return {
            "category": str(category),
            "severity": severity_clean,
            "description": str(description),
            "evidence": str(evidence),
            "timestamp": timestamp_str
        }

    # -------------------------------------------------------------------------
    # Privilege & Environment Checks
    # -------------------------------------------------------------------------

    def is_admin(self) -> bool:
        """
        Check if the current process is running with administrative privileges.
        """
        if platform.system() == "Windows":
            try:
                if ctypes and hasattr(ctypes, "windll"):
                    return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except (AttributeError, OSError):
                pass
            return False
        else:
            # POSIX fallback
            try:
                return os.geteuid() == 0
            except AttributeError:
                return False

    # -------------------------------------------------------------------------
    # Shannon Entropy Calculation
    # -------------------------------------------------------------------------

    def calculate_entropy(self, target: Union[str, bytes, Path], max_bytes: int = 4096) -> float:
        """
        Calculate the Shannon entropy of a byte stream or the first max_bytes of a file.
        Formula: H(X) = - SUM(P(x) * log2(P(x)))

        Entropy values range from 0.0 (uniform single byte) to 8.0 (purely random/encrypted).
        Executable files with entropy > 7.5 are typically packed, encrypted, or compressed,
        which is a strong indicator of AV evasion or packer use.
        """
        data: bytes = b""
        if isinstance(target, (str, Path)):
            path_obj = Path(str(target).strip('"'))
            try:
                if not path_obj.is_file():
                    return 0.0
                with open(path_obj, "rb") as f:
                    data = f.read(max_bytes)
            except (OSError, PermissionError):
                return 0.0
        elif isinstance(target, (bytes, bytearray)):
            data = bytes(target[:max_bytes])
        else:
            return 0.0

        if not data:
            return 0.0

        length = len(data)
        freq: Dict[int, int] = {}
        for byte_val in data:
            freq[byte_val] = freq.get(byte_val, 0) + 1

        entropy = 0.0
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)

        return round(entropy, 4)

    # -------------------------------------------------------------------------
    # Digital Signature Verification
    # -------------------------------------------------------------------------

    def check_digital_signature(self, file_path: str) -> Dict[str, Any]:
        """
        Verify the Authenticode digital signature of a Windows PE executable.
        Returns a dictionary with status, is_signed, and signer details.
        """
        # If a custom signature checker is injected (useful for tests)
        if callable(self.signature_checker):
            return self.signature_checker(file_path)

        clean_path = str(file_path).strip('"')
        result = {
            "file_path": clean_path,
            "is_signed": False,
            "valid": False,
            "signer": None,
            "status": "Unknown"
        }

        if not os.path.exists(clean_path):
            result["status"] = "FileNotFound"
            return result

        if platform.system() != "Windows":
            # Running in non-Windows test/dev environment
            result["status"] = "NotWindows"
            return result

        # Method 1: Use PowerShell Get-AuthenticodeSignature (reliable on Win 10/11)
        try:
            cmd = [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                f"(Get-AuthenticodeSignature -FilePath '{clean_path}') | Select-Object Status, @{{Name='Signer';Expression={{$_.SignerCertificate.Subject}}}} | ConvertTo-Json"
            ]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
                check=False
            )
            if proc.returncode == 0 and proc.stdout.strip():
                import json
                try:
                    data = json.loads(proc.stdout.strip())
                    status = str(data.get("Status", "Unknown"))
                    signer = data.get("Signer")
                    is_valid = status.lower() == "valid"
                    result["is_signed"] = status.lower() in ("valid", "hashmismatch", "nottrusted")
                    result["valid"] = is_valid
                    result["signer"] = signer
                    result["status"] = status
                    return result
                except json.JSONDecodeError:
                    pass
        except (subprocess.SubprocessError, OSError, FileNotFoundError):
            pass

        return result

    # -------------------------------------------------------------------------
    # Registry Helpers
    # -------------------------------------------------------------------------

    def read_registry_values(self, root_key_name: str, subkey: str) -> List[Dict[str, Any]]:
        """
        Read all values from a specified Windows registry key.
        Handles both 32-bit and 64-bit views.
        Returns a list of dicts: {"name": str, "data": Any, "type": int, "root": str, "subkey": str}
        """
        if callable(self.registry_provider):
            return self.registry_provider(root_key_name, subkey)

        if not winreg or platform.system() != "Windows":
            return []

        root_hkeys = {
            "HKLM": winreg.HKEY_LOCAL_MACHINE,
            "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
            "HKCU": winreg.HKEY_CURRENT_USER,
            "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
            "HKCR": winreg.HKEY_CLASSES_ROOT,
            "HKU": winreg.HKEY_USERS
        }

        hkey_root = root_hkeys.get(root_key_name.upper())
        if not hkey_root:
            return []

        entries: List[Dict[str, Any]] = []
        # Try both 64-bit and 32-bit registry views
        access_flags = [
            winreg.KEY_READ,
            winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0),
            winreg.KEY_READ | getattr(winreg, "KEY_WOW64_32KEY", 0)
        ]

        seen_names = set()
        for flags in access_flags:
            try:
                with winreg.OpenKey(hkey_root, subkey, 0, flags) as key:
                    index = 0
                    while True:
                        try:
                            val_name, val_data, val_type = winreg.EnumValue(key, index)
                            entry_id = (val_name, str(val_data))
                            if entry_id not in seen_names:
                                seen_names.add(entry_id)
                                entries.append({
                                    "name": val_name,
                                    "data": val_data,
                                    "type": val_type,
                                    "root": root_key_name,
                                    "subkey": subkey
                                })
                            index += 1
                        except OSError:
                            # Reached end of values
                            break
            except (FileNotFoundError, PermissionError, OSError):
                continue

        return entries

    # -------------------------------------------------------------------------
    # Process Enumeration Helpers
    # -------------------------------------------------------------------------

    def enumerate_processes(self) -> List[Dict[str, Any]]:
        """
        Enumerate all active running processes.
        Returns a list of dicts:
        {
            "pid": int,
            "name": str,
            "exe": str,
            "cmdline": str,
            "username": str,
            "ppid": int
        }
        """
        if callable(self.process_provider):
            return self.process_provider()

        processes: List[Dict[str, Any]] = []

        # Strategy 1: psutil (preferred, highly detailed)
        if psutil:
            for p in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username', 'ppid']):
                try:
                    info = p.info
                    cmd_list = info.get('cmdline') or []
                    cmd_str = " ".join(cmd_list) if isinstance(cmd_list, list) else str(cmd_list or "")
                    processes.append({
                        "pid": info.get('pid') or 0,
                        "name": str(info.get('name') or ""),
                        "exe": str(info.get('exe') or ""),
                        "cmdline": cmd_str,
                        "username": str(info.get('username') or ""),
                        "ppid": info.get('ppid') or 0
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            return processes

        # Strategy 2: WMI (if available on Windows)
        if wmi and platform.system() == "Windows":
            try:
                c = wmi.WMI()
                for p in c.Win32_Process():
                    processes.append({
                        "pid": int(p.ProcessId or 0),
                        "name": str(p.Name or ""),
                        "exe": str(p.ExecutablePath or ""),
                        "cmdline": str(p.CommandLine or ""),
                        "username": "",
                        "ppid": int(p.ParentProcessId or 0)
                    })
                return processes
            except Exception as e:
                self.logger.debug("WMI process enumeration failed: %s", e)

        # Strategy 3: tasklist CLI fallback on Windows
        if platform.system() == "Windows":
            try:
                proc = subprocess.run(
                    ["tasklist.exe", "/fo", "csv", "/v"],
                    capture_output=True,
                    text=True,
                    check=False
                )
                if proc.returncode == 0:
                    import csv
                    import io
                    reader = csv.reader(io.StringIO(proc.stdout))
                    header = next(reader, None)
                    for row in reader:
                        if len(row) >= 2:
                            processes.append({
                                "pid": int(row[1]) if row[1].isdigit() else 0,
                                "name": row[0],
                                "exe": "",
                                "cmdline": "",
                                "username": row[6] if len(row) > 6 else "",
                                "ppid": 0
                            })
                    return processes
            except Exception as e:
                self.logger.debug("tasklist fallback failed: %s", e)

        return processes

    def enumerate_process_modules(self, pid: int) -> List[str]:
        """
        Enumerate loaded modules (DLLs) for a given process PID.
        Returns a list of module paths/names.
        Requires administrative privileges for non-owned processes.
        """
        modules: List[str] = []
        if not psutil:
            return modules

        try:
            proc = psutil.Process(pid)
            # memory_maps() provides loaded DLLs on Windows
            m_maps = proc.memory_maps()
            for m in m_maps:
                path = getattr(m, 'path', '')
                if path and path not in modules:
                    modules.append(path)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, AttributeError, OSError):
            pass

        return modules

    # -------------------------------------------------------------------------
    # Service & Scheduled Task Enumeration Helpers
    # -------------------------------------------------------------------------

    def enumerate_services(self) -> List[Dict[str, Any]]:
        """
        Enumerate Windows services.
        Returns a list of dicts:
        {
            "name": str,
            "display_name": str,
            "binpath": str,
            "start_type": str,
            "description": str,
            "status": str
        }
        """
        if callable(self.service_provider):
            return self.service_provider()

        services: List[Dict[str, Any]] = []

        if platform.system() != "Windows":
            return services

        # Method 1: psutil win_service_iter
        if psutil and hasattr(psutil, "win_service_iter"):
            try:
                for s in psutil.win_service_iter():
                    try:
                        s_info = s.as_dict()
                        services.append({
                            "name": s_info.get("name", ""),
                            "display_name": s_info.get("display_name", ""),
                            "binpath": s_info.get("binpath", ""),
                            "start_type": s_info.get("start_type", ""),
                            "description": s_info.get("description", "") or "",
                            "status": s_info.get("status", "")
                        })
                    except Exception:
                        continue
                if services:
                    return services
            except Exception as e:
                self.logger.debug("psutil service enumeration error: %s", e)

        # Method 2: WMI Win32_Service
        if wmi:
            try:
                c = wmi.WMI()
                for s in c.Win32_Service():
                    services.append({
                        "name": str(s.Name or ""),
                        "display_name": str(s.DisplayName or ""),
                        "binpath": str(s.PathName or ""),
                        "start_type": str(s.StartMode or ""),
                        "description": str(s.Description or "") if s.Description else "",
                        "status": str(s.State or "")
                    })
                if services:
                    return services
            except Exception as e:
                self.logger.debug("WMI service enumeration error: %s", e)

        # Method 3: PowerShell fallback
        try:
            ps_cmd = [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-CimInstance Win32_Service | Select-Object Name, DisplayName, PathName, StartMode, Description, State | ConvertTo-Json"
            ]
            proc = subprocess.run(ps_cmd, capture_output=True, text=True, timeout=15, check=False)
            if proc.returncode == 0 and proc.stdout.strip():
                import json
                raw = json.loads(proc.stdout.strip())
                items = raw if isinstance(raw, list) else [raw]
                for s in items:
                    services.append({
                        "name": str(s.get("Name") or ""),
                        "display_name": str(s.get("DisplayName") or ""),
                        "binpath": str(s.get("PathName") or ""),
                        "start_type": str(s.get("StartMode") or ""),
                        "description": str(s.get("Description") or "") if s.get("Description") else "",
                        "status": str(s.get("State") or "")
                    })
        except Exception as e:
            self.logger.debug("PowerShell service enumeration error: %s", e)

        return services

    def enumerate_scheduled_tasks(self) -> List[Dict[str, Any]]:
        """
        Enumerate Windows Scheduled Tasks.
        Returns a list of dicts:
        {
            "name": str,
            "path": str,
            "task_to_run": str,
            "author": str,
            "state": str
        }
        """
        if callable(self.task_provider):
            return self.task_provider()

        tasks: List[Dict[str, Any]] = []

        if platform.system() != "Windows":
            return tasks

        # Method 1: schtasks.exe CLI
        try:
            proc = subprocess.run(
                ["schtasks.exe", "/query", "/fo", "csv", "/v"],
                capture_output=True,
                text=True,
                timeout=20,
                check=False
            )
            if proc.returncode == 0:
                import csv
                import io
                reader = csv.reader(io.StringIO(proc.stdout))
                header = next(reader, None)
                if header:
                    header_map = {col.strip().lower(): idx for idx, col in enumerate(header)}
                    name_idx = header_map.get("taskname")
                    action_idx = header_map.get("task to run")
                    author_idx = header_map.get("author")
                    status_idx = header_map.get("status")

                    for row in reader:
                        if not row:
                            continue
                        name = row[name_idx] if name_idx is not None and len(row) > name_idx else ""
                        action = row[action_idx] if action_idx is not None and len(row) > action_idx else ""
                        author = row[author_idx] if author_idx is not None and len(row) > author_idx else ""
                        status = row[status_idx] if status_idx is not None and len(row) > status_idx else ""
                        tasks.append({
                            "name": name,
                            "path": name,
                            "task_to_run": action,
                            "author": author,
                            "state": status
                        })
                return tasks
        except Exception as e:
            self.logger.debug("schtasks enumeration failed: %s", e)

        # Method 2: PowerShell fallback
        try:
            ps_cmd = [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-ScheduledTask | Select-Object TaskName, TaskPath, State, @{Name='Action';Expression={$_.Actions.Execute + ' ' + $_.Actions.Arguments}} | ConvertTo-Json"
            ]
            proc = subprocess.run(ps_cmd, capture_output=True, text=True, timeout=20, check=False)
            if proc.returncode == 0 and proc.stdout.strip():
                import json
                raw = json.loads(proc.stdout.strip())
                items = raw if isinstance(raw, list) else [raw]
                for t in items:
                    tasks.append({
                        "name": str(t.get("TaskName") or ""),
                        "path": str(t.get("TaskPath") or ""),
                        "task_to_run": str(t.get("Action") or "").strip(),
                        "author": "",
                        "state": str(t.get("State") or "")
                    })
        except Exception as e:
            self.logger.debug("PowerShell task enumeration failed: %s", e)

        return tasks

    # -------------------------------------------------------------------------
    # Path & Environment Heuristics
    # -------------------------------------------------------------------------

    def extract_file_path(self, command_str: str) -> Optional[str]:
        """
        Extract the primary executable file path from a command line string.
        Resolves environment variables like %SystemRoot%, %TEMP%, etc.
        Handles quoted paths, flags, and arguments using Windows command semantics.
        """
        if not command_str:
            return None

        cmd_clean = os.path.expandvars(command_str.strip())

        # If wrapped in quotes, extract string inside quotes
        if cmd_clean.startswith('"'):
            end_quote = cmd_clean.find('"', 1)
            if end_quote != -1:
                return cmd_clean[1:end_quote].strip()

        # Use posix=False so backslashes '\' are treated as path separators, not escape characters
        try:
            parts = shlex.split(cmd_clean, posix=False)
            if parts:
                return parts[0].strip('"\';,')
        except Exception:
            pass

        # Whitespace split fallback
        candidate = cmd_clean.split()[0]
        return candidate.strip('"\';,')

    def is_temp_or_user_writable(self, path: str) -> bool:
        """
        Determine whether a given file/folder path points to a temporary,
        user-writable, or non-standard directory commonly abused by malware.
        """
        if not path:
            return False

        norm = os.path.normpath(str(path)).lower()

        suspicious_keywords = [
            "\\temp\\",
            "\\tmp\\",
            "\\appdata\\",
            "\\users\\public\\",
            "\\programdata\\",
            "\\windows\\temp\\",
            "\\downloads\\",
            "\\desktop\\",
            "%temp%",
            "%tmp%",
            "%appdata%",
            "%localappdata%"
        ]

        # Expand current env vars to catch actual paths
        expanded_temp = os.path.normpath(os.path.expandvars("%TEMP%")).lower()
        expanded_appdata = os.path.normpath(os.path.expandvars("%APPDATA%")).lower()
        expanded_localappdata = os.path.normpath(os.path.expandvars("%LOCALAPPDATA%")).lower()

        # Check explicit paths
        for kw in suspicious_keywords:
            if kw in norm or norm.startswith(kw) or norm.endswith(kw.rstrip("\\")):
                return True

        if expanded_temp and expanded_temp in norm:
            return True
        if expanded_appdata and expanded_appdata in norm:
            return True
        if expanded_localappdata and expanded_localappdata in norm:
            return True

        # Check if path is under C:\Users\ (excluding legitimate default program directories)
        if norm.startswith("c:\\users\\") and "\\appdata\\" in norm:
            return True

        return False

    def is_standard_system_path(self, path: str) -> bool:
        """
        Check if a file resides within standard legitimate program/system directories.
        """
        if not path:
            return False

        norm = os.path.normpath(str(path)).lower()
        system_prefixes = [
            "c:\\windows",
            "c:\\program files",
            "c:\\program files (x86)"
        ]

        return any(norm.startswith(prefix) for prefix in system_prefixes)
