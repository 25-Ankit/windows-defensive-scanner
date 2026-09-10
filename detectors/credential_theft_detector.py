"""
Credential Theft Detection Module for Windows Defensive Security Scanner.

Detects indicators of credential access and memory dumping:
- Process command lines invoking known credential dumpers (mimikatz, sekurlsa, procdump, etc.)
- Abuse of comsvcs.dll or rundll32 for lsass memory dumping
- Heuristic checks for processes targeting lsass.exe with elevated/debug privileges
"""

import os
import re
import logging
from typing import List, Dict, Any, Optional

from .base_detector import BaseDetector

try:
    import ctypes
    from ctypes import wintypes
except ImportError:
    ctypes = None
    wintypes = None


class CredentialTheftDetector(BaseDetector):
    """
    Scans for active credential dumping tools and suspicious access to lsass.exe memory.
    """

    KNOWN_DUMP_TOOLS = [
        "mimikatz",
        "sekurlsa",
        "wce",
        "pwdump",
        "fgdump",
        "procdump",
        "safetykatz",
        "nanodump",
        "sharpsecdump",
        "lazagne",
        "pypykatz",
        "dumpert",
        "gsecdump",
        "lsadump"
    ]

    # Windows API constants for OpenProcess
    PROCESS_VM_READ = 0x0010
    PROCESS_QUERY_INFORMATION = 0x0400

    def __init__(self, logger: Optional[logging.Logger] = None):
        super().__init__(logger=logger)
        self.lsass_tester = None  # Injectable hook for testing access heuristic

    def run(self) -> List[Dict[str, Any]]:
        """
        Execute credential theft detection across process arguments and LSASS memory access.
        """
        findings: List[Dict[str, Any]] = []

        self.logger.info("Scanning process command lines for credential dumping tools...")
        try:
            findings.extend(self._scan_process_cmdlines())
        except Exception as e:
            self.logger.warning("Error during process command lines scan: %s", e)

        self.logger.info("Executing LSASS access and privilege heuristic...")
        try:
            findings.extend(self._check_lsass_access_heuristic())
        except Exception as e:
            self.logger.warning("Error during LSASS heuristic evaluation: %s", e)

        return findings

    # -------------------------------------------------------------------------
    # Command Line Scanning for Credential Dumping Tools
    # -------------------------------------------------------------------------

    def _scan_process_cmdlines(self) -> List[Dict[str, Any]]:
        findings = []
        processes = self.enumerate_processes()

        for proc in processes:
            if not isinstance(proc, dict):
                continue

            raw_pid = proc.get("pid", 0)
            try:
                pid = int(raw_pid) if raw_pid is not None else 0
            except (ValueError, TypeError):
                pid = 0

            if pid == os.getpid():
                continue

            name = str(proc.get("name") or "").lower()
            cmdline = str(proc.get("cmdline") or "").lower()

            # Check 1: Known tool name in process name or command line
            matched_tools = []
            for tool in self.KNOWN_DUMP_TOOLS:
                if len(tool) <= 3:
                    if re.search(r'(?<![a-zA-Z0-9])' + re.escape(tool) + r'(?![a-zA-Z0-9])', f"{name} {cmdline}"):
                        matched_tools.append(tool)
                else:
                    if tool in name or tool in cmdline:
                        matched_tools.append(tool)

            if matched_tools:
                findings.append(self.create_finding(
                    category="Credential Theft",
                    severity="ALERT",
                    description=f"Known credential dumping tool identified: {matched_tools}",
                    evidence=f"PID: {pid} | Process: {proc.get('name')} | Cmdline: {proc.get('cmdline')} | Tool: {matched_tools}",
                    rule_id="RULE-CRED-TOOL",
                    process=proc.get("name"),
                    pid=pid,
                    path=proc.get("exe") or None,
                    recommendation="Isolate host immediately, investigate executing user account, and terminate dumping process."
                ))

            # Check 2: LSASS combined with dump / read / inject / minidump
            if "lsass" in cmdline:
                if any(kw in cmdline for kw in ("dump", "minidump", "read", "inject", "sekurlsa", "logonpasswords")):
                    findings.append(self.create_finding(
                        category="Credential Theft",
                        severity="ALERT",
                        description="Process command line targets LSASS with memory dumping or reading syntax",
                        evidence=f"PID: {pid} | Process: {proc.get('name')} | Cmdline: {proc.get('cmdline')}",
                        rule_id="RULE-CRED-LSASS-SYNTAX",
                        process=proc.get("name"),
                        pid=pid,
                        path=proc.get("exe") or None,
                        recommendation="Terminate process targeting LSASS memory, capture triage memory image, and audit security events."
                    ))

            # Check 3: Built-in LOLBAS comsvcs.dll minidump abuse:
            # rundll32.exe comsvcs.dll, #24 or MiniDump
            if "comsvcs" in cmdline and ("minidump" in cmdline or "#24" in cmdline):
                findings.append(self.create_finding(
                    category="Credential Theft",
                    severity="ALERT",
                    description="Native LOLBAS abuse detected: comsvcs.dll used to dump memory (likely LSASS)",
                    evidence=f"PID: {pid} | Process: {proc.get('name')} | Cmdline: {proc.get('cmdline')}",
                    rule_id="RULE-CRED-COMSVCS-LOLBAS",
                    process=proc.get("name"),
                    pid=pid,
                    path=proc.get("exe") or None,
                    recommendation="Investigate comsvcs minidump invocation, identify destination dump file, and terminate process."
                ))

        return findings

    # -------------------------------------------------------------------------
    # LSASS Access & Privilege Heuristic
    # -------------------------------------------------------------------------

    def _check_lsass_access_heuristic(self) -> List[Dict[str, Any]]:
        findings = []

        # If a custom tester is injected (for unit/integration testing)
        if callable(self.lsass_tester):
            custom_result = self.lsass_tester()
            if custom_result:
                findings.extend(custom_result)
            return findings

        # Heuristic requires administrative privileges
        if not self.is_admin():
            self.logger.debug("Skipping LSASS access heuristic: requires administrative privileges")
            return findings

        if not ctypes or not hasattr(ctypes, "windll"):
            return findings

        # Find lsass.exe process
        processes = self.enumerate_processes()
        lsass_proc = None
        for p in processes:
            if (p.get("name") or "").lower() == "lsass.exe":
                lsass_proc = p
                break

        if not lsass_proc:
            return findings

        lsass_pid = lsass_proc.get("pid", 0)
        if not lsass_pid:
            return findings

        try:
            # Enable SeDebugPrivilege in current token if possible
            self._enable_debug_privilege()

            # Attempt to open handle to lsass.exe with PROCESS_VM_READ and PROCESS_QUERY_INFORMATION
            # If our process can open it, it verifies administrative/debug access is functional.
            # Next, inspect other non-system processes that might be accessing or holding handles.
            h_process = ctypes.windll.kernel32.OpenProcess(
                self.PROCESS_VM_READ | self.PROCESS_QUERY_INFORMATION,
                False,
                lsass_pid
            )

            if h_process:
                ctypes.windll.kernel32.CloseHandle(h_process)
                # Verify if any non-system process is running with SeDebugPrivilege or interacting with LSASS
                for proc in processes:
                    p_name = (proc.get("name") or "").lower()
                    p_cmd = (proc.get("cmdline") or "").lower()
                    p_pid = proc.get("pid", 0)

                    # Check for suspicious non-system processes associated with scripting/execution
                    if p_name in ("powershell.exe", "pwsh.exe", "cmd.exe", "rundll32.exe", "cscript.exe", "wscript.exe"):
                        if "lsass" in p_cmd or "debug" in p_cmd:
                            findings.append(self.create_finding(
                                category="Credential Theft",
                                severity="ALERT",
                                description=f"Suspicious script host '{p_name}' attempting access to LSASS with debug privileges",
                                evidence=f"PID: {p_pid} | Process: {p_name} | Cmdline: {proc.get('cmdline')}",
                                rule_id="RULE-CRED-LSASS-ACCESS",
                                process=p_name,
                                pid=p_pid,
                                path=proc.get("exe") or None,
                                recommendation="Audit process permissions, revoke SeDebugPrivilege from non-administrative contexts, and terminate process."
                            ))

        except Exception as e:
            self.logger.debug("LSASS heuristic evaluation encountered error: %s", e)

        return findings

    def _enable_debug_privilege(self) -> bool:
        """
        Attempt to enable SeDebugPrivilege for the current process token.
        """
        if not ctypes or not hasattr(ctypes, "windll"):
            return False

        try:
            advapi32 = ctypes.windll.advapi32
            kernel32 = ctypes.windll.kernel32

            TOKEN_ADJUST_PRIVILEGES = 0x0020
            TOKEN_QUERY = 0x0008
            SE_PRIVILEGE_ENABLED = 0x00000002

            class LUID(ctypes.Structure):
                _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

            class LUID_AND_ATTRIBUTES(ctypes.Structure):
                _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

            class TOKEN_PRIVILEGES(ctypes.Structure):
                _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]

            h_token = wintypes.HANDLE()
            if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(h_token)):
                return False

            luid = LUID()
            if not advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
                kernel32.CloseHandle(h_token)
                return False

            tp = TOKEN_PRIVILEGES()
            tp.PrivilegeCount = 1
            tp.Privileges[0].Luid = luid
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

            success = advapi32.AdjustTokenPrivileges(h_token, False, ctypes.byref(tp), 0, None, None)
            kernel32.CloseHandle(h_token)
            return bool(success)
        except Exception:
            return False
