"""
Keylogger Detection Module for Windows Defensive Security Scanner.

Detects indicators of keylogging and keyboard interception techniques:
- Presence and activation of AppInit_DLLs in Registry
- Suspicious loaded modules containing 'hook' or 'keylog'
- Process command lines invoking Windows keyboard hook APIs or keylogging routines
"""

import os
import re
import logging
from typing import List, Dict, Any, Optional

from .base_detector import BaseDetector


class KeyloggerDetector(BaseDetector):
    """
    Scans for AppInit_DLLs injection, hook-related DLLs, and keylogging command line patterns.
    """

    APPINIT_KEYS = [
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
        r"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows",
    ]

    KEYBOARD_HOOK_KEYWORDS = [
        "setwindowshookex",
        "wh_keyboard",
        "wh_keyboard_ll",
        "keyboard hook",
        "getasynckeystate",
        "getkeyboardstate",
        "registerrawinputdevices"
    ]

    # Whitelist legitimate system DLLs that might contain 'hook' in their name
    KNOWN_BENIGN_DLLS = {
        "userenv.dll",
        "uxtheme.dll"
    }

    def __init__(self, logger: Optional[logging.Logger] = None):
        super().__init__(logger=logger)

    def run(self) -> List[Dict[str, Any]]:
        """
        Execute keylogging detection routines.
        """
        findings: List[Dict[str, Any]] = []

        self.logger.info("Checking AppInit_DLLs registry entries...")
        findings.extend(self._check_appinit_dlls())

        self.logger.info("Scanning process command lines for keyboard hook keywords...")
        findings.extend(self._scan_process_hook_cmdlines())

        self.logger.info("Inspecting loaded modules for keyboard hook / keylogger libraries...")
        findings.extend(self._scan_loaded_modules())

        return findings

    # -------------------------------------------------------------------------
    # AppInit_DLLs Registry Check
    # -------------------------------------------------------------------------

    def _check_appinit_dlls(self) -> List[Dict[str, Any]]:
        findings = []

        for subkey in self.APPINIT_KEYS:
            entries = self.read_registry_values("HKLM", subkey)
            appinit_dlls = ""
            load_appinit = 0

            for entry in entries:
                name = entry.get("name", "")
                data = entry.get("data", "")
                if name.lower() == "appinit_dlls":
                    appinit_dlls = str(data).strip()
                elif name.lower() == "loadappinit_dlls":
                    try:
                        load_appinit = int(data)
                    except (ValueError, TypeError):
                        load_appinit = 0

            if appinit_dlls:
                findings.append(self.create_finding(
                    category="Keylogging",
                    severity="ALERT",
                    description="AppInit_DLLs registry entry is non-empty (DLL injection / global hooking mechanism)",
                    evidence=f"Registry Key: HKLM\\{subkey}\\AppInit_DLLs | Value: '{appinit_dlls}' | LoadAppInit_DLLs: {load_appinit}"
                ))

        return findings

    # -------------------------------------------------------------------------
    # Process Command Line Keyboard Hook Analysis
    # -------------------------------------------------------------------------

    def _scan_process_hook_cmdlines(self) -> List[Dict[str, Any]]:
        findings = []
        processes = self.enumerate_processes()

        for proc in processes:
            pid = proc.get("pid", 0)
            name = proc.get("name", "")
            cmdline = proc.get("cmdline", "")

            if not cmdline:
                continue

            cmd_lower = cmdline.lower()
            matched = [kw for kw in self.KEYBOARD_HOOK_KEYWORDS if kw in cmd_lower]

            if matched:
                findings.append(self.create_finding(
                    category="Keylogging",
                    severity="ALERT",
                    description=f"Process command line references keyboard hook / keylogger functions: {matched}",
                    evidence=f"PID: {pid} | Process: {name} | Cmdline: {cmdline} | Matched: {matched}"
                ))

        return findings

    # -------------------------------------------------------------------------
    # Loaded Module (DLL) Inspection
    # -------------------------------------------------------------------------

    def _scan_loaded_modules(self) -> List[Dict[str, Any]]:
        findings = []
        processes = self.enumerate_processes()

        for proc in processes:
            pid = proc.get("pid", 0)
            name = proc.get("name", "")
            modules = self.enumerate_process_modules(pid)

            for mod_path in modules:
                base_name = os.path.basename(mod_path).lower()
                if base_name in self.KNOWN_BENIGN_DLLS:
                    continue

                if "hook" in base_name or "keylog" in base_name:
                    findings.append(self.create_finding(
                        category="Keylogging",
                        severity="ALERT",
                        description=f"Suspicious hook/keylog module loaded in process: '{base_name}'",
                        evidence=f"PID: {pid} | Process: {name} | Module Path: {mod_path}"
                    ))

        return findings
