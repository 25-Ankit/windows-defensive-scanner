"""
Covert Surveillance Detection Module for Windows Defensive Security Scanner.

Detects indicators of unauthorized surveillance and monitoring:
- Active processes or services associated with covert screen recording, hidden VNC, or surveillance
- Scheduled tasks invoking screen capture utilities or scripts (e.g. PowerShell CopyFromScreen, .NET Drawing)
"""

import os
import re
import logging
from typing import List, Dict, Any, Optional

from .base_detector import BaseDetector


class SurveillanceDetector(BaseDetector):
    """
    Scans processes, services, and scheduled tasks for covert surveillance tools.
    """

    # Patterns for surveillance keywords (matching standalone words and common tool prefixes like winvnc)
    SURVEILLANCE_PATTERNS = [
        re.compile(r"vnc", re.I),
        re.compile(r"(?<![a-zA-Z0-9])rdp", re.I),
        re.compile(r"surveil", re.I),
        re.compile(r"webcam", re.I),
        re.compile(r"screen[_\s\-]?(capture|record|grab|shot)", re.I),
        re.compile(r"(audio|mic)[_\s\-]?record", re.I),
        re.compile(r"(?<![a-zA-Z0-9])(screen|capture|record|remote|monitor)(?![a-zA-Z0-9])", re.I),
    ]

    # Known benign / legitimate Windows tools and common development applications to exclude
    LEGITIMATE_ALLOWLIST = {
        "mstsc.exe",            # Official Microsoft RDP client
        "rdpclip.exe",          # Official Windows RDP clipboard utility
        "vmware-vmx.exe",       # VMware Workstation
        "vmtoolsd.exe",         # VMware Tools
        "vboxservice.exe",      # VirtualBox Guest Additions
        "vboxtray.exe",         # VirtualBox Tray
        "dwm.exe",              # Desktop Window Manager
        "perfmon.exe",          # Windows Performance Monitor
        "resmon.exe",           # Windows Resource Monitor
        "taskmgr.exe",          # Windows Task Manager
        "wmiapsrv.exe",         # WMI Performance Adapter
        "spoolsv.exe",          # Print Spooler
        "explorer.exe",         # Windows Shell
        # Common GUI/browser engines when evaluated in development
        "code", "code.exe",
        "chrome", "chrome.exe",
        "brave", "brave.exe",
        "firefox", "firefox.exe",
        "chrome_crashpad_handler"
    }

    # Scheduled task suspicious patterns (e.g. PowerShell screen capture)
    TASK_SCREEN_CAPTURE_PATTERNS = [
        "copyfromscreen",
        "system.drawing",
        "system.windows.forms",
        "graphics.copyfromscreen",
        "nircmd.exe savescreenshot",
        "ffmpeg -f gdigrab"
    ]

    def __init__(self, logger: Optional[logging.Logger] = None):
        super().__init__(logger=logger)

    def run(self) -> List[Dict[str, Any]]:
        """
        Execute surveillance and covert capture detection.
        """
        findings: List[Dict[str, Any]] = []

        self.logger.info("Scanning processes for surveillance indicators...")
        findings.extend(self._scan_surveillance_processes())

        self.logger.info("Scanning services for surveillance keywords...")
        findings.extend(self._scan_surveillance_services())

        self.logger.info("Scanning scheduled tasks for automated screen capture routines...")
        findings.extend(self._scan_screen_capture_tasks())

        return findings

    # -------------------------------------------------------------------------
    # Process Scanning
    # -------------------------------------------------------------------------

    def _scan_surveillance_processes(self) -> List[Dict[str, Any]]:
        findings = []
        processes = self.enumerate_processes()

        for proc in processes:
            pid = proc.get("pid", 0)
            name = (proc.get("name") or "").lower()
            cmdline = (proc.get("cmdline") or "").lower()

            # Skip Linux kernel threads if scanner is tested on POSIX
            if pid < 100 and not proc.get("exe") and not cmdline:
                continue

            if name in self.LEGITIMATE_ALLOWLIST:
                continue

            target_text = f"{name} {cmdline}"
            matched = []
            for pat in self.SURVEILLANCE_PATTERNS:
                m = pat.search(target_text)
                if m:
                    matched.append(m.group(0))

            if matched:
                # Disregard common system services / legitimate paths if signed/standard
                findings.append(self.create_finding(
                    category="Covert Surveillance",
                    severity="WARN",
                    description=f"Process matches surveillance or remote capture indicators: {matched}",
                    evidence=f"PID: {pid} | Process: {proc.get('name')} | Cmdline: {proc.get('cmdline')} | Indicators: {matched}"
                ))

        return findings

    # -------------------------------------------------------------------------
    # Service Scanning
    # -------------------------------------------------------------------------

    def _scan_surveillance_services(self) -> List[Dict[str, Any]]:
        findings = []
        services = self.enumerate_services()

        # Legitimate Windows services related to remote access or display
        legitimate_services = {
            "termservice", "sessionenv", "umrdpservice", "dispbrokerdesktopsvc",
            "lanmanserver", "lanmanworkstation", "remoteregistry"
        }

        for svc in services:
            svc_name = (svc.get("name") or "").lower()
            display_name = (svc.get("display_name") or "").lower()
            binpath = (svc.get("binpath") or "").lower()

            if svc_name in legitimate_services:
                continue

            text_to_check = f"{svc_name} {display_name} {binpath}"
            matched = []
            for pat in self.SURVEILLANCE_PATTERNS:
                m = pat.search(text_to_check)
                if m:
                    matched.append(m.group(0))

            if matched:
                findings.append(self.create_finding(
                    category="Covert Surveillance",
                    severity="WARN",
                    description=f"Service configured with surveillance or remote access keywords: {matched}",
                    evidence=f"Service: {svc.get('name')} | Display: {svc.get('display_name')} | Path: {svc.get('binpath')}"
                ))

        return findings

    # -------------------------------------------------------------------------
    # Scheduled Tasks Screen Capture Detection
    # -------------------------------------------------------------------------

    def _scan_screen_capture_tasks(self) -> List[Dict[str, Any]]:
        findings = []
        tasks = self.enumerate_scheduled_tasks()

        for task in tasks:
            task_name = task.get("name", "")
            action = (task.get("task_to_run") or "").lower()

            matched_patterns = [p for p in self.TASK_SCREEN_CAPTURE_PATTERNS if p in action]
            if matched_patterns:
                findings.append(self.create_finding(
                    category="Covert Surveillance",
                    severity="ALERT",
                    description=f"Scheduled task invokes automated screen capture or graphics grab routines: {matched_patterns}",
                    evidence=f"Task Name: {task_name} | Action: {task.get('task_to_run')} | Matched: {matched_patterns}"
                ))

        return findings
