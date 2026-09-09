"""
Hidden Installation Detection Module for Windows Defensive Security Scanner.

Detects stealthy, abnormal, or hidden installations:
- Services whose binary path resides in %TEMP%, %TMP%, %APPDATA%, or user-writable paths
- Scheduled tasks whose actions execute binaries from user-writable directories
- Auto-start services with missing display names or descriptions (common in stealth implants)
"""

import os
import re
import logging
from typing import List, Dict, Any, Optional

from .base_detector import BaseDetector


class HiddenInstallDetector(BaseDetector):
    """
    Scans for services and tasks installed in stealthy or user-writable locations.
    """

    AUTO_START_VALUES = {"automatic", "auto", "2", "delayed-auto"}

    def __init__(self, logger: Optional[logging.Logger] = None):
        super().__init__(logger=logger)

    def run(self) -> List[Dict[str, Any]]:
        """
        Execute hidden installation detection across services and scheduled tasks.
        """
        findings: List[Dict[str, Any]] = []

        self.logger.info("Scanning services for hidden / user-writable binary paths and stealth configs...")
        findings.extend(self._scan_hidden_services())

        self.logger.info("Scanning scheduled tasks for actions pointing to user-writable paths...")
        findings.extend(self._scan_hidden_tasks())

        return findings

    # -------------------------------------------------------------------------
    # Service Inspection
    # -------------------------------------------------------------------------

    def _scan_hidden_services(self) -> List[Dict[str, Any]]:
        findings = []
        services = self.enumerate_services()

        for svc in services:
            svc_name = svc.get("name", "")
            display_name = (svc.get("display_name") or "").strip()
            binpath = (svc.get("binpath") or "").strip()
            start_type = str(svc.get("start_type", "")).strip().lower()
            description = (svc.get("description") or "").strip()

            if not binpath:
                continue

            extracted_exe = self.extract_file_path(binpath)
            if not extracted_exe:
                continue

            expanded_path = os.path.expandvars(extracted_exe)

            # Heuristic 1: Service binary path in temp, appdata, or user directory
            if self.is_temp_or_user_writable(expanded_path):
                findings.append(self.create_finding(
                    category="Hidden Installation",
                    severity="ALERT",
                    description="Service binary path is located in a temporary, AppData, or user-writable folder",
                    evidence=f"Service: {svc_name} | Path: {binpath} | Resolved: {expanded_path}"
                ))

            # Heuristic 2: Service is set to auto-start but lacks display name or description
            is_autostart = (start_type in self.AUTO_START_VALUES or "auto" in start_type)
            has_no_display = (not display_name or display_name.lower() == svc_name.lower())
            has_no_desc = (not description)

            if is_autostart and (not display_name or (has_no_display and has_no_desc)):
                findings.append(self.create_finding(
                    category="Hidden Installation",
                    severity="WARN",
                    description="Auto-start service lacks standard display name or descriptive metadata (stealth installation profile)",
                    evidence=f"Service: {svc_name} | Display Name: '{display_name}' | Description: '{description}' | Start Type: {start_type}"
                ))

        return findings

    # -------------------------------------------------------------------------
    # Scheduled Tasks Inspection
    # -------------------------------------------------------------------------

    def _scan_hidden_tasks(self) -> List[Dict[str, Any]]:
        findings = []
        tasks = self.enumerate_scheduled_tasks()

        for task in tasks:
            task_name = task.get("name", "")
            action = (task.get("task_to_run") or "").strip()

            if not action:
                continue

            extracted_exe = self.extract_file_path(action)
            if not extracted_exe:
                continue

            expanded_action = os.path.expandvars(extracted_exe)

            # Check if command points to temp, appdata, or user directory
            if self.is_temp_or_user_writable(expanded_action):
                findings.append(self.create_finding(
                    category="Hidden Installation",
                    severity="ALERT",
                    description="Scheduled task executes from a temporary, AppData, or user-writable directory",
                    evidence=f"Task: {task_name} | Action: {action} | Resolved: {expanded_action}"
                ))

        return findings
