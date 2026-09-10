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
        try:
            findings.extend(self._scan_hidden_services())
        except Exception as e:
            self.logger.warning("Error during hidden services scan: %s", e)

        self.logger.info("Scanning scheduled tasks for actions pointing to user-writable paths...")
        try:
            findings.extend(self._scan_hidden_tasks())
        except Exception as e:
            self.logger.warning("Error during hidden tasks scan: %s", e)

        return findings

    # -------------------------------------------------------------------------
    # Service Inspection
    # -------------------------------------------------------------------------

    def _scan_hidden_services(self) -> List[Dict[str, Any]]:
        findings = []
        services = self.enumerate_services()

        for svc in services:
            if not isinstance(svc, dict):
                continue
            svc_name = str(svc.get("name") or "")
            display_name = str(svc.get("display_name") or "").strip()
            binpath = str(svc.get("binpath") or "").strip()
            start_type = str(svc.get("start_type", "")).strip().lower()
            description = str(svc.get("description") or "").strip()

            if not binpath:
                continue

            # Check CWE-428 Unquoted Service Path Vulnerability
            if self.check_unquoted_path_vulnerability(binpath):
                findings.append(self.create_finding(
                    category="Hidden Installation",
                    severity="WARN",
                    description="Service contains unquoted path with spaces (CWE-428 unquoted search path vulnerability)",
                    evidence=f"Service: {svc_name} | Path: {binpath}",
                    rule_id="RULE-HIDDEN-SVC-UNQUOTED",
                    process=svc_name,
                    pid=None,
                    path=binpath,
                    recommendation="Enclose the service binary path in quotation marks to prevent CWE-428 search path hijacking."
                ))

            extracted_exe = self.extract_file_path(binpath)
            if not extracted_exe:
                continue

            expanded_path = os.path.expandvars(extracted_exe)

            # Heuristic 1: Service binary path or invoked script in temp, appdata, or user directory
            if self.is_temp_or_user_writable(expanded_path) or self.is_temp_or_user_writable(binpath):
                findings.append(self.create_finding(
                    category="Hidden Installation",
                    severity="ALERT",
                    description="Service binary path is located in a temporary, AppData, or user-writable folder",
                    evidence=f"Service: {svc_name} | Path: {binpath} | Resolved: {expanded_path}",
                    rule_id="RULE-HIDDEN-SVC-TEMP",
                    process=svc_name,
                    pid=None,
                    path=expanded_path,
                    recommendation="Investigate service origin, isolate host, and disable service configured to run from user-writable directories."
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
                    evidence=f"Service: {svc_name} | Display Name: '{display_name}' | Description: '{description}' | Start Type: {start_type}",
                    rule_id="RULE-HIDDEN-SVC-STEALTH",
                    process=svc_name,
                    pid=None,
                    path=binpath,
                    recommendation="Review service binary against known legitimate software catalogs; verify service installation provenance."
                ))

        return findings

    # -------------------------------------------------------------------------
    # Scheduled Tasks Inspection
    # -------------------------------------------------------------------------

    def _scan_hidden_tasks(self) -> List[Dict[str, Any]]:
        findings = []
        tasks = self.enumerate_scheduled_tasks()

        for task in tasks:
            if not isinstance(task, dict):
                continue
            task_name = str(task.get("name") or "")
            action = str(task.get("task_to_run") or "").strip()

            if not action:
                continue

            # Check CWE-428 Unquoted Task Path Vulnerability
            if self.check_unquoted_path_vulnerability(action):
                findings.append(self.create_finding(
                    category="Hidden Installation",
                    severity="WARN",
                    description="Scheduled task contains unquoted path with spaces (CWE-428 unquoted search path vulnerability)",
                    evidence=f"Task: {task_name} | Action: {action}",
                    rule_id="RULE-HIDDEN-TASK-UNQUOTED",
                    process=task_name,
                    pid=None,
                    path=action,
                    recommendation="Enclose scheduled task action executable path in quotation marks."
                ))

            extracted_exe = self.extract_file_path(action)
            if not extracted_exe:
                continue

            expanded_action = os.path.expandvars(extracted_exe)

            # Check if command or script payload points to temp, appdata, or user directory
            if self.is_temp_or_user_writable(expanded_action) or self.is_temp_or_user_writable(action):
                findings.append(self.create_finding(
                    category="Hidden Installation",
                    severity="ALERT",
                    description="Scheduled task executes from a temporary, AppData, or user-writable directory",
                    evidence=f"Task: {task_name} | Action: {action} | Resolved: {expanded_action}",
                    rule_id="RULE-HIDDEN-TASK-TEMP",
                    process=task_name,
                    pid=None,
                    path=expanded_action,
                    recommendation="Investigate task creator, review triggered actions, and remove unauthorized scheduled tasks executing from user folders."
                ))

        return findings
