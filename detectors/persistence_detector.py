"""
Persistence Detection Module for Windows Defensive Security Scanner.

Detects autostart persistence mechanisms across:
- Registry Run, RunOnce, RunServices keys (HKLM, HKCU, and Wow6432Node)
- StartupApproved keys
- User and All Users (Common) Startup folders
- Windows Services with suspicious paths or naming
- Scheduled Tasks executing from user-writable / non-standard locations
"""

import os
import re
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path

from .base_detector import BaseDetector


class PersistenceDetector(BaseDetector):
    """
    Scans for unauthorized or suspicious persistence techniques on Windows.
    """

    RUN_KEYS = [
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"Software\Microsoft\Windows\CurrentVersion\RunServices",
        r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        r"Software\Microsoft\Windows\CurrentVersion\StartupApproved\Run",
        r"Software\Microsoft\Windows\CurrentVersion\StartupApproved\Run32",
        r"Software\Microsoft\Windows\CurrentVersion\StartupApproved\StartupFolder",
        r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices",
        r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    ]

    SUSPICIOUS_SERVICE_NAMES = [
        re.compile(r"^[a-z0-9]{1,2}$", re.I),                     # Single or two character names (e.g. "a", "x1")
        re.compile(r"^[0-9a-f]{8,32}$", re.I),                    # Hex/hash/randomized names
        re.compile(r"^(svchost|csrss|lsass|winlogon|smss)\b", re.I) # Masquerading names
    ]

    def __init__(self, logger: Optional[logging.Logger] = None):
        super().__init__(logger=logger)
        self.startup_folders_override: Optional[List[str]] = None

    def run(self) -> List[Dict[str, Any]]:
        """
        Execute persistence scans across Registry, Startup folders, Services, and Scheduled Tasks.
        """
        findings: List[Dict[str, Any]] = []

        self.logger.info("Scanning Registry Run and Startup keys...")
        try:
            findings.extend(self._scan_registry_persistence())
        except Exception as e:
            self.logger.warning("Error during registry persistence scan: %s", e)

        self.logger.info("Scanning Windows Startup folders...")
        try:
            findings.extend(self._scan_startup_folders())
        except Exception as e:
            self.logger.warning("Error during startup folder scan: %s", e)

        self.logger.info("Scanning Windows Services for persistence...")
        try:
            findings.extend(self._scan_services_persistence())
        except Exception as e:
            self.logger.warning("Error during services persistence scan: %s", e)

        self.logger.info("Scanning Scheduled Tasks for persistence...")
        try:
            findings.extend(self._scan_scheduled_tasks_persistence())
        except Exception as e:
            self.logger.warning("Error during scheduled tasks persistence scan: %s", e)

        return findings

    # -------------------------------------------------------------------------
    # Registry Run Key Scanning
    # -------------------------------------------------------------------------

    def _scan_registry_persistence(self) -> List[Dict[str, Any]]:
        findings = []
        root_keys = ["HKCU", "HKLM"]

        for root in root_keys:
            for subkey in self.RUN_KEYS:
                is_startup_approved = "startupapproved" in subkey.lower()
                entries = self.read_registry_values(root, subkey)
                for entry in entries:
                    if not isinstance(entry, dict):
                        continue
                    raw_data = entry.get("data")
                    val_name = str(entry.get("name") or "")

                    if raw_data is None or val_name == "(Default)":
                        continue

                    # StartupApproved keys contain binary status flags, not command paths
                    if is_startup_approved and (isinstance(raw_data, (bytes, bytearray)) or str(raw_data).startswith("b'")):
                        continue

                    val_data = str(raw_data).strip()
                    if not val_data:
                        continue

                    target_file = self.extract_file_path(val_data)
                    key_location = f"{root}\\{subkey}\\{val_name}"

                    # CWE-428 Unquoted Service / Autostart Path Vulnerability
                    if self.check_unquoted_path_vulnerability(val_data):
                        findings.append(self.create_finding(
                            category="Persistence",
                            severity="WARN",
                            description="Registry autostart contains unquoted path with spaces (CWE-428 unquoted search path vulnerability)",
                            evidence=f"Registry Key: {key_location} | Command: {val_data}",
                            rule_id="RULE-PERSIST-RUN-UNQUOTED",
                            process=val_name,
                            pid=None,
                            path=key_location,
                            recommendation="Quote the executable path in the autostart registry entry to avoid CWE-428 path hijacking."
                        ))

                    if target_file:
                        expanded_target = os.path.expandvars(target_file)
                        file_exists = os.path.exists(expanded_target) or os.path.exists(expanded_target + ".exe")

                        # Heuristic 1: Entry points to temporary, user-writable, or non-standard directory
                        if self.is_temp_or_user_writable(expanded_target) or self.is_temp_or_user_writable(val_data):
                            findings.append(self.create_finding(
                                category="Persistence",
                                severity="ALERT",
                                description="Registry autostart points to a temporary, user-writable, or non-standard directory",
                                evidence=f"Registry Key: {key_location} | Target: {expanded_target} | Command: {val_data}",
                                rule_id="RULE-PERSIST-RUN-TEMP",
                                process=val_name,
                                pid=None,
                                path=expanded_target,
                                recommendation="Investigate the binary in the user-writable path and remove the autostart entry if unauthorized."
                            ))
                        elif not self.is_standard_system_path(expanded_target):
                            findings.append(self.create_finding(
                                category="Persistence",
                                severity="WARN",
                                description="Registry autostart points to a non-standard application directory",
                                evidence=f"Registry Key: {key_location} | Target: {expanded_target} | Command: {val_data}",
                                rule_id="RULE-PERSIST-RUN-NONSTANDARD",
                                process=val_name,
                                pid=None,
                                path=expanded_target,
                                recommendation="Verify whether the autostart entry is associated with an approved enterprise application."
                            ))

                        # Heuristic 2: Entry points to non-existent executable file (orphan or stealth persistence)
                        if not file_exists:
                            findings.append(self.create_finding(
                                category="Persistence",
                                severity="WARN",
                                description="Registry autostart entry points to a non-existent file (orphan or stealth persistence)",
                                evidence=f"Registry Key: {key_location} | Command: {val_data} | Resolved Path: {expanded_target}",
                                rule_id="RULE-PERSIST-RUN-ORPHAN",
                                process=val_name,
                                pid=None,
                                path=expanded_target,
                                recommendation="Delete orphaned autostart registry entry pointing to missing executable."
                            ))

                        # Heuristic 3: Check digital signature of the persistence executable if present
                        if os.path.isfile(expanded_target):
                            sig_info = self.check_digital_signature(expanded_target)
                            if sig_info.get("status") in ("NotSigned", "HashMismatch", "NotTrusted"):
                                findings.append(self.create_finding(
                                category="Persistence",
                                severity="WARN",
                                description="Autostart binary has an invalid or missing digital signature",
                                evidence=f"File: {expanded_target} | Signature Status: {sig_info.get('status')} | Key: {key_location}",
                                rule_id="RULE-PERSIST-RUN-UNSIGNED",
                                process=val_name,
                                pid=None,
                                path=expanded_target,
                                recommendation="Verify digital signature validity with Sigcheck; remove unverified autostart programs."
                            ))

        return findings

    # -------------------------------------------------------------------------
    # Startup Folder Scanning
    # -------------------------------------------------------------------------

    def _scan_startup_folders(self) -> List[Dict[str, Any]]:
        findings = []

        if self.startup_folders_override is not None:
            startup_paths = self.startup_folders_override
        else:
            appdata = os.environ.get("APPDATA", "")
            programdata = os.environ.get("PROGRAMDATA", r"C:\ProgramData")

            startup_paths = [
                os.path.join(appdata, r"Microsoft\Windows\Start Menu\Programs\Startup") if appdata else "",
                os.path.join(programdata, r"Microsoft\Windows\Start Menu\Programs\Startup") if programdata else ""
            ]

        for folder in startup_paths:
            if not folder or not os.path.isdir(folder):
                continue

            try:
                for entry in os.scandir(folder):
                    if not entry.is_file():
                        continue

                    file_name = entry.name.lower()
                    file_path = entry.path

                    # desktop.ini is standard Windows shell folder config
                    if file_name == "desktop.ini":
                        continue

                    # Legitimate Windows startup entries are shortcuts (.lnk) or url shortcuts (.url)
                    ext = os.path.splitext(file_name)[1].lower()
                    if ext not in (".lnk", ".url"):
                        # Direct executables or scripts in the Startup folder are high-risk persistence
                        findings.append(self.create_finding(
                            category="Persistence",
                            severity="ALERT",
                            description="Non-shortcut executable or script placed directly in Windows Startup directory",
                            evidence=f"Startup File: {file_path} (Extension: '{ext}') | Folder: {folder}",
                            rule_id="RULE-PERSIST-STARTUP-FILE",
                            process=file_name,
                            pid=None,
                            path=file_path,
                            recommendation="Remove direct executable/script from Windows Startup folder; investigate dropper origin."
                        ))
                    else:
                        # For shortcuts, check if the file itself has high entropy or unusual size
                        entropy = self.calculate_entropy(file_path)
                        if entropy > 7.5:
                            findings.append(self.create_finding(
                                category="Persistence",
                                severity="WARN",
                                description="Startup shortcut file has unusually high entropy (possible embedded payload)",
                                evidence=f"Shortcut: {file_path} | Entropy: {entropy}",
                                rule_id="RULE-PERSIST-STARTUP-ENTROPY",
                                process=file_name,
                                pid=None,
                                path=file_path,
                                recommendation="Inspect startup shortcut file for embedded polyglot or packed malicious payload."
                            ))

            except (PermissionError, OSError) as e:
                self.logger.debug("Error reading startup folder '%s': %s", folder, e)

        return findings

    # -------------------------------------------------------------------------
    # Services Persistence Scanning
    # -------------------------------------------------------------------------

    def _scan_services_persistence(self) -> List[Dict[str, Any]]:
        findings = []
        services = self.enumerate_services()

        for svc in services:
            if not isinstance(svc, dict):
                continue
            svc_name = str(svc.get("name") or "")
            display_name = str(svc.get("display_name") or "")
            binpath = str(svc.get("binpath") or "").strip()
            status = str(svc.get("status") or "")

            if not binpath:
                continue

            # CWE-428 Unquoted Service Path Vulnerability
            if self.check_unquoted_path_vulnerability(binpath):
                findings.append(self.create_finding(
                    category="Persistence",
                    severity="WARN",
                    description="Service binary path contains unquoted path with spaces (CWE-428 unquoted search path vulnerability)",
                    evidence=f"Service Name: {svc_name} | Path: {binpath}",
                    rule_id="RULE-PERSIST-SVC-UNQUOTED",
                    process=svc_name,
                    pid=None,
                    path=binpath,
                    recommendation="Enclose service path in quotation marks to prevent CWE-428 path hijacking."
                ))

            exec_path = self.extract_file_path(binpath)
            if not exec_path:
                continue

            expanded_path = os.path.expandvars(exec_path)

            # Check 1: Binary path or script argument in user-writable/temp directory
            if self.is_temp_or_user_writable(expanded_path) or self.is_temp_or_user_writable(binpath):
                findings.append(self.create_finding(
                    category="Persistence",
                    severity="ALERT",
                    description="Service binary path is located in a user-writable or temporary directory",
                    evidence=f"Service Name: {svc_name} | Display: {display_name} | Path: {binpath} | State: {status}",
                    rule_id="RULE-PERSIST-SVC-TEMP",
                    process=svc_name,
                    pid=None,
                    path=expanded_path,
                    recommendation="Isolate endpoint and remove unauthorized service executing from user-writable folder."
                ))

            # Check 2: Suspicious naming mimicking core system binaries from outside system32
            base_name = self.get_path_basename(expanded_path).lower()
            if base_name in ("svchost.exe", "lsass.exe", "services.exe", "csrss.exe", "smss.exe"):
                norm_exp = expanded_path.lower().replace("/", "\\")
                if not norm_exp.startswith("c:\\windows\\system32") and not norm_exp.startswith("c:\\windows\\syswow64"):
                    findings.append(self.create_finding(
                        category="Persistence",
                        severity="ALERT",
                        description=f"Service mimics critical system binary '{base_name}' from abnormal path",
                        evidence=f"Service Name: {svc_name} | Path: {binpath}",
                        rule_id="RULE-PERSIST-SVC-MASQ",
                        process=svc_name,
                        pid=None,
                        path=expanded_path,
                        recommendation="Terminate and remove service masquerading as core Windows system executable."
                    ))

        return findings

    # -------------------------------------------------------------------------
    # Scheduled Tasks Persistence Scanning
    # -------------------------------------------------------------------------

    def _scan_scheduled_tasks_persistence(self) -> List[Dict[str, Any]]:
        findings = []
        tasks = self.enumerate_scheduled_tasks()

        for task in tasks:
            if not isinstance(task, dict):
                continue
            task_name = str(task.get("name") or "")
            action = str(task.get("task_to_run") or "").strip()

            if not action:
                continue

            # CWE-428 Unquoted Task Path Vulnerability
            if self.check_unquoted_path_vulnerability(action):
                findings.append(self.create_finding(
                    category="Persistence",
                    severity="WARN",
                    description="Scheduled task contains unquoted path with spaces (CWE-428 unquoted search path vulnerability)",
                    evidence=f"Task: {task_name} | Action: {action}",
                    rule_id="RULE-PERSIST-TASK-UNQUOTED",
                    process=task_name,
                    pid=None,
                    path=action,
                    recommendation="Quote scheduled task action path to prevent CWE-428 path hijacking."
                ))

            exec_path = self.extract_file_path(action)
            if not exec_path:
                continue

            expanded_action = os.path.expandvars(exec_path)

            # Check if scheduled task runs from temp or user-writable location, or executes payload in user-writable path
            if self.is_temp_or_user_writable(expanded_action) or self.is_temp_or_user_writable(action):
                findings.append(self.create_finding(
                    category="Persistence",
                    severity="ALERT",
                    description="Scheduled task executes from a temporary or user-writable location",
                    evidence=f"Task: {task_name} | Action: {action} | Resolved: {expanded_action}",
                    rule_id="RULE-PERSIST-TASK-TEMP",
                    process=task_name,
                    pid=None,
                    path=expanded_action,
                    recommendation="Inspect and delete scheduled task executing from user-writable directories."
                ))

        return findings
