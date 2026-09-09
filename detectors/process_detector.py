"""
Process Spoofing and AV Evasion Detector for Windows Defensive Security Scanner.

Detects indicators of:
- Process masquerading and spoofing (system process names running from abnormal paths)
- Unsigned binaries residing in core system directories
- High-entropy (packed or encrypted) executable files
- Processes with suspicious names or command line arguments indicating malware/offensive tools
"""

import os
import re
import logging
from typing import List, Dict, Any, Optional

from .base_detector import BaseDetector


class ProcessDetector(BaseDetector):
    """
    Scans running processes and executables for masquerading, AV evasion, and malicious behavior.
    """

    # Mapping of critical Windows system processes to their legitimate canonical paths (lowercased)
    SYSTEM_PROCESS_PATHS = {
        "svchost.exe": ["c:\\windows\\system32\\svchost.exe", "c:\\windows\\syswow64\\svchost.exe"],
        "lsass.exe": ["c:\\windows\\system32\\lsass.exe"],
        "csrss.exe": ["c:\\windows\\system32\\csrss.exe"],
        "winlogon.exe": ["c:\\windows\\system32\\winlogon.exe"],
        "services.exe": ["c:\\windows\\system32\\services.exe"],
        "smss.exe": ["c:\\windows\\system32\\smss.exe"],
        "wininit.exe": ["c:\\windows\\system32\\wininit.exe"],
        "spoolsv.exe": ["c:\\windows\\system32\\spoolsv.exe"],
        "taskhostw.exe": ["c:\\windows\\system32\\taskhostw.exe"],
        "conhost.exe": ["c:\\windows\\system32\\conhost.exe"],
        "explorer.exe": ["c:\\windows\\explorer.exe", "c:\\windows\\syswow64\\explorer.exe"],
    }

    # Suspicious keyword regex patterns with word boundary constraints to avoid substring false positives
    SUSPICIOUS_KEYWORD_PATTERNS = [
        re.compile(r"(?<![a-zA-Z0-9])keylog", re.I),
        re.compile(r"(?<![a-zA-Z0-9])hook(?![a-zA-Z0-9])", re.I),
        re.compile(r"(?<![a-zA-Z0-9])spy(?![a-zA-Z0-9])", re.I),
        re.compile(r"(?<![a-zA-Z0-9])rat(?![a-zA-Z0-9])", re.I),
        re.compile(r"(?<![a-zA-Z0-9])stealer", re.I),
        re.compile(r"(?<![a-zA-Z0-9])logger(?![a-zA-Z0-9])", re.I),
        re.compile(r"(?<![a-zA-Z0-9])inject(?![a-zA-Z0-9])", re.I),
        re.compile(r"(?<![a-zA-Z0-9])hidden(?![a-zA-Z0-9])", re.I),
        re.compile(r"(?<![a-zA-Z0-9])backdoor", re.I),
        re.compile(r"(?<![a-zA-Z0-9])meterpreter", re.I),
        re.compile(r"(?<![a-zA-Z0-9])beacon", re.I),
        re.compile(r"(?<![a-zA-Z0-9])reverse_tcp", re.I),
        re.compile(r"(?<![a-zA-Z0-9])c2(?![a-zA-Z0-9])", re.I),
        re.compile(r"(?<![a-zA-Z0-9])cobaltstrike", re.I),
        re.compile(r"(?<![a-zA-Z0-9])powersploit", re.I),
        re.compile(r"(?<![a-zA-Z0-9])empire(?![a-zA-Z0-9])", re.I),
        re.compile(r"(?<![a-zA-Z0-9])mimikatz", re.I)
    ]

    ENTROPY_PACKED_THRESHOLD = 7.5

    def __init__(self, logger: Optional[logging.Logger] = None):
        super().__init__(logger=logger)

    @staticmethod
    def levenshtein_distance(s1: str, s2: str) -> int:
        """Calculate the Levenshtein edit distance between two strings."""
        if len(s1) < len(s2):
            return ProcessDetector.levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        previous_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]

    def _check_typosquatting(self, proc_name: str) -> Optional[str]:
        """
        Check if a process name is deceptively similar (typosquatting or visual spoofing)
        to a protected Windows core system process.
        """
        base_name = proc_name.lower()
        if base_name.endswith(".exe"):
            base_clean = base_name[:-4]
        else:
            base_clean = base_name

        # Check for trailing whitespace or dot abuse (e.g. "svchost.exe ")
        if proc_name.rstrip(". ") != proc_name:
            return "Process name contains trailing whitespace or dot characters"

        # Check homoglyph / leetspeak substitutions (0->o, 1->l, 5->s, 3->e)
        homoglyph_map = str.maketrans({"0": "o", "1": "l", "5": "s", "3": "e", "@": "a"})
        deobfuscated = base_clean.translate(homoglyph_map)
        deobf_exe = f"{deobfuscated}.exe"
        if deobf_exe in self.SYSTEM_PROCESS_PATHS and base_name != deobf_exe:
            return f"Visual homoglyph / leetspeak masquerading of system binary '{deobf_exe}'"

        # Check Levenshtein edit distance
        for sys_exe in self.SYSTEM_PROCESS_PATHS:
            sys_clean = sys_exe[:-4] if sys_exe.endswith(".exe") else sys_exe
            # Ignore exact match (handled in canonical path verification)
            if base_clean == sys_clean:
                continue

            max_allowed_dist = 2 if len(sys_clean) > 5 else 1
            dist = self.levenshtein_distance(base_clean, sys_clean)
            if 1 <= dist <= max_allowed_dist:
                return f"Typosquatting lookalike of core system process '{sys_exe}' (edit distance: {dist})"

        return None

    def run(self) -> List[Dict[str, Any]]:
        """
        Execute process spoofing, entropy, signature, and command line checks.
        """
        findings: List[Dict[str, Any]] = []
        processes = self.enumerate_processes()

        self.logger.info("Scanning %d running processes...", len(processes))

        scanned_exes = set()

        for proc in processes:
            pid = proc.get("pid", 0)
            name = (proc.get("name") or "").lower()
            raw_name = proc.get("name") or ""
            exe_path = proc.get("exe") or ""
            cmdline = proc.get("cmdline") or ""

            # Skip Linux kernel threads if scanner is tested on POSIX
            if pid < 100 and not exe_path and not cmdline:
                continue

            # -----------------------------------------------------------------
            # 1. Process Spoofing / Path Masquerading & Typosquatting
            # -----------------------------------------------------------------
            # Check 1A: Typosquatting / Visual Spoofing
            typo_reason = self._check_typosquatting(raw_name)
            if typo_reason:
                findings.append(self.create_finding(
                    category="Process Spoofing / AV Evasion",
                    severity="ALERT",
                    description=f"Suspicious lookalike process name detected ({typo_reason})",
                    evidence=f"PID: {pid} | Process Name: '{raw_name}' | Path: '{exe_path}' | Reason: {typo_reason}"
                ))

            # Check 1B: Exact System Process Canonical Path Verification
            if name in self.SYSTEM_PROCESS_PATHS:
                expected_paths = self.SYSTEM_PROCESS_PATHS[name]
                if exe_path:
                    norm_exe = os.path.normpath(os.path.expandvars(exe_path)).lower()
                    if norm_exe not in expected_paths:
                        findings.append(self.create_finding(
                            category="Process Spoofing / AV Evasion",
                            severity="ALERT",
                            description=f"System process '{name}' running from unauthorized location (Process Masquerading)",
                            evidence=f"PID: {pid} | Process: {name} | Path: {exe_path} | Expected: {', '.join(expected_paths)}"
                        ))
                elif not exe_path and platform_is_windows():
                    # Process exists with system name but path is inaccessible
                    findings.append(self.create_finding(
                        category="Process Spoofing / AV Evasion",
                        severity="WARN",
                        description=f"System process '{name}' detected with inaccessible or hidden executable path",
                        evidence=f"PID: {pid} | Process: {name} | Cmdline: {cmdline}"
                    ))

            # -----------------------------------------------------------------
            # 2. Suspicious Process Names & Command Lines
            # -----------------------------------------------------------------
            target_str = f"{name} {cmdline}"
            matched_keywords = []
            for pat in self.SUSPICIOUS_KEYWORD_PATTERNS:
                m = pat.search(target_str)
                if m:
                    matched_keywords.append(m.group(0))

            if matched_keywords:
                findings.append(self.create_finding(
                    category="Process Spoofing / AV Evasion",
                    severity="ALERT",
                    description=f"Process name or command line matches suspicious malware indicators: {matched_keywords}",
                    evidence=f"PID: {pid} | Name: {name} | Cmdline: {cmdline} | Matched: {matched_keywords}"
                ))

            # -----------------------------------------------------------------
            # 3. Executable File Analysis (Signatures and Entropy)
            # -----------------------------------------------------------------
            if exe_path and exe_path not in scanned_exes:
                scanned_exes.add(exe_path)
                expanded_exe = os.path.expandvars(exe_path).strip('"')

                if os.path.isfile(expanded_exe):
                    norm_path = os.path.normpath(expanded_exe).lower()

                    # Signature verification for executables in system directories
                    if norm_path.startswith("c:\\windows\\system32") or norm_path.startswith("c:\\windows\\syswow64"):
                        sig = self.check_digital_signature(expanded_exe)
                        status = sig.get("status", "")
                        if status in ("NotSigned", "HashMismatch", "NotTrusted"):
                            findings.append(self.create_finding(
                                category="Process Spoofing / AV Evasion",
                                severity="ALERT",
                                description=f"Unsigned or untrusted binary running from Windows system directory",
                                evidence=f"PID: {pid} | File: {expanded_exe} | Signature Status: {status}"
                            ))

                    # Shannon Entropy Calculation (First 4KB)
                    entropy = self.calculate_entropy(expanded_exe, max_bytes=4096)
                    if entropy > self.ENTROPY_PACKED_THRESHOLD:
                        findings.append(self.create_finding(
                            category="Process Spoofing / AV Evasion",
                            severity="ALERT",
                            description=f"Process executable exhibits high entropy ({entropy:.4f} > {self.ENTROPY_PACKED_THRESHOLD}), indicating packing, compression, or encryption (AV Evasion)",
                            evidence=f"PID: {pid} | File: {expanded_exe} | Entropy: {entropy:.4f}"
                        ))

        return findings


def platform_is_windows() -> bool:
    import platform
    return platform.system() == "Windows"
