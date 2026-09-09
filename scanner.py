#!/usr/bin/env python3
"""
Windows Defensive Security Scanner.

A modular, read-only, non-destructive defensive security scanning tool for Windows.
Detects persistence, process spoofing/AV evasion, keylogging, credential theft,
covert surveillance, and hidden installations.
"""

import os
import sys
import json
import argparse
import logging
import platform
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

# Ensure project root is in sys.path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from detectors import (
    BaseDetector,
    PersistenceDetector,
    ProcessDetector,
    KeyloggerDetector,
    CredentialTheftDetector,
    SurveillanceDetector,
    HiddenInstallDetector,
)

# Optional colorama support
try:
    import colorama
    colorama.init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False

# ANSI Color Codes
COLOR_RESET = "\033[0m"
COLOR_BOLD = "\033[1m"
COLOR_RED = "\033[91m"
COLOR_YELLOW = "\033[93m"
COLOR_GREEN = "\033[92m"
COLOR_CYAN = "\033[96m"
COLOR_BLUE = "\033[94m"
COLOR_GRAY = "\033[90m"


class ColorPrinter:
    """Terminal color formatting utility with automatic fallback."""

    def __init__(self, enabled: bool = True):
        # Enable ANSI colors if on POSIX, or if colorama is available, or Windows 10+ ANSI support
        self.enabled = enabled and (
            HAS_COLORAMA or platform.system() != "Windows" or os.environ.get("TERM") or "WT_SESSION" in os.environ
        )

    def colorize(self, text: str, color_code: str) -> str:
        if not self.enabled:
            return text
        return f"{color_code}{text}{COLOR_RESET}"

    def red(self, text: str) -> str:
        return self.colorize(text, COLOR_RED)

    def yellow(self, text: str) -> str:
        return self.colorize(text, COLOR_YELLOW)

    def green(self, text: str) -> str:
        return self.colorize(text, COLOR_GREEN)

    def cyan(self, text: str) -> str:
        return self.colorize(text, COLOR_CYAN)

    def bold(self, text: str) -> str:
        return self.colorize(text, COLOR_BOLD)

    def gray(self, text: str) -> str:
        return self.colorize(text, COLOR_GRAY)


class SecurityScanner:
    """
    Orchestrates execution of all defensive detection modules, collects findings,
    renders formatted console reports, and logs output to disk.
    """

    DEFAULT_LOG_FILE = "defensive_scan_log.txt"

    def __init__(
        self,
        log_file: Optional[str] = None,
        color_enabled: bool = True,
        verbose: bool = False,
        detectors_to_run: Optional[List[str]] = None
    ):
        self.log_file = log_file or self.DEFAULT_LOG_FILE
        self.color = ColorPrinter(enabled=color_enabled)
        self.verbose = verbose
        self.detectors_to_run = detectors_to_run

        self.logger = self._setup_logging()
        self.detectors: List[BaseDetector] = self._initialize_detectors()
        self.findings: List[Dict[str, Any]] = []

    def _setup_logging(self) -> logging.Logger:
        logger = logging.getLogger("WindowsDefenseScanner")
        logger.setLevel(logging.DEBUG if self.verbose else logging.INFO)
        logger.handlers.clear()

        # Console Stream Handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.DEBUG if self.verbose else logging.INFO)
        console_format = logging.Formatter(f"%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
        console_handler.setFormatter(console_format)
        logger.addHandler(console_handler)

        return logger

    def _initialize_detectors(self) -> List[BaseDetector]:
        all_detector_classes = {
            "persistence": PersistenceDetector,
            "process": ProcessDetector,
            "keylogger": KeyloggerDetector,
            "credential_theft": CredentialTheftDetector,
            "surveillance": SurveillanceDetector,
            "hidden_install": HiddenInstallDetector,
        }

        instances = []
        if self.detectors_to_run:
            for key in self.detectors_to_run:
                norm_key = key.lower().strip()
                if norm_key in all_detector_classes:
                    instances.append(all_detector_classes[norm_key](logger=self.logger))
        else:
            for cls in all_detector_classes.values():
                instances.append(cls(logger=self.logger))

        return instances

    def print_banner(self) -> None:
        banner = """
================================================================================
           WINDOWS DEFENSIVE SECURITY SCANNER - INCIDENT RESPONSE
================================================================================
 Mode: Read-Only / Non-Destructive
 Target OS: Windows 10/11
 Timestamp: {timestamp}
 Elevation: {elevation}
 System: {os_info}
================================================================================
""".format(
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            elevation=self._get_elevation_str(),
            os_info=f"{platform.system()} {platform.release()} ({platform.version()})"
        )
        print(self.color.cyan(banner))

    def _get_elevation_str(self) -> str:
        detector = BaseDetector()
        is_elevated = detector.is_admin()
        if is_elevated:
            return self.color.green("Elevated (Administrator)")
        return self.color.yellow("Standard User (Run as Admin recommended for full coverage)")

    def run(self) -> List[Dict[str, Any]]:
        """
        Execute all registered detection modules sequentially.
        """
        self.print_banner()
        self.findings.clear()

        start_time = datetime.now(timezone.utc)

        for detector in self.detectors:
            name = detector.__class__.__name__
            print(f"\n{self.color.bold(f'[*] Running module: {name}')}")
            try:
                module_findings = detector.run()
                print(f"    Findings detected: {len(module_findings)}")
                self.findings.extend(module_findings)
            except Exception as e:
                self.logger.error("Error executing detector %s: %s", name, e, exc_info=self.verbose)

        duration = (datetime.now(timezone.utc) - start_time).total_seconds()

        # Render console report
        self.render_report(duration)

        # Write all findings to log file
        self.write_log_file()

        return self.findings

    def render_report(self, duration: float) -> None:
        """
        Print detailed findings and a categorized summary table to console.
        """
        print("\n" + "=" * 80)
        print(self.color.bold("                            SCAN FINDINGS DETAILS"))
        print("=" * 80)

        if not self.findings:
            print(self.color.green("\n[+] Scan completed. No suspicious indicators detected."))
        else:
            for idx, finding in enumerate(self.findings, 1):
                sev = finding.get("severity", "INFO")
                cat = finding.get("category", "General")
                desc = finding.get("description", "")
                evidence = finding.get("evidence", "")
                ts = finding.get("timestamp", "")

                if sev == "ALERT":
                    sev_str = self.color.red(f"[{sev}]")
                elif sev == "WARN":
                    sev_str = self.color.yellow(f"[{sev}]")
                else:
                    sev_str = self.color.cyan(f"[{sev}]")

                print(f"\n{self.color.bold(f'[{idx}]')} {sev_str} {self.color.bold(cat)} ({ts})")
                print(f"    Description: {desc}")
                print(f"    Evidence:    {self.color.gray(evidence)}")

        # Print Summary Breakdown
        print("\n" + "=" * 80)
        print(self.color.bold("                               SCAN SUMMARY"))
        print("=" * 80)

        counts_by_cat: Dict[str, int] = {}
        counts_by_sev: Dict[str, int] = {"ALERT": 0, "WARN": 0, "INFO": 0}

        for f in self.findings:
            cat = f.get("category", "Unknown")
            sev = f.get("severity", "INFO")
            counts_by_cat[cat] = counts_by_cat.get(cat, 0) + 1
            counts_by_sev[sev] = counts_by_sev.get(sev, 0) + 1

        print(f"\nTotal Scan Duration: {duration:.2f} seconds")
        print(f"Total Findings:      {len(self.findings)}")
        print(f"  - {self.color.red('ALERT (High Risk)')}:  {counts_by_sev['ALERT']}")
        print(f"  - {self.color.yellow('WARN  (Suspicious)'):}  {counts_by_sev['WARN']}")
        print(f"  - {self.color.cyan('INFO  (Low/Inform)'):}  {counts_by_sev['INFO']}")

        print("\nCategory Breakdown:")
        for cat, count in sorted(counts_by_cat.items()):
            print(f"  * {cat:<32}: {count}")

        print("=" * 80)

    def write_log_file(self) -> None:
        """
        Write all scan findings and summary into the output log file.
        """
        try:
            with open(self.log_file, "w", encoding="utf-8") as f:
                f.write("=" * 80 + "\n")
                f.write("WINDOWS DEFENSIVE SECURITY SCANNER - AUDIT LOG\n")
                f.write(f"Generated: {datetime.now(timezone.utc).isoformat()}\n")
                f.write(f"Platform:  {platform.system()} {platform.release()} ({platform.version()})\n")
                f.write(f"Total Findings: {len(self.findings)}\n")
                f.write("=" * 80 + "\n\n")

                if not self.findings:
                    f.write("No suspicious indicators or threats identified during this scan.\n")
                else:
                    for idx, finding in enumerate(self.findings, 1):
                        f.write(f"[{idx}] [{finding.get('severity')}] [{finding.get('category')}]\n")
                        f.write(f"Timestamp:   {finding.get('timestamp')}\n")
                        f.write(f"Description: {finding.get('description')}\n")
                        f.write(f"Evidence:    {finding.get('evidence')}\n")
                        f.write("-" * 80 + "\n")

                # Append Category Summary
                f.write("\n" + "=" * 80 + "\n")
                f.write("SUMMARY BY CATEGORY\n")
                f.write("=" * 80 + "\n")
                counts_by_cat: Dict[str, int] = {}
                for finding in self.findings:
                    cat = finding.get("category", "Unknown")
                    counts_by_cat[cat] = counts_by_cat.get(cat, 0) + 1
                for cat, cnt in sorted(counts_by_cat.items()):
                    f.write(f"{cat:<35}: {cnt}\n")

            print(f"\n[+] Full findings log successfully saved to: {os.path.abspath(self.log_file)}")
        except (OSError, PermissionError) as e:
            self.logger.error("Failed to write log file to %s: %s", self.log_file, e)


def main() -> int:
    """CLI Entrypoint for the security scanner."""
    parser = argparse.ArgumentParser(
        description="Windows Defensive Security Scanner - Proactive threat detection and persistence scanning"
    )
    parser.add_argument(
        "--output", "-o",
        dest="log_file",
        default="defensive_scan_log.txt",
        help="Path to output findings log file (default: defensive_scan_log.txt)"
    )
    parser.add_argument(
        "--no-color",
        dest="no_color",
        action="store_true",
        help="Disable ANSI colored terminal output"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose debugging output"
    )
    parser.add_argument(
        "--module", "-m",
        dest="modules",
        nargs="+",
        choices=["persistence", "process", "keylogger", "credential_theft", "surveillance", "hidden_install"],
        help="Specific detector module(s) to execute"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output findings as JSON to stdout"
    )

    args = parser.parse_args()

    scanner = SecurityScanner(
        log_file=args.log_file,
        color_enabled=not args.no_color,
        verbose=args.verbose,
        detectors_to_run=args.modules
    )

    findings = scanner.run()

    if args.json:
        print("\n--- JSON OUTPUT ---")
        print(json.dumps(findings, indent=2))

    # Return exit code 2 if ALERT found, 1 if WARN found, 0 if clean
    severities = {f.get("severity") for f in findings}
    if "ALERT" in severities:
        return 2
    if "WARN" in severities:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
