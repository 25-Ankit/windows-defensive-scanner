#!/usr/bin/env python3
"""
Remote Windows Defensive Security Scanner Orchestrator.

Orchestrates defensive security scans across remote Windows endpoints via
WinRM / PowerShell Remoting. Transfers the scanner payload, executes it remotely
with administrative privileges, retrieves structured JSON findings, cleans up artifacts,
and generates a consolidated multi-host incident response report.
"""

import os
import sys
import json
import base64
import argparse
import logging
import platform
import subprocess
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


class RemoteScannerOrchestrator:
    """
    Manages remote deployment, execution, and telemetry retrieval across Windows targets.
    """

    def __init__(
        self,
        targets: List[str],
        username: Optional[str] = None,
        password: Optional[str] = None,
        output_file: str = "remote_defensive_scan_log.txt",
        modules: Optional[List[str]] = None,
        verbose: bool = False
    ):
        self.targets = targets
        self.username = username
        self.password = password
        self.output_file = output_file
        self.modules = modules or []
        self.verbose = verbose
        self.logger = self._setup_logging()
        self.consolidated_results: Dict[str, Any] = {}
        self.command_runner = None  # Injectable hook for testing

    def _setup_logging(self) -> logging.Logger:
        logger = logging.getLogger("RemoteScannerOrchestrator")
        logger.setLevel(logging.DEBUG if self.verbose else logging.INFO)
        logger.handlers.clear()
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"))
        logger.addHandler(handler)
        return logger

    def build_remote_payload_bundle(self) -> str:
        """
        Bundle scanner.py and the detectors/ package into a base64-encoded zip archive
        for zero-dependency deployment over WinRM.
        """
        import io
        import zipfile

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
            # Add scanner.py
            scanner_path = os.path.join(SCRIPT_DIR, "scanner.py")
            if os.path.isfile(scanner_path):
                zip_file.write(scanner_path, "scanner.py")

            # Add detectors
            detectors_dir = os.path.join(SCRIPT_DIR, "detectors")
            if os.path.isdir(detectors_dir):
                for root, _, files in os.walk(detectors_dir):
                    for file in files:
                        if file.endswith(".py"):
                            full_p = os.path.join(root, file)
                            rel_p = os.path.relpath(full_p, SCRIPT_DIR)
                            zip_file.write(full_p, rel_p)

        return base64.b64encode(zip_buffer.getvalue()).decode("utf-8")

    def execute_remote_scan(self, target: str) -> Dict[str, Any]:
        """
        Execute scan on a single remote endpoint and return findings and status.
        """
        self.logger.info("Initiating remote scan on target: %s", target)
        result: Dict[str, Any] = {
            "target": target,
            "status": "FAILED",
            "findings": [],
            "error": None,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        # If custom command runner is injected (for unit tests)
        if callable(self.command_runner):
            return self.command_runner(target)

        bundle_b64 = self.build_remote_payload_bundle()
        module_args = (" -m " + " ".join(self.modules)) if self.modules else ""

        # PowerShell script that unpacks bundle to temporary dir, executes scanner.py --json, and cleans up
        ps_remote_script = f"""
$ErrorActionPreference = 'Stop'
$tempDir = [System.IO.Path]::Combine($env:TEMP, "DefScanner_" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
try {{
    $zipBytes = [System.Convert]::FromBase64String("{bundle_b64}")
    $zipPath = Join-Path $tempDir "scanner.zip"
    [System.IO.File]::WriteAllBytes($zipPath, $zipBytes)
    Expand-Archive -Path $zipPath -DestinationPath $tempDir -Force
    
    $pythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
    if (-not $pythonExe) {{
        $pythonExe = (Get-Command py -ErrorAction SilentlyContinue).Source
    }}
    if (-not $pythonExe) {{
        throw "Python 3 is not installed or not in PATH on target host."
    }}
    
    $scanOutput = & $pythonExe (Join-Path $tempDir "scanner.py") --json --no-color{module_args}
    $jsonMarker = "--- JSON OUTPUT ---"
    $idx = $scanOutput.IndexOf($jsonMarker)
    if ($idx -ge 0) {{
        $scanOutput.Substring($idx + $jsonMarker.Length).Trim()
    }} else {{
        $scanOutput
    }}
}} finally {{
    Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
}}
"""

        try:
            # Build Invoke-Command via powershell
            cmd = ["powershell.exe", "-NoProfile", "-NonInteractive"]
            if self.username and self.password:
                cred_block = f"$secPass = ConvertTo-SecureString '{self.password}' -AsPlainText -Force; $cred = New-Object System.Management.Automation.PSCredential ('{self.username}', $secPass);"
                invoke_block = f"{cred_block} Invoke-Command -ComputerName '{target}' -Credential $cred -ScriptBlock {{ {ps_remote_script} }}"
            else:
                invoke_block = f"Invoke-Command -ComputerName '{target}' -ScriptBlock {{ {ps_remote_script} }}"

            cmd.extend(["-Command", invoke_block])

            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)

            if proc.returncode == 0:
                raw_out = proc.stdout.strip()
                # Parse JSON findings
                try:
                    # Look for JSON array in stdout
                    json_start = raw_out.find("[")
                    json_end = raw_out.rfind("]")
                    if json_start != -1 and json_end != -1:
                        findings = json.loads(raw_out[json_start:json_end + 1])
                        result["status"] = "SUCCESS"
                        result["findings"] = findings
                    else:
                        result["status"] = "SUCCESS"
                        result["findings"] = []
                except json.JSONDecodeError as jde:
                    result["status"] = "ERROR"
                    result["error"] = f"Failed to parse remote JSON output: {jde} | Raw: {raw_out[:300]}"
            else:
                result["status"] = "ERROR"
                result["error"] = proc.stderr.strip() or f"Process exited with code {proc.returncode}"

        except subprocess.TimeoutExpired:
            result["status"] = "TIMEOUT"
            result["error"] = "Remote scan timed out after 120 seconds"
        except Exception as e:
            result["status"] = "ERROR"
            result["error"] = str(e)

        return result

    def run_all(self) -> Dict[str, Any]:
        """
        Execute scan on all targets, generate consolidated report and audit log.
        """
        self.logger.info("Starting remote fleet scan against %d host(s)...", len(self.targets))
        start_time = datetime.now(timezone.utc)

        for target in self.targets:
            target_res = self.execute_remote_scan(target.strip())
            self.consolidated_results[target] = target_res
            status = target_res["status"]
            cnt = len(target_res.get("findings", []))
            self.logger.info("Target %s finished with status: %s (Findings: %d)", target, status, cnt)

        duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        self.write_consolidated_log(duration)
        self.render_summary(duration)

        return self.consolidated_results

    def render_summary(self, duration: float) -> None:
        """
        Print multi-host fleet summary to console.
        """
        print("\n" + "=" * 80)
        print("                     REMOTE FLEET SECURITY SCAN SUMMARY")
        print("=" * 80)
        print(f"Total Targets: {len(self.targets)} | Total Duration: {duration:.2f}s\n")

        header = f"{'Target':<24} {'Status':<10} {'Total':<8} {'ALERT':<8} {'WARN':<8} {'INFO':<8}"
        print(header)
        print("-" * len(header))

        for target, res in self.consolidated_results.items():
            status = res.get("status", "UNKNOWN")
            findings = res.get("findings", [])
            alerts = sum(1 for f in findings if f.get("severity") == "ALERT")
            warns = sum(1 for f in findings if f.get("severity") == "WARN")
            infos = sum(1 for f in findings if f.get("severity") == "INFO")
            print(f"{target:<24} {status:<10} {len(findings):<8} {alerts:<8} {warns:<8} {infos:<8}")

        print("=" * 80)

    def write_consolidated_log(self, duration: float) -> None:
        """
        Write structured audit log covering all remote hosts.
        """
        try:
            with open(self.output_file, "w", encoding="utf-8") as f:
                f.write("=" * 80 + "\n")
                f.write("CONSOLIDATED REMOTE DEFENSIVE SCAN AUDIT LOG\n")
                f.write(f"Generated: {datetime.now(timezone.utc).isoformat()}\n")
                f.write(f"Targets Scanned: {len(self.targets)}\n")
                f.write(f"Scan Duration:   {duration:.2f} seconds\n")
                f.write("=" * 80 + "\n\n")

                for target, res in self.consolidated_results.items():
                    f.write(f"\n--- TARGET: {target} (Status: {res.get('status')}) ---\n")
                    if res.get("error"):
                        f.write(f"Error: {res.get('error')}\n")

                    findings = res.get("findings", [])
                    if not findings:
                        f.write("No indicators or threats detected on this host.\n")
                    else:
                        for idx, item in enumerate(findings, 1):
                            f.write(f"  [{idx}] [{item.get('severity')}] [{item.get('category')}]\n")
                            f.write(f"      Time:        {item.get('timestamp')}\n")
                            f.write(f"      Description: {item.get('description')}\n")
                            f.write(f"      Evidence:    {item.get('evidence')}\n")
                            f.write("\n")

            self.logger.info("Consolidated remote log successfully saved to: %s", os.path.abspath(self.output_file))
        except (OSError, PermissionError) as e:
            self.logger.error("Failed to write consolidated log to %s: %s", self.output_file, e)


def main() -> int:
    parser = argparse.ArgumentParser(description="Remote Defensive Security Scanner Orchestrator via WinRM")
    parser.add_argument("targets", nargs="*", help="Remote hostnames or IP addresses to scan")
    parser.add_argument("--targets-file", "-f", help="File containing target hostnames/IPs (one per line)")
    parser.add_argument("--username", "-u", help="Remote Windows administrative username")
    parser.add_argument("--password", "-p", help="Remote Windows administrative password")
    parser.add_argument("--output", "-o", default="remote_defensive_scan_log.txt", help="Consolidated output log file")
    parser.add_argument("--module", "-m", nargs="+", help="Specific detector module(s) to execute on targets")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose debug logging")

    args = parser.parse_args()

    target_list = list(args.targets)
    if args.targets_file and os.path.isfile(args.targets_file):
        with open(args.targets_file, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    target_list.append(stripped)

    if not target_list:
        parser.print_help()
        print("\n[!] Error: At least one remote target must be provided via arguments or --targets-file.")
        return 1

    orchestrator = RemoteScannerOrchestrator(
        targets=target_list,
        username=args.username,
        password=args.password,
        output_file=args.output,
        modules=args.module,
        verbose=args.verbose
    )

    results = orchestrator.run_all()

    # Exit code: 2 if any ALERT, 1 if any WARN, 0 if clean
    highest_sev = "INFO"
    for r in results.values():
        for f in r.get("findings", []):
            sev = f.get("severity")
            if sev == "ALERT":
                return 2
            elif sev == "WARN":
                highest_sev = "WARN"

    return 1 if highest_sev == "WARN" else 0


if __name__ == "__main__":
    sys.exit(main())
