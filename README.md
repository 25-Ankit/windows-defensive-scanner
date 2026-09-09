# Windows Defensive Security Scanner

A modular, production-ready, read-only defensive security scanning application for Windows 10 and 11 (Python 3.8+).

Designed for incident response, threat hunting, and host integrity auditing, the scanner identifies indicators of compromise (IOCs), persistence mechanisms, process masquerading, credential theft attempts, covert surveillance, and stealth installations without altering system state.

---

## Key Features & Detection Modules

| Module | Category | Detection Techniques & Heuristics |
| :--- | :--- | :--- |
| `persistence_detector.py` | **Persistence** | • Scans HKLM and HKCU `Run`, `RunOnce`, `RunServices`, `StartupApproved\Run`, and `StartupApproved\Run32` keys (including `Wow6432Node`).<br>• Flags entries pointing to non-existent binaries (orphan/stealth persistence), user-writable paths (`%TEMP%`, `%APPDATA%`), or non-standard folders.<br>• Flags unsigned autostart executables.<br>• Scans User and All Users Startup folders for non-shortcut executables/scripts (`.exe`, `.bat`, `.vbs`, `.ps1`, `.js`).<br>• Flags services and scheduled tasks configured to run from user-writable directories. |
| `process_detector.py` | **Process Spoofing / AV Evasion** | • Validates running process binary paths against legitimate canonical Windows paths (e.g. `svchost.exe`, `lsass.exe`, `csrss.exe`, `winlogon.exe`, `services.exe`, `smss.exe`, `explorer.exe`).<br>• Detects process name typosquatting and visual lookalikes using Levenshtein distance and homoglyph/l33tspeak normalization (e.g. `svch0st.exe`, `scvhost.exe`, `lsas.exe`, `1sass.exe`, `csrs.exe`, `winlog0n.exe`, `services32.exe`).<br>• Flags trailing whitespace or dot abuse in process names (`svchost.exe `).<br>• Detects processes with suspicious offensive keywords in names or command line arguments (`keylog`, `rat`, `stealer`, `beacon`, `meterpreter`, `c2`, etc.).<br>• Checks digital signatures of binaries residing in system directories (`System32`, `SysWOW64`) to catch dropped malware.<br>• Computes Shannon entropy on the first 4KB of executables; flags entropy > 7.5 (packed or encrypted PE binaries). |
| `keylogger_detector.py` | **Keylogging** | • Inspects `AppInit_DLLs` and `LoadAppInit_DLLs` in 32-bit and 64-bit registry hives for global DLL injection.<br>• Enumerates loaded modules of running processes and flags third-party DLLs containing `hook` or `keylog`.<br>• Scans active process command lines for keyboard interception APIs and hook keywords (`SetWindowsHookEx`, `WH_KEYBOARD`, `WH_KEYBOARD_LL`, `GetAsyncKeyState`, `GetKeyboardState`, `RegisterRawInputDevices`). |
| `credential_theft_detector.py` | **Credential Theft** | • Detects invocation of known credential dumpers (`mimikatz`, `sekurlsa`, `wce`, `pwdump`, `fgdump`, `procdump`, `safetykatz`, `nanodump`, `sharpsecdump`, `lazagne`, `pypykatz`, `dumpert`).<br>• Detects command lines targeting LSASS memory (`lsass` combined with `dump`, `minidump`, `inject`, or `read`).<br>• Detects native LOLBAS memory dumping via `comsvcs.dll` (`rundll32.exe ... comsvcs.dll, #24` or `MiniDump`).<br>• Heuristic evaluation of `lsass.exe` process access permissions and elevated token privileges (`SeDebugPrivilege`). |
| `surveillance_detector.py` | **Covert Surveillance** | • Detects processes or services associated with covert screen capture, webcam/microphone recording, remote access, or VNC.<br>• Filters out legitimate system and virtualization tools (`mstsc.exe`, `vmware`, `vmtoolsd.exe`, `vboxservice.exe`, `perfmon.exe`, `taskmgr.exe`).<br>• Analyzes Scheduled Tasks for automated screenshot grabbers (e.g. PowerShell scripts invoking `CopyFromScreen`, `System.Drawing`, `Graphics`). |
| `hidden_install_detector.py` | **Hidden Installation** | • Enumerates Windows services and scheduled tasks whose executable paths point to `%TEMP%`, `%TMP%`, `%APPDATA%`, `%LOCALAPPDATA%`, or `C:\Users\*`.<br>• Identifies auto-start services lacking display names or descriptions (common in stealth implants). |

---

## Architectural Principles

1. **Read-Only & Non-Destructive**: The scanner performs zero modification to files, registries, services, or processes. It acts strictly as an observer and auditor.
2. **Graceful Degradation**: Built using Python's standard library. It automatically utilizes `psutil` or `wmi` when available, and gracefully falls back to native Windows utilities (`tasklist`, `schtasks`, `powershell`) if optional dependencies are absent.
3. **Structured Finding Format**: Every detector returns a list of standardized dictionaries:
   ```python
   {
       "category": "Persistence",
       "severity": "ALERT",          # INFO, WARN, ALERT
       "description": "Registry autostart points to a temporary or user-writable directory",
       "evidence": "Registry Key: HKCU\\... | Target: C:\\Temp\\evil.exe",
       "timestamp": "2026-09-09T16:00:00Z"
   }
   ```
4. **Dual Output**: Findings are color-coded in the terminal console and simultaneously exported to an audit log file (`defensive_scan_log.txt`).

---

## Project Structure

```
windows_defensive_scanner/
├── scanner.py                       # Main CLI entrypoint and orchestrator
├── requirements.txt                 # Optional enhancement packages
├── README.md                        # Documentation
├── defensive_scan_log.txt           # Scan report output (generated on execution)
├── detectors/
│   ├── __init__.py                  # Detector exports
│   ├── base_detector.py             # BaseDetector class with shared helpers
│   ├── persistence_detector.py      # Autostart persistence detection
│   ├── process_detector.py          # Process spoofing & entropy analysis
│   ├── keylogger_detector.py        # AppInit_DLLs & keyboard hooks
│   ├── credential_theft_detector.py # LSASS dumping & mimikatz detection
│   ├── surveillance_detector.py     # Covert monitoring & screen capture
│   └── hidden_install_detector.py   # User-writable services & stealth installs
└── tests/
    ├── __init__.py
    ├── conftest.py                  # Pytest fixtures and mock data
    ├── test_base_detector.py        # BaseDetector unit tests
    ├── test_persistence_detector.py # Persistence unit tests
    ├── test_process_detector.py     # Process detector unit tests
    ├── test_keylogger_detector.py   # Keylogger detector unit tests
    ├── test_credential_theft_detector.py # Credential theft unit tests
    ├── test_surveillance_detector.py# Surveillance detector unit tests
    ├── test_hidden_install_detector.py # Hidden install unit tests
    ├── test_scanner_cli.py          # CLI flags and exit code tests
    └── test_end_to_end.py           # Integration and requirement scenarios
```

---

## Installation

### Prerequisites
- Windows 10, Windows 11, or Windows Server 2016+
- Python 3.8 or higher installed and added to `PATH`

### 1. Clone or Download the Repository
```cmd
cd C:\Tools\windows_defensive_scanner
```

### 2. (Optional) Install Dependencies
The scanner functions with standard library modules alone. For enhanced performance, higher fidelity process memory mapping, and legacy command prompt coloring:

```cmd
pip install -r requirements.txt
```

---

## Running the Scanner

> **Note on Elevation:** For complete visibility into system processes (such as inspecting LSASS, viewing all service configurations, and querying HKLM registry hives), open Command Prompt or PowerShell with **Run as Administrator**.

### Full Scan (Default)
```cmd
python scanner.py
```

### Run Specific Modules
```cmd
python scanner.py -m persistence credential_theft
```

### Custom Log File Path
```cmd
python scanner.py --output C:\Logs\incident_scan.txt
```

### JSON Output for SIEM / Automated Pipelines
```cmd
python scanner.py --json --no-color > findings.json
```

### Verbose Debugging
```cmd
python scanner.py -v
```

### Command Line Flags
| Flag | Short | Description |
| :--- | :--- | :--- |
| `--output <path>` | `-o` | Specify path for the output audit log file (default: `defensive_scan_log.txt`) |
| `--module <name...>`| `-m` | Execute specific modules (`persistence`, `process`, `keylogger`, `credential_theft`, `surveillance`, `hidden_install`) |
| `--no-color` | | Disable ANSI terminal color codes |
| `--json` | | Print machine-readable JSON array of findings to stdout |
| `--verbose` | `-v` | Enable detailed debug logs |
| `--help` | `-h` | Display usage instructions |

---

## Remote Endpoint Scanning via WinRM (`remote_scanner.py`)

To scan other systems across an Active Directory domain or corporate network, use `remote_scanner.py`. It bundles the scanner into a zero-dependency package, deploys it to target hosts over WinRM / PowerShell Remoting, runs elevated scans, retrieves JSON findings, safely wipes staging artifacts, and aggregates the results into a consolidated audit log.

### Remote Execution Commands

```cmd
# Scan a single remote host
python remote_scanner.py TARGET-PC01 -u "DOMAIN\Admin" -p "Password123"

# Scan multiple remote endpoints
python remote_scanner.py 192.168.1.50 192.168.1.51 TARGET-SRV02 -u "DOMAIN\Admin" -p "Password123"

# Scan a fleet using a targets file
python remote_scanner.py --targets-file endpoints.txt -u "DOMAIN\Admin" -p "Password123"

# Run specific modules on remote targets
python remote_scanner.py TARGET-PC01 -m keylogger process credential_theft -o fleet_audit.txt
```

### Remote Scanner Flags
| Flag | Short | Description |
| :--- | :--- | :--- |
| `targets...` | | One or more remote hostnames or IP addresses |
| `--targets-file` | `-f` | File containing target hostnames/IPs (one per line) |
| `--username` | `-u` | Elevated administrative user (e.g. `DOMAIN\admin`) |
| `--password` | `-p` | Administrative password |
| `--output` | `-o` | Consolidated multi-host audit log (default: `remote_defensive_scan_log.txt`) |
| `--module` | `-m` | Specific module(s) to execute on remote endpoints |
| `--verbose` | `-v` | Enable verbose execution logs |

---

## Exit Codes

The scanner provides scriptable exit codes suitable for CI/CD or incident response pipelines:
- `0` — Clean scan (no `ALERT` or `WARN` findings detected).
- `1` — Suspicious items found (`WARN` level).
- `2` — High-severity threats or indicators of compromise detected (`ALERT` level).

---

## Interpreting Results

### Severity Taxonomy
- **`ALERT`** (Red): High-confidence malicious indicator or active attack technique (e.g., Mimikatz command line, process masquerading, AppInit_DLLs injection, service binary in `%TEMP%`, or packed executable).
- **`WARN`** (Yellow): Anomalous configuration, non-standard path, or orphan autostart entry that warrants manual analyst review.
- **`INFO`** (Cyan): Low-risk contextual data.

### Sample Console Output
```
================================================================================
           WINDOWS DEFENSIVE SECURITY SCANNER - INCIDENT RESPONSE
================================================================================
 Mode: Read-Only / Non-Destructive
 Target OS: Windows 10/11
 Timestamp: 2026-09-09 16:05:12 UTC
 Elevation: Elevated (Administrator)
 System: Windows 10 (10.0.19045)
================================================================================

[*] Running module: PersistenceDetector
    Findings detected: 1
[*] Running module: ProcessDetector
    Findings detected: 1
[*] Running module: KeyloggerDetector
    Findings detected: 0
[*] Running module: CredentialTheftDetector
    Findings detected: 1
[*] Running module: SurveillanceDetector
    Findings detected: 0
[*] Running module: HiddenInstallDetector
    Findings detected: 1

================================================================================
                            SCAN FINDINGS DETAILS
================================================================================

[1] [ALERT] Credential Theft (2026-09-09T16:05:14.218204+00:00)
    Description: Known credential dumping tool identified: ['mimikatz']
    Evidence:    PID: 4920 | Process: mimikatz.exe | Cmdline: mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"

[2] [ALERT] Process Spoofing / AV Evasion (2026-09-09T16:05:14.221532+00:00)
    Description: System process 'svchost.exe' running from unauthorized location (Process Masquerading)
    Evidence:    PID: 8112 | Process: svchost.exe | Path: C:\Users\Public\svchost.exe | Expected: c:\windows\system32\svchost.exe

================================================================================
                               SCAN SUMMARY
================================================================================

Total Scan Duration: 1.84 seconds
Total Findings:      4
  - ALERT (High Risk):  3
  - WARN  (Suspicious)  1
  - INFO  (Low/Inform)  0

Category Breakdown:
  * Credential Theft                : 1
  * Hidden Installation             : 1
  * Persistence                     : 1
  * Process Spoofing / AV Evasion   : 1
================================================================================
```

---

## Extending with New Detectors

To add a new detection module:

1. Create a new file in `detectors/` (e.g. `detectors/network_detector.py`).
2. Inherit from `BaseDetector` and implement the `run()` method:
   ```python
   from .base_detector import BaseDetector
   from typing import List, Dict, Any

   class NetworkDetector(BaseDetector):
       def run(self) -> List[Dict[str, Any]]:
           findings = []
           # Use helper methods like self.enumerate_processes(), self.is_admin()
           # Detect suspicious connections or listening ports...
           findings.append(self.create_finding(
               category="Network Anomaly",
               severity="ALERT",
               description="Suspicious external beacon connection detected",
               evidence="PID: 1234 | Remote: 198.51.100.23:4444"
           ))
           return findings
   ```
3. Export the class in `detectors/__init__.py`.
4. Register the detector in `scanner.py` within `SecurityScanner._initialize_detectors()`.
5. Add unit tests in `tests/`.

---

## Running the Automated Test Suite

The scanner comes with an extensive unit, integration, and evasion test suite (65 test cases):

```bash
pytest -v --durations=5
```

All tests utilize mock data providers and dependency injection, enabling the test suite to execute successfully across both Windows and non-Windows environments:
- **5 Core requirement scenarios**: Persistence, Process Spoofing, AppInit_DLLs, Credential Theft, Hidden Install.
- **24 Hard scenarios**: Levenshtein typosquatting, l33tspeak homoglyphs, trailing whitespace/dot abuse, path traversal evasion, Shannon entropy boundary conditions, LOLBAS `comsvcs.dll` dumps, multi-DLL `AppInit_DLLs`, PowerShell reflection screen grabbers, 8.3 short paths, and remote WinRM orchestration.
- **6 User-mode application threat simulations**: Userland keyloggers (`WH_KEYBOARD_LL` / `GetAsyncKeyState`), credential stealers (`pypykatz` / `comsvcs`), surveillance tools (`winvnc` / GDI screen grabbers), userland masquerading (`svchost.exe` / `svch0st.exe` in `%APPDATA%`), user startup folder script droppers, and full multi-stage userland infection pipeline.
- **30 Base detector, CLI, and individual module unit tests**.

---

## Remote Detection Capability Assessment

### What This Project CAN Detect on Other Systems (via WinRM / Agent)
1. **User-Space Keyloggers**: Identifies `AppInit_DLLs` persistence, loaded DLLs containing hook routines, and processes with command lines invoking `SetWindowsHookEx`, `WH_KEYBOARD_LL`, or `GetAsyncKeyState`.
2. **Active Credential Theft**: Detects command line executions of Mimikatz, Procdump, Sekurlsa, PyPyKatz, and native LOLBAS LSASS dumping via `comsvcs.dll #24`.
3. **Process Masquerading & Typosquatting**: Uncovers processes claiming to be `svchost.exe`, `lsass.exe`, `csrss.exe` running from wrong paths, as well as lookalike names (`svch0st.exe`, `scvhost.exe`, `lsas.exe`).
4. **Packed & Encrypted Payloads**: Measures Shannon entropy on executable PE files, reliably catching packed binaries ($H > 7.5$).
5. **Autostart & Hidden Persistence**: Flags services, scheduled tasks, and Run keys residing in user-writable paths (`%TEMP%`, `%APPDATA%`) or auto-start services with stripped display names.

### Limitations & Defense-in-Depth Context
- **Kernel-Level Keyloggers (Rootkits)**: A filter driver keylogger (e.g. hooking `kbdclass.sys`) operates below user-mode Windows APIs. It does not appear in user-space loaded modules or `AppInit_DLLs`. Detecting kernel rootkits requires driver signature enforcement auditing (`sigcheck -k`), kernel memory inspection, or specialized EDR agents.
- **Process Injection / Hollowing into Legitimate Processes**: If malware injects shellcode directly into an already-running, legitimately signed `svchost.exe` without modifying its disk binary or command line, userland process list inspection will show the legitimate path. Detecting process hollowing requires thread start address analysis or memory scanning (e.g. `pe-sieve` / `moneta`).
- **Network / WinRM Dependency**: Remote scanning requires WinRM (TCP 5985/5986) enabled on target endpoints and elevated administrative credentials (`Domain Admins` or local `Administrators`).
