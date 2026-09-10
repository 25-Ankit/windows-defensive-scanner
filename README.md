# Windows Defensive Security Scanner

A modular, read-only defensive security auditing and threat detection tool for Windows 10, Windows 11, and Windows Server 2016+ (Python 3.8+).

Designed for incident response, threat hunting, and host integrity auditing, the scanner identifies indicators of compromise (IOCs), autostart persistence mechanisms, process masquerading, credential theft attempts, covert surveillance, and stealth installations without altering system state or introducing destructive actions.

---

## Problem Being Solved

Windows endpoints in enterprise and lab environments are frequently targeted with stealth persistence mechanisms, LOLBAS (Living-off-the-Land Binaries and Scripts), and userland tradecraft that bypass basic antivirus signatures:
* Executables and scripts dropped into user-writable directories (`%TEMP%`, `%APPDATA%`, `C:\Users\*`).
* Masquerading processes that mimic critical Windows binaries (`svchost.exe`, `lsass.exe`, `csrss.exe`) from unauthorized paths, or utilize visual lookalikes and homoglyph typosquatting (`svch0st.exe`, `1sass.exe`).
* Native memory dumping of LSASS via LOLBAS utilities (`comsvcs.dll #24`) or tools like Mimikatz and PyPyKatz.
* Covert keystroke interception via `AppInit_DLLs` registry injection or keyboard hook APIs (`SetWindowsHookEx`, `WH_KEYBOARD_LL`, `GetAsyncKeyState`).
* Unauthorized remote access tools, covert VNC servers, and scheduled screen capture scripts.
* Stealth services with stripped display names or unquoted service paths subject to CWE-428 hijacking.

The Windows Defensive Security Scanner provides defenders, analysts, and incident responders with an automated, lightweight, non-destructive tool to audit endpoints locally or across fleets via WinRM.

---

## Architecture

The scanner is built on a modular design utilizing standard Python libraries, with optional performance enhancements when `psutil` or `wmi` are available:

```
windows_defensive_scanner/
├── scanner.py                         # Local CLI orchestrator and report generator
├── remote_scanner.py                  # Remote WinRM orchestrator and fleet aggregator
├── requirements.txt                   # Optional enhancement packages
├── README.md                          # Documentation and schema specification
├── .github/workflows/ci.yml           # Cross-platform GitHub Actions CI pipeline
├── detectors/
│   ├── __init__.py                    # Module exports
│   ├── base_detector.py               # BaseDetector class with shared telemetry helpers
│   ├── finding.py                     # Standardized Finding schema model
│   ├── scoring.py                     # Transparent heuristic scoring engine
│   ├── allowlist.py                   # Centralized false-positive allowlist
│   ├── persistence_detector.py        # Autostart persistence detection
│   ├── process_detector.py            # Process spoofing, masquerading & entropy analysis
│   ├── keylogger_detector.py          # AppInit_DLLs & keyboard hooks
│   ├── credential_theft_detector.py   # LSASS dumping & mimikatz detection
│   ├── surveillance_detector.py       # Covert monitoring & screen capture
│   └── hidden_install_detector.py     # User-writable services & stealth installs
└── tests/                             # Unit, integration, and adversarial test suite (124 tests)
```

### Architectural Principles
1. **Read-Only & Non-Destructive**: Zero modifications to files, registry keys, services, or running processes.
2. **Graceful Degradation**: If an individual data source fails (e.g. registry access permission error or service query failure), remaining checks proceed without aborting the scan.
3. **Cross-Platform Testability**: Uses dependency injection and mock providers, allowing all unit, integration, and adversarial tests to run on both Windows and non-Windows environments (Linux, macOS).
4. **Standardized Schema**: Every detector outputs findings conforming to a unified dictionary model.

---

## Detector Modules

| Module | Category | Primary Detection Techniques & Heuristics |
| :--- | :--- | :--- |
| `persistence_detector.py` | **Persistence** | • Scans HKLM and HKCU `Run`, `RunOnce`, `RunServices`, and `StartupApproved` keys (including `Wow6432Node`).<br>• Flags orphaned autostart entries pointing to non-existent binaries.<br>• Flags entries pointing to user-writable paths (`%TEMP%`, `%APPDATA%`, `C:\Users\*`).<br>• Flags unsigned autostart executables.<br>• Audits User and All Users Startup folders for non-shortcut files (`.exe`, `.bat`, `.vbs`, `.ps1`, `.js`).<br>• Identifies unquoted autostart and service paths containing spaces (CWE-428). |
| `process_detector.py` | **Process Spoofing / AV Evasion** | • Verifies running processes claiming critical system names (`svchost.exe`, `lsass.exe`, `csrss.exe`, `winlogon.exe`, `services.exe`, `smss.exe`, `explorer.exe`) against canonical system paths.<br>• Detects process typosquatting and visual lookalikes using Levenshtein distance and homoglyph mapping (`svch0st.exe`, `1sass.exe`, `scvhost.exe`, `csrs.exe`, `winlog0n.exe`, `services32.exe`).<br>• Identifies trailing whitespace or dot abuse (`svchost.exe `).<br>• Scans process command lines for offensive tool indicators (`mimikatz`, `meterpreter`, `cobaltstrike`, `beacon`, `stealer`, etc.).<br>• Flags unsigned or untrusted binaries running from system directories (`System32`, `SysWOW64`).<br>• Measures Shannon entropy on the first 4KB of executables, flagging packed or encrypted PE binaries ($H > 7.5$). |
| `keylogger_detector.py` | **Keylogging** | • Inspects `AppInit_DLLs` and `LoadAppInit_DLLs` in 32-bit and 64-bit registry hives for global DLL injection.<br>• Audits loaded modules (DLLs) of running processes for third-party hook libraries (`hook`, `keylog`), filtering out legitimate signed system DLLs.<br>• Scans process arguments for keyboard interception APIs (`SetWindowsHookEx`, `WH_KEYBOARD`, `WH_KEYBOARD_LL`, `GetAsyncKeyState`, `GetKeyboardState`, `RegisterRawInputDevices`). |
| `credential_theft_detector.py` | **Credential Theft** | • Detects process command lines invoking known dumping tools (`mimikatz`, `sekurlsa`, `wce`, `pwdump`, `procdump`, `safetykatz`, `nanodump`, `sharpsecdump`, `lazagne`, `pypykatz`, `dumpert`).<br>• Detects command lines targeting LSASS memory (`lsass` combined with `dump`, `minidump`, `inject`, or `read`).<br>• Detects native LOLBAS memory dumping via `comsvcs.dll` (`rundll32.exe ... comsvcs.dll, #24` or `MiniDump`).<br>• Heuristic evaluation of LSASS process access permissions and elevated token privileges (`SeDebugPrivilege`). |
| `surveillance_detector.py` | **Covert Surveillance** | • Detects processes or services associated with covert screen capture, webcam/microphone recording, or hidden VNC.<br>• Whitelists legitimate system and virtualization tools (`mstsc.exe`, `vmware`, `vmtoolsd.exe`, `vboxservice.exe`, `perfmon.exe`, `taskmgr.exe`).<br>• Analyzes Scheduled Tasks for automated screenshot grabbers (PowerShell scripts invoking `CopyFromScreen`, `System.Drawing`, `Graphics`, `nircmd`, `ffmpeg -f gdigrab`). |
| `hidden_install_detector.py` | **Hidden Installation** | • Enumerates Windows services and scheduled tasks whose executable paths point to `%TEMP%`, `%APPDATA%`, or user profile directories.<br>• Identifies auto-start services lacking display names or descriptions.<br>• Flags unquoted service and task paths containing spaces (CWE-428). |

---

## Detection Methodology

The scanner employs a multi-tiered inspection model:
1. **Host Context & Privilege Evaluation**: Verifies administrator elevation status to adjust scan depth (certain features, such as inspecting LSASS handles and HKLM system hives, require elevation).
2. **Cascading Telemetry Providers**: Collects system state via `psutil` or `wmi` when present, falling back gracefully to native Windows command utilities (`tasklist.exe`, `schtasks.exe`, PowerShell CIM cmdlets) or mock providers during testing.
3. **Multi-Signal Contextual Correlation**: Rather than relying on isolated keyword matches, detections correlate path trust (system vs. user-writable), Authenticode signature verification, binary Shannon entropy, and command line semantics.
4. **Centralized Allowlist Filtering**: Software names that match known benign utilities (e.g. Chrome, VS Code) are verified against execution paths; if an allowlisted name executes from an untrusted location like `%TEMP%`, the allowlist is bypassed to catch process masquerading.

---

## Finding Schema

Every detector outputs findings using the standardized `Finding` class (`detectors/finding.py`), which subclasses `dict` for 100% backward compatibility with dictionary lookups, iteration, and standard JSON serialization:

```json
{
  "finding_id": "FIND-8A4F1D9C3E2B",
  "rule_id": "RULE-PERSIST-RUN-TEMP",
  "category": "Persistence",
  "severity": "ALERT",
  "confidence": 0.85,
  "risk_score": 80,
  "description": "Registry autostart points to a temporary, user-writable, or non-standard directory",
  "evidence": "Registry Key: HKCU\\Software\\...\\Run\\DiscordUpdate | Target: C:\\Users\\Victim\\AppData\\Local\\Temp\\updater.exe",
  "recommendation": "Investigate the binary in the user-writable path and remove the autostart entry if unauthorized.",
  "timestamp": "2026-09-10T14:30:15.123456+00:00",
  "host": "TARGET-PC01",
  "process": "DiscordUpdate",
  "pid": null,
  "path": "C:\\Users\\Victim\\AppData\\Local\\Temp\\updater.exe",
  "risk_factors": [
    "Base ALERT severity: +45",
    "User writable path: +20",
    "Suspicious persistence: +15",
    "Multiple indicators: +10"
  ]
}
```

### Schema Fields
| Field | Type | Description |
| :--- | :--- | :--- |
| `finding_id` | `str` | Unique finding identifier (`FIND-<12_HEX_DIGITS>`). |
| `rule_id` | `str` or `null` | Stable rule identifier (e.g. `RULE-PROC-MASQUERADE`). |
| `category` | `str` | Threat category (`Persistence`, `Process Spoofing`, `Keylogging`, etc.). |
| `severity` | `str` | Severity classification (`CRITICAL`, `ALERT`, `WARN`, `INFO`). |
| `confidence` | `float` | Estimated confidence level bounded between `0.05` and `0.99`. |
| `risk_score` | `int` | Explainable composite risk score bounded between `0` and `100`. |
| `description` | `str` | Human-readable explanation of the anomaly. |
| `evidence` | `str` | Factual technical evidence string. |
| `recommendation` | `str` or `null` | Remediation and investigative guidance. |
| `timestamp` | `str` | ISO-8601 UTC timestamp. |
| `host` | `str` | Hostname where the anomaly was observed. |
| `process` | `str` or `null` | Process name associated with finding (if applicable). |
| `pid` | `int` or `null` | Integer process ID (if applicable). |
| `path` | `str` or `null` | File, registry key, or task path (if applicable). |
| `risk_factors` | `list[str]` | Transparent breakdown of point contributions to the risk score. |

---

## Risk Scoring Model

The scanner features a centralized, explainable heuristic scoring engine (`detectors/scoring.py`). 

> **Important Note:** This scoring system is strictly heuristic and deterministic. It does not use machine learning, probability distributions, or claim scientifically validated malware classification.

### Scoring Formula
$$\text{Risk Score} = \text{clamp}_{[0, 100]}\left(\text{Base Score} + \sum \text{Signal Weights} + \sum \text{Reductions}\right)$$

### Point Contributions
* **Base Scores by Severity**:
  * `CRITICAL`: 60
  * `ALERT` (High): 45
  * `WARN` (Medium): 25
  * `INFO` (Low): 10
* **Positive Signal Weights**:
  * `known_attack_tool` (Mimikatz, PyPyKatz, procdump, nanodump, comsvcs dump): +25
  * `process_masquerading` (Typosquatting lookalike or canonical path violation): +25
  * `user_writable_path` (Execution from `%TEMP%`, `%APPDATA%`, `C:\Users\*`): +20
  * `unsigned_binary` (Untrusted or missing Authenticode signature): +15
  * `high_entropy` (Shannon entropy > 7.5 indicating packed/compressed PE): +15
  * `suspicious_cmdline` (Hooks, memory dump syntax, SeDebugPrivilege): +15
  * `suspicious_persistence` (Direct script in startup folder, AppInit_DLLs): +15
  * `unquoted_path` (CWE-428 search path vulnerability): +10
  * `stealth_profile` (Auto-start service missing display name or description): +10
  * `multiple_indicators` (Two or more independent positive signals present): +10
* **Mitigating Reductions**:
  * `allowlist_match` (Verified benign application or service): -30
  * `standard_system_path` (Resides in canonical `C:\Windows` or `C:\Program Files`): -15

---

## Installation

### Prerequisites
* Windows 10, Windows 11, or Windows Server 2016+ (Local execution)
* Python 3.8 or higher installed and added to `PATH`
* Administrator privileges recommended for complete visibility into LSASS, system services, and HKLM registry hives.

### 1. Clone Repository
```cmd
git clone https://github.com/example/windows-defensive-scanner.git
cd windows-defensive-scanner
```

### 2. (Optional) Install Dependencies
The core scanner operates using Python's standard library alone. For enhanced process memory mapping, WMI querying, and legacy console coloring:
```cmd
pip install -r requirements.txt
```

---

## Usage

### Full Scan (Default)
```cmd
python scanner.py
```

### Run Specific Detection Modules
```cmd
python scanner.py -m persistence credential_theft
```

### Specify Output Log Path
```cmd
python scanner.py -o C:\Logs\host_audit.txt
```

### JSON Output Mode (Machine-Readable)
```cmd
python scanner.py --json > findings.json
```

### Verbose Execution Logging
```cmd
python scanner.py -v
```

---

## CLI Examples

### Command Line Flags (`scanner.py`)
| Flag | Short | Description |
| :--- | :--- | :--- |
| `--output <path>` | `-o` | Specify path for the output audit log file (default: `defensive_scan_log.txt`) |
| `--module <name...>`| `-m` | Specific module(s) to run (`persistence`, `process`, `keylogger`, `credential_theft`, `surveillance`, `hidden_install`) |
| `--json` | | Output pure machine-readable JSON to stdout (suppresses console banner and tables) |
| `--no-color` | | Disable ANSI terminal color codes |
| `--verbose` | `-v` | Enable verbose debugging output |
| `--help` | `-h` | Display usage instructions |

### Sample Console Output
```
================================================================================
Windows Defensive Security Scanner
================================================================================
Host:      WORKSTATION-01
Scan type: Full
Duration:  1.45s

Findings
--------
CRITICAL: 0
HIGH:     2
MEDIUM:   1
LOW:      0

================================================================================
                            SCAN FINDINGS DETAILS
================================================================================

[1] [HIGH / ALERT] Process Spoofing / AV Evasion (2026-09-10T14:30:12.105432+00:00)
    Finding ID:     FIND-4B9A7C1E2D3F
    Rule ID:        RULE-PROC-MASQUERADE
    Severity:       ALERT
    Confidence:     0.85
    Risk score:     80
    Description:    System process 'svchost.exe' running from unauthorized location (Process Masquerading)
    Evidence:       PID: 8420 | Process: svchost.exe | Path: C:\Users\Public\svchost.exe | Expected: c:\windows\system32\svchost.exe
    Recommendation: Terminate the masquerading process, capture memory/disk artifacts, and investigate parent process.
    Risk factors:   Base ALERT severity: +45, Process masquerading: +25, Multiple indicators: +10

[2] [HIGH / ALERT] Credential Theft (2026-09-10T14:30:12.112001+00:00)
    Finding ID:     FIND-9D8E7F6A5B4C
    Rule ID:        RULE-CRED-TOOL
    Severity:       ALERT
    Confidence:     0.80
    Risk score:     70
    Description:    Known credential dumping tool identified: ['mimikatz']
    Evidence:       PID: 9112 | Process: mimikatz.exe | Cmdline: mimikatz.exe privilege::debug sekurlsa::logonpasswords
    Recommendation: Isolate host immediately, investigate executing user account, and terminate dumping process.
    Risk factors:   Base ALERT severity: +45, Known attack tool: +25

[3] [MEDIUM / WARN] Hidden Installation (2026-09-10T14:30:12.118945+00:00)
    Finding ID:     FIND-1A2B3C4D5E6F
    Rule ID:        RULE-HIDDEN-SVC-UNQUOTED
    Severity:       WARN
    Confidence:     0.55
    Risk score:     35
    Description:    Service contains unquoted path with spaces (CWE-428 unquoted search path vulnerability)
    Evidence:       Service: VulnerableAppService | Path: C:\Program Files\Vulnerable App\service.exe
    Recommendation: Enclose the service binary path in quotation marks to prevent CWE-428 search path hijacking.
    Risk factors:   Base WARN severity: +25, Unquoted path: +10

================================================================================
                               SCAN SUMMARY
================================================================================
Total Scan Duration: 1.45 seconds
Total Findings:      3
  - CRITICAL (Critical): 0
  - HIGH / ALERT (High):   2
  - MEDIUM / WARN (Medium): 1
  - LOW / INFO (Low):       0

Category Breakdown:
  * Credential Theft                : 1
  * Hidden Installation             : 1
  * Process Spoofing / AV Evasion   : 1
================================================================================
```

---

## JSON Example

When invoked with `--json`, human-readable banners, module progress lines, and summary tables are suppressed from stdout. Standard output provides machine-readable output:

```cmd
python scanner.py --json > findings.json
```

```json
--- JSON OUTPUT ---
[
  {
    "finding_id": "FIND-8A4F1D9C3E2B",
    "rule_id": "RULE-CRED-TOOL",
    "category": "Credential Theft",
    "severity": "ALERT",
    "confidence": 0.80,
    "risk_score": 70,
    "description": "Known credential dumping tool identified: ['mimikatz']",
    "evidence": "PID: 4920 | Process: mimikatz.exe | Cmdline: mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\"",
    "recommendation": "Isolate host immediately, investigate executing user account, and terminate dumping process.",
    "timestamp": "2026-09-10T14:30:12.000000+00:00",
    "host": "TARGET-PC01",
    "process": "mimikatz.exe",
    "pid": 4920,
    "path": "C:\\Tools\\mimikatz.exe",
    "risk_factors": [
      "Base ALERT severity: +45",
      "Known attack tool: +25"
    ]
  }
]
```

---

## Exit Codes

The scanner emits scriptable exit codes suitable for CI/CD or security automation pipelines:
* `0` — Clean scan (no `ALERT`, `CRITICAL`, or `WARN` findings).
* `1` — Suspicious items or anomalies detected (`WARN` level).
* `2` — High-severity threats or IOCs detected (`ALERT` or `CRITICAL` level).

---

## Remote Endpoint Scanning via WinRM (`remote_scanner.py`)

`remote_scanner.py` orchestrates multi-host security audits across remote Windows endpoints using native WinRM / PowerShell Remoting without requiring permanent agent installations:
1. Dynamically bundles `scanner.py` and `detectors/` into an in-memory zip archive.
2. Deploys the package to target machines under `$env:TEMP\DefScanner_<guid>`.
3. Executes `scanner.py --json --no-color`.
4. Retrieves JSON findings over standard output.
5. Reliably wipes staging directories in a `finally` block on target endpoints.
6. Generates a consolidated audit log (`remote_defensive_scan_log.txt`).

### Remote Execution Commands
```cmd
# 1. Scan a remote host using Integrated Windows Authentication (Kerberos SSO)
python remote_scanner.py TARGET-PC01

# 2. Scan remote hosts passing password via environment variable (recommended)
set DEFSCAN_PASSWORD=SecretPassword123!
python remote_scanner.py 192.168.1.50 192.168.1.51 -u "DOMAIN\Admin"

# 3. Scan remote hosts with interactive password prompt
python remote_scanner.py TARGET-SRV02 -u "DOMAIN\Admin"

# 4. Scan a fleet using a targets file
python remote_scanner.py --targets-file endpoints.txt -u "DOMAIN\Admin" -o fleet_audit.txt
```

---

## Security Considerations & Credential Handling

* **No Hard-Coded Credentials**: Passwords are never stored in source files, config files, or audit logs.
* **Process Table Protection**: Subprocess invocation feeds credentials to PowerShell through standard input (`-Command -`) and private subprocess environment variables (`DEFSCAN_TARGET_PASS`) rather than CLI argument strings, preventing credential exposure in process listings (`Get-Process`, `ps`).
* **Recursive Redaction**: Error strings, remote exceptions, and output dictionaries recursively redact cleartext passwords (`[REDACTED]`).
* **Target & Username Validation**: Enforces strict regex validation on hostnames and usernames before script block interpolation to prevent command injection.
* **Temporary Artifact Cleanup**: Remote staging folders are wiped inside a guaranteed `finally` block on target machines.

---

## Limitations

* **Kernel-Level Rootkits & Filter Drivers**: Filter driver keyloggers (e.g. hooking `kbdclass.sys`) operate below user-mode Windows APIs. They do not appear in user-space loaded modules or `AppInit_DLLs`. Detecting kernel rootkits requires driver signature enforcement auditing (`sigcheck -k`), kernel memory analysis, or dedicated EDR sensors.
* **In-Memory Process Injection / Process Hollowing**: If malicious shellcode is injected directly into an already-running, legitimately signed process (e.g. `explorer.exe`) without modifying its on-disk binary or command line, userland process enumeration displays the legitimate binary path. Detecting process hollowing requires thread start address analysis or memory scanning (e.g. `pe-sieve` / `moneta`).
* **WinRM & Network Transport**: Remote scanning requires WinRM (TCP 5985/5986) enabled on target endpoints and administrative privileges. Unencrypted WinRM over untrusted workgroups without Kerberos/SPNEGO is vulnerable to interception and not recommended.
* **Remote Python Requirement**: Remote endpoints must have Python 3.x installed and present in `PATH`.

---

## False-Positive Considerations

* **Centralized Allowlisting**: Broad keyword matching can flag legitimate developer tools (e.g. Chrome with `--enable-logging`, Python scripts with logging modules, VS Code windows). The scanner uses `detectors/allowlist.py` to recognize standard software in canonical directories.
* **Location Sensitivity**: Allowlisting strictly respects file paths. A process named `chrome.exe` running from `C:\Users\Public` or `%TEMP%` is **never** allowlisted, ensuring masquerading malware cannot evade detection.
* **Compounding Evidence**: A single ambiguous keyword (`logger`, `hidden`, `c2`) on standard software does not trigger an ALERT unless accompanied by additional indicators (such as execution from user-writable paths or unsigned binaries).

---

## Testing

The scanner includes an automated test suite containing 124 unit, integration, and adversarial tests:

```bash
pytest -v --durations=10
```

### Test Coverage
* `test_base_detector.py`: Base entropy calculation, path extraction, and privilege checks.
* `test_finding_model.py`: Schema conformity, type safety, JSON serialization, and bounding.
* `test_scoring_engine.py`: Heuristic scoring, compounding indicator bonuses, allowlist reductions, and boundary limits.
* `test_false_positive_reduction.py`: Legitimate software allowlisting, user-writable override protections, and keyword ambiguity handling.
* `test_adversarial_degradation.py`: Exercises all 15 failure scenarios (missing dependencies, permission rejections, malformed rows, corrupt processes, empty cmdlines).
* `test_cli_reporting_enhanced.py`: Human-readable summary output, JSON mode suppression, ISO timestamps, and exit codes.
* `test_remote_scanner_security.py`: Stdin credential passing, password redaction, input validation, and SSO authentication.
* `test_hard_scenarios.py`: Typosquatting, homoglyphs, trailing whitespace, 8.3 paths, and LOLBAS dumps.
* `test_usermode_applications.py`: User-mode threat simulations (keyloggers, stealers, surveillance, packed droppers).
* `test_end_to_end.py`: End-to-end requirement scenarios and full scan pipeline execution.

---

## Continuous Integration (CI/CD)

Automated testing is configured via GitHub Actions (`.github/workflows/ci.yml`):
* Tested across operating systems: `ubuntu-latest` and `windows-latest`.
* Tested across Python versions: `3.8`, `3.9`, `3.10`, `3.11`, `3.12`, `3.13`.
* Enforces syntax compilation (`python -m py_compile`) and test execution (`pytest`).

---

## Defensive / Read-Only Disclaimer

This project is strictly a defensive, read-only security auditing tool. It does not perform destructive actions, process termination, file deletion, registry remediation, malware deployment, persistence installation, credential theft, or surveillance. It is intended solely for security analysts, incident responders, and system administrators to audit Windows endpoints defensively.

---

## Roadmap

* [ ] Structured export formats for SARIF and STIX 2.1.
* [ ] Local event log auditing (Security Event IDs 4688, 4697, 7045) via standard library APIs.
* [ ] Hash-based threat intelligence lookup against local offline IOC databases.
* [ ] Native YARA rule scanning integration for suspicious autostart executables.

---

## License

This project is licensed under the MIT License. See the LICENSE file for details.
