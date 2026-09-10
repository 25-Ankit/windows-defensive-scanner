# Windows Defensive Security Scanner — System & Architecture Documentation

This document provides a comprehensive technical reference for the **Windows Defensive Security Scanner**, explaining every subsystem, class, and function, detailing the ethical design principles and boundaries, and providing guidance on explaining the system in simple terms.

---

## 1. What the System Does in Simple Terms

### The Elevator Pitch
Think of this application as an **expert building inspector or a non-invasive medical diagnostic scanner** for a Windows computer. 
* It **never touches, alters, or destroys anything**.
* It walks through the computer, inspecting common places where intruders hide, checking if programs are using fake badges (masquerading), checking if anyone is eavesdropping on keystrokes, and checking if anyone is attempting to steal passwords.
* When finished, it provides a transparent, easy-to-read report detailing exactly what it observed, why it flagged it, and what should be investigated.

### Intuitive Analogies for Non-Technical Stakeholders

| Technical Area | Real-World Analogy | What the Scanner Does |
| :--- | :--- | :--- |
| **Autostart Persistence** | **Secret Building Entrances** | Checks if unapproved visitors have rigged doors or windows to open automatically every morning (registry Run keys, Startup folders, auto-start services). |
| **Process Masquerading** | **Fake Security Badges** | Checks if an intruder is wearing a badge that says "Security Guard" (`svchost.exe`), but is wandering around in the basement or temporary storage locker (`C:\Users\Public` or `%TEMP%`) where guards never belong. |
| **Name Typosquatting** | **Misspelled Uniforms** | Catches subtle lookalikes (like `svch0st.exe` or `1sass.exe`) where intruders swap a letter for a zero or number to fool a human glancing at the task list. |
| **Credential Theft** | **Lock-Picking Activity** | Detects known lock-picking tools (like Mimikatz) or programs attempting to tap into the vault holding Windows passwords (LSASS memory). |
| **Keylogging** | **Wiretaps on Keyboards** | Detects global wiretaps (`AppInit_DLLs`) or software attempting to record every key pressed on the physical keyboard. |
| **Covert Surveillance** | **Hidden Microphones & Cameras** | Detects unauthorized screen recorders, hidden VNC remote desktop servers, or scripts taking secret desktop screenshots. |
| **CWE-428 Unquoted Paths** | **Confusing Street Signs** | Identifies file paths with spaces that aren't wrapped in quotation marks, preventing attackers from intercepting legitimate system commands. |

---

## 2. Ethical and Defensive Design Mandates

### A. What Was Included (The Ethical & Defensive Core)

1. **Strictly Read-Only Operation**:
   * The scanner performs **zero destructive actions**: it never kills processes, deletes files, modifies registry values, stops services, or disables tasks.
   * Modifying system state during active incident response can alert adversaries, destroy forensic volatile memory, or cause system downtime. The scanner acts purely as an auditor and observer.

2. **Transparent, Explainable Heuristic Scoring**:
   * The scoring system (`detectors/scoring.py`) uses observable technical signals with explainable point additions (+25 for attack tools, +20 for user-writable paths, etc.).
   * **No False Claims**: The project explicitly rejects claiming that scores are "AI probabilities" or "scientifically validated malware ratings". Every score is explainable down to the exact observable factors.

3. **Strict Credential Protection & Secret Scrubbing**:
   * Remote administrative credentials used for WinRM scanning are **never hardcoded**, never written to source code or disk logs, and never exposed in command line argument lists.
   * Credentials are fed to PowerShell via private subprocess environments and standard input (`-Command -`), avoiding exposure in local process tables (`ps`, `Get-Process`).
   * Remote findings, error messages, and logs are recursively sanitized using `_redact_credentials` to replace cleartext passwords with `[REDACTED]`.

4. **Location-Aware Allowlisting**:
   * Centralized allowlisting (`detectors/allowlist.py`) prevents alert fatigue on benign tools (Chrome, VS Code, Task Manager) while strictly enforcing path verification.
   * If a binary named `chrome.exe` or `svchost.exe` executes from `%TEMP%` or `C:\Users\*`, the allowlist is **bypassed immediately**, preventing adversaries from evading detection via simple renaming.

5. **Fault Isolation and Graceful Degradation**:
   * Detection sub-phases and provider calls are isolated so that permission errors (e.g., SACL access rejection or crashing RPC services) never crash the complete scan.

---

### B. What Was Intentionally NOT Included (The Unethical & Dangerous Boundaries)

| Excluded Functionality | Why It Was Omitted (Ethical & Technical Rationale) |
| :--- | :--- |
| **Automated Remediation / File Deletion** | Deleting files automatically without human analyst confirmation can permanently damage legitimate line-of-business applications, brick operating systems, or corrupt evidence required for legal forensics. |
| **Offensive Exploitation & Weaponization** | No exploits, brute-forcing modules, password cracking, or remote execution payloads. Defensive security requires tools that verify host integrity without creating risk. |
| **Credential Extraction / Memory Dumping** | While the scanner detects other processes attempting to dump LSASS memory, the scanner itself **never dumps credentials or extracts password hashes**. |
| **Process Injection / Hollowing Capabilities** | No memory manipulation, DLL injection, or thread hijacking techniques. The scanner operates exclusively within normal userland and administrative query APIs. |
| **Surveillance or User Keystroke Recording** | The scanner detects surveillance tools and keyloggers; it never records user screens, audio, or keystrokes. |

---

## 3. Subsystem Architecture & Function-by-Function Reference

```
windows_defensive_scanner/
├── scanner.py                 <- Local CLI Orchestrator & Reporting
├── remote_scanner.py          <- Remote WinRM Orchestrator & Credential Safety
├── detectors/
│   ├── base_detector.py       <- Shared Base Class, Provider Hooks & System Helpers
│   ├── finding.py             <- Standardized Finding Schema Model
│   ├── scoring.py             <- Heuristic Scoring & Confidence Calculation
│   ├── allowlist.py           <- Centralized Allowlist & Path Validation
│   ├── persistence_detector.py<- Autostart, Run Keys, Startup Folders
│   ├── process_detector.py    <- Canonical Paths, Typosquatting, Entropy
│   ├── keylogger_detector.py  <- AppInit_DLLs & Keyboard Hook APIs
│   ├── credential_theft_detector.py <- Mimikatz, Procdump, comsvcs LOLBAS
│   ├── surveillance_detector.py     <- Covert VNC, Screen Recorders
│   └── hidden_install_detector.py   <- Stealth Services & Unquoted Paths
```

---

### A. `scanner.py` (Local Orchestration & Reporting)

Orchestrates local detection modules, coordinates console formatting, writes audit logs to disk, and governs exit codes.

#### Classes & Functions
* **`ColorPrinter(enabled: bool)`**:
  * `__init__(enabled)`: Determines whether ANSI escape color codes should be enabled based on terminal support, Windows 10+ ANSI flags, and Colorama availability.
  * `colorize(text, color_code)`: Wraps text in ANSI escape codes and resets styling.
  * `red(text)`, `yellow(text)`, `green(text)`, `cyan(text)`, `bold(text)`, `gray(text)`: Color formatting helper methods.
* **`SecurityScanner`**:
  * `__init__(log_file, color_enabled, verbose, detectors_to_run, json_mode)`: Sets up output paths, console formatting, logging handlers, and instantiates detection modules.
  * `_setup_logging() -> logging.Logger`: Configures stream handlers. If `json_mode` is active, routes logs to `stderr` to prevent polluting `stdout`.
  * `_initialize_detectors() -> List[BaseDetector]`: Instantiates detector classes, selectively loading specified modules if `-m` is provided.
  * `print_banner() -> None`: Prints terminal header with OS version, elevation level, and timestamp (suppressed in `json_mode`).
  * `_get_elevation_str() -> str`: Queries `BaseDetector.is_admin()` and returns a colorized elevation status.
  * `run() -> List[Dict[str, Any]]`: Sequentially executes each detector, aggregates findings, records elapsed duration, triggers report rendering, writes the audit log, and returns the finding list.
  * `render_report(duration: float) -> None`: Displays the human-readable summary table (CRITICAL, HIGH, MEDIUM, LOW counts), followed by detailed finding cards with Finding ID, Rule ID, Severity, Confidence, Risk Score, Description, Evidence, Recommendation, and Risk Factors.
  * `write_log_file() -> None`: Writes structured audit records and category breakdowns to `defensive_scan_log.txt`.
* **`main() -> int`**:
  * Parses CLI flags (`-o`, `-m`, `--json`, `--no-color`, `-v`).
  * Runs the scanner.
  * When `--json` is specified, outputs `--- JSON OUTPUT ---` followed by machine-readable JSON.
  * Returns exit codes: `2` (CRITICAL or ALERT), `1` (WARN), `0` (clean).

---

### B. `remote_scanner.py` (Remote WinRM Fleet Orchestrator)

Coordinates zero-dependency agentless scans across Active Directory fleets and remote endpoints.

#### Classes & Functions
* **`get_powershell_executable() -> str`**: Auto-detects whether `powershell.exe`, `pwsh.exe`, or `pwsh` is installed across Windows, Linux, or macOS.
* **`RemoteScannerOrchestrator`**:
  * `__init__(targets, username, password, output_file, modules, verbose)`: Configures targets, credentials, modules, and consolidated logging.
  * `_setup_logging() -> logging.Logger`: Configures logger for remote execution telemetry.
  * `_redact_credentials(data: Any, secret: str) -> Any`: Recursively traverses dictionaries, lists, strings, and findings to replace occurrences of cleartext passwords with `[REDACTED]`.
  * `build_remote_payload_bundle() -> str`: Compresses `scanner.py` and all `.py` files in `detectors/` into an in-memory ZIP archive, returning a base64 string.
  * `execute_remote_scan(target: str) -> Dict[str, Any]`:
    * Validates target hostname/IP against `TARGET_PATTERN` (rejects shell metacharacters).
    * Validates username against `USERNAME_PATTERN`.
    * Builds remote PowerShell script block to unpack the bundle in `$env:TEMP\DefScanner_<guid>`, execute `python scanner.py --json --no-color`, extract JSON results, and wipe staging artifacts in a `finally` block.
    * Injects credentials via private subprocess environment variable `DEFSCAN_TARGET_PASS` and passes invocation script via stdin (`-Command -`).
    * Parses JSON findings and scrubs credentials from all return structures.
  * `run_all() -> Dict[str, Any]`: Iterates across all targets, aggregates results, prints console summary, and writes consolidated report.
  * `render_summary(duration: float) -> None`: Displays consolidated tabular status (Target, Status, Total Findings, ALERT, WARN, INFO).
  * `write_consolidated_log(duration: float) -> None`: Exports multi-host findings to `remote_defensive_scan_log.txt`.
* **`main() -> int`**:
  * Resolves credentials safely: CLI argument -> `DEFSCAN_PASSWORD` environment variable -> interactive `getpass` prompt.
  * Emits security warning if password was passed via CLI flags.
  * Executes fleet scan and returns highest severity exit code across all targets.

---

### C. `detectors/finding.py` (Standardized Finding Model)

Defines the centralized schema dictionary model.

#### Classes & Functions
* **`Finding(dict)`**:
  * Subclasses Python's built-in `dict` to provide 100% backward compatibility with dictionary lookups (`finding['severity']`) while enabling attribute access (`finding.severity`).
  * `__init__(category, severity, description, evidence, rule_id, confidence, risk_score, recommendation, host, process, pid, path, finding_id, timestamp, signals, risk_factors)`:
    * Standardizes severity to `CRITICAL`, `ALERT`, `WARN`, or `INFO`.
    * Automatically computes heuristic risk score, confidence, and risk factors via `HeuristicScorer` if not explicitly supplied.
    * Sets missing optional fields (`rule_id`, `process`, `pid`, `path`, `recommendation`) to `None` without fabricating data.
  * `__getattr__(name)` / `__setattr__(name, value)`: Enables attribute-style dot notation.
  * `to_dict() -> Dict[str, Any]`: Returns raw Python dictionary.
  * `validate() -> bool`: Verifies that all required schema keys are present and have correct data types.

---

### D. `detectors/scoring.py` (Heuristic Risk Scoring Engine)

Provides transparent, deterministic scoring calculation.

#### Classes & Functions
* **`HeuristicScorer`**:
  * `calculate_score(severity, category, rule_id, signals, base_risk, base_confidence) -> Tuple[int, float, List[str]]`:
    1. Sets base score from severity baseline (`CRITICAL`: 60, `ALERT`: 45, `WARN`: 25, `INFO`: 10).
    2. Seeds active signals from `rule_id` mapping (`RULE_SIGNAL_MAP`).
    3. Merges explicit boolean signal overrides (`signals`).
    4. Evaluates compounding indicators: if $\ge 2$ positive signals are present, adds `multiple_indicators` bonus (+10).
    5. Adds positive signal weights (e.g. +25 for attack tools, +20 for user-writable paths).
    6. Deducts mitigating reductions (e.g. -30 for allowlist matches, -15 for standard paths).
    7. Clamps final risk score to `[0, 100]` and confidence to `[0.05, 0.99]`.
    8. Returns tuple of `(risk_score, confidence, risk_factors)`.

---

### E. `detectors/allowlist.py` (Centralized Allowlist & Path Trust)

Defines benign components and enforces path sensitivity.

#### Functions
* **`is_user_writable_path(path: str) -> bool`**: Evaluates whether a path is located in `%TEMP%`, `%APPDATA%`, `C:\Users\*`, or public folders.
* **`is_allowlisted_process(name: str, exe_path: Optional[str]) -> bool`**:
  * Checks name against benign applications (Chrome, VS Code, VMware Tools, etc.).
  * **Critical Security Enforcement**: Returns `False` if `exe_path` is in a user-writable path, preventing masquerading malware from using benign names.
  * Verifies canonical paths for Windows system binaries (`svchost.exe`, `lsass.exe`, etc.).
* **`is_allowlisted_service(name: str, binpath: Optional[str]) -> bool`**: Checks service against legitimate Windows services, bypassing allowlist if `binpath` is user-writable.
* **`is_allowlisted_dll(module_path_or_name: str) -> bool`**: Checks loaded DLL against known benign system libraries.
* **`register_benign_process(name)`**, **`register_benign_service(name)`**, **`register_benign_dll(name)`**: Enables runtime registration of organization-specific software.
* **`reset_custom_allowlists()`**: Restores baseline allowlist state (used in testing).

---

### F. `detectors/base_detector.py` (Base Detector & Shared Telemetry)

Abstract base class providing telemetry collection and utility methods.

#### Classes & Methods
* **`BaseDetector`**:
  * `__init__(logger)`: Initializes logging and configurable test providers (`process_provider`, `registry_provider`, `service_provider`, `task_provider`, `signature_checker`).
  * `run() -> List[Dict[str, Any]]`: Abstract method implemented by each detector.
  * `create_finding(...) -> Finding`: Centralized finding factory returning structured `Finding` objects.
  * `calculate_heuristic_score(...)`: Helper querying `HeuristicScorer`.
  * `is_admin() -> bool`: Tests for administrative privileges using `ctypes.windll.shell32.IsUserAnAdmin()` on Windows, or `geteuid() == 0` on POSIX.
  * `calculate_entropy(target, max_bytes) -> float`: Calculates Shannon entropy ($H = -\sum p \log_2 p$) on byte streams or the first 4KB of a file. Returns values between 0.0 and 8.0; values $> 7.5$ indicate packing or encryption.
  * `check_digital_signature(file_path) -> Dict[str, Any]`: Verifies Authenticode digital signatures via PowerShell `Get-AuthenticodeSignature`.
  * `read_registry_values(root_key_name, subkey) -> List[Dict[str, Any]]`: Queries Windows registry across both 32-bit and 64-bit views (`KEY_WOW64_64KEY`, `KEY_WOW64_32KEY`).
  * `enumerate_processes() -> List[Dict[str, Any]]`: Cascades process collection across `psutil`, WMI (`Win32_Process`), and native `tasklist.exe`.
  * `enumerate_process_modules(pid: int) -> List[str]`: Enumerates loaded DLLs for a process using `psutil.Process(pid).memory_maps()`.
  * `enumerate_services() -> List[Dict[str, Any]]`: Cascades service enumeration across `psutil.win_service_iter()`, WMI (`Win32_Service`), and PowerShell `Get-CimInstance`.
  * `enumerate_scheduled_tasks() -> List[Dict[str, Any]]`: Cascades task enumeration across `schtasks.exe /query /fo csv` and PowerShell `Get-ScheduledTask`.
  * `get_path_basename(file_path: str) -> str`: Normalizes Windows and POSIX separators and extracts the file basename.
  * `extract_file_path(command_str: str) -> Optional[str]`: Resolves environment variables, extracts unquoted paths with spaces ending in executable extensions, and parses command switches.
  * `check_unquoted_path_vulnerability(command_str: str) -> bool`: Checks for CWE-428 unquoted search path vulnerabilities.
  * `is_temp_or_user_writable(path: str) -> bool`: Checks if a path points to temporary or user-writable locations.
  * `is_standard_system_path(path: str) -> bool`: Verifies if a path resides within `C:\Windows`, `C:\Program Files`, or `C:\Program Files (x86)`.

---

### G. Detection Modules Reference

#### 1. `detectors/persistence_detector.py`
* `_scan_registry_persistence()`: Audits 12 autostart registry locations across HKLM and HKCU. Flags unquoted paths (WARN), temporary/user-writable paths (ALERT), non-standard paths (WARN), non-existent orphaned targets (WARN), and unsigned binaries (WARN).
* `_scan_startup_folders()`: Scans user and system Startup folders. Direct scripts or executables (`.exe`, `.bat`, `.vbs`, `.ps1`) are flagged as ALERT. Shortcut files with high entropy ($> 7.5$) are flagged as WARN.
* `_scan_services_persistence()`: Identifies services running from user-writable paths (ALERT), unquoted paths (WARN), or services masquerading as core system binaries (ALERT).
* `_scan_scheduled_tasks_persistence()`: Identifies scheduled tasks executing from temporary or user-writable folders (ALERT) or containing unquoted paths (WARN).

#### 2. `detectors/process_detector.py`
* `levenshtein_distance(s1, s2) -> int`: Computes edit distance between process names.
* `_check_typosquatting(proc_name) -> Optional[str]`: Flags trailing whitespace abuse, homoglyphs/leetspeak (`0` for `o`, `1` for `l`, etc.), and Levenshtein distance lookalikes against protected Windows system binaries.
* `run()`:
  * Verifies running system processes against canonical system paths (`svchost.exe`, `lsass.exe`, `csrss.exe`, etc.).
  * Scans names and arguments against offensive tool patterns (`mimikatz`, `meterpreter`, `beacon`, `stealer`).
  * Validates Authenticode signatures of executables running from system folders.
  * Measures Shannon entropy on executable binaries ($> 7.5$ indicates packing).

#### 3. `detectors/keylogger_detector.py`
* `_check_appinit_dlls()`: Scans 32-bit and 64-bit `AppInit_DLLs` registry values for global DLL injection (ALERT).
* `_scan_process_hook_cmdlines()`: Scans command lines for Windows keyboard hook API references (`SetWindowsHookEx`, `WH_KEYBOARD_LL`, `GetAsyncKeyState`, etc.) (ALERT).
* `_scan_loaded_modules()`: Inspects loaded DLLs in running processes, filtering out known benign system DLLs and flagging third-party libraries matching `hook` or `keylog` (ALERT).

#### 4. `detectors/credential_theft_detector.py`
* `_scan_process_cmdlines()`: Detects known credential dumpers (`mimikatz`, `sekurlsa`, `procdump`, `nanodump`, `pypykatz`, etc.), LSASS dumping syntax (`dump`, `minidump`, `inject`), and native LOLBAS memory dumping via `comsvcs.dll #24` (ALERT).
* `_check_lsass_access_heuristic()`: When running elevated, tests whether process token privileges (`SeDebugPrivilege`) and script hosts (`powershell.exe`, `rundll32.exe`) are attempting access to LSASS handles.

#### 5. `detectors/surveillance_detector.py`
* `_scan_surveillance_processes()`: Flags processes matching covert surveillance, screen recording, webcam capture, or hidden VNC keywords, filtering out allowlisted applications (WARN).
* `_scan_surveillance_services()`: Scans service names and display descriptions for surveillance keywords while protecting legitimate Windows remote access and display services.
* `_scan_screen_capture_tasks()`: Scans Scheduled Tasks for automated PowerShell screen grabbers (`CopyFromScreen`, `System.Drawing`, `Graphics`, `nircmd`, `ffmpeg -f gdigrab`) (ALERT).

#### 6. `detectors/hidden_install_detector.py`
* `_scan_hidden_services()`: Audits services with binary paths residing in `%TEMP%`, `%APPDATA%`, or user profile folders (ALERT), auto-start services with missing display names or descriptions (WARN), and unquoted paths (WARN).
* `_scan_hidden_tasks()`: Audits scheduled tasks executing from temporary or user-writable paths (ALERT) and unquoted paths (WARN).

---

## 4. Future Technical Roadmap

The following defensive enhancements can be integrated in future development cycles:

1. **Windows Event Log Auditing**:
   * Integrate standard library Windows Event Log queries (via `win32evtlog` or native PowerShell cmdlets) for:
     * Event ID 4688: Process creation with command line auditing enabled.
     * Event ID 7045 / 4697: New service installations.
     * Event ID 1102: Audit log clearing attempts.

2. **Offline Threat Intelligence Hash Matching**:
   * Compute SHA-256 hashes of autostart executables and query local offline SQLite databases of known malicious hash catalogs (e.g. NIST NSRL, Malware Bazaar offline datasets).

3. **Standardized Security Export Formats**:
   * Export scan results in **SARIF** (OASIS Static Analysis Results Interchange Format) for direct ingestion into GitHub Advanced Security and VS Code.
   * Export in **STIX 2.1** (Structured Threat Information Expression) for threat intelligence sharing platforms (MISP, OpenCTI).

4. **Network Socket & Named Pipe Correlation**:
   * Enumerate listening sockets and outbound established connections (using `Get-NetTCPConnection` or `psutil.net_connections()`) to correlate suspicious processes with external IP connections and known C2 ports.

5. **Kernel-Mode Driver Auditing**:
   * Query loaded Windows kernel drivers (`sc.exe query type= driver` or `driverquery.exe /v`) to audit third-party drivers lacking valid Microsoft Authenticode signatures, detecting vulnerable drivers subject to BYOVD (Bring Your Own Vulnerable Driver) attacks.
