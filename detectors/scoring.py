"""
Heuristic Risk Scoring and Confidence Engine.

Provides an explainable, deterministic heuristic scoring system for findings
produced by the Windows Defensive Security Scanner.

IMPORTANT:
This scoring model is explicitly heuristic and rule-based. It does NOT claim to be
a machine-learning probability, neural network inference, or scientifically
validated malware classification score. Every score point is directly attributable
to an observable technical signal or contextual indicator.
"""

from typing import Dict, Any, List, Tuple, Optional


# Baseline risk scores by severity classification
SEVERITY_BASE_SCORES: Dict[str, int] = {
    "CRITICAL": 60,
    "ALERT": 45,
    "WARN": 25,
    "INFO": 10,
}

# Baseline confidence levels by severity classification
SEVERITY_BASE_CONFIDENCE: Dict[str, float] = {
    "CRITICAL": 0.85,
    "ALERT": 0.70,
    "WARN": 0.50,
    "INFO": 0.30,
}

# Heuristic Signal Weights (Points added to base risk score)
SIGNAL_WEIGHTS: Dict[str, int] = {
    "known_attack_tool": 25,          # Mimikatz, PyPyKatz, procdump, nanodump, comsvcs dump
    "process_masquerading": 25,       # Typosquatting lookalike or canonical path violation
    "user_writable_path": 20,         # Execution from %TEMP%, %APPDATA%, C:\Users\*
    "unsigned_binary": 15,            # Untrusted or missing Authenticode signature
    "high_entropy": 15,               # Shannon entropy > 7.5 (packed or encrypted PE)
    "suspicious_cmdline": 15,         # Keyboard hook APIs, memory dump syntax, debug privilege
    "suspicious_persistence": 15,     # Direct startup script, AppInit_DLLs injection
    "unquoted_path": 10,              # CWE-428 unquoted search path vulnerability
    "stealth_profile": 10,            # Auto-start service missing display name or description
    "multiple_indicators": 10,        # Two or more independent risk signals present
}

# Signal Confidence Adjustments
SIGNAL_CONFIDENCE_DELTAS: Dict[str, float] = {
    "known_attack_tool": 0.10,
    "process_masquerading": 0.10,
    "user_writable_path": 0.05,
    "unsigned_binary": 0.05,
    "high_entropy": 0.05,
    "suspicious_cmdline": 0.05,
    "suspicious_persistence": 0.05,
    "unquoted_path": 0.05,
    "stealth_profile": 0.05,
    "multiple_indicators": 0.05,
}

# Mitigating Reductions
REDUCTION_WEIGHTS: Dict[str, int] = {
    "allowlist_match": -30,           # Matches recognized benign application / system service
    "standard_system_path": -15,      # Resides in canonical C:\Windows or C:\Program Files
}

REDUCTION_CONFIDENCE_DELTAS: Dict[str, float] = {
    "allowlist_match": -0.25,
    "standard_system_path": -0.10,
}

# Mapping of known rule IDs to default active signals
RULE_SIGNAL_MAP: Dict[str, List[str]] = {
    # Persistence
    "RULE-PERSIST-RUN-UNQUOTED": ["unquoted_path"],
    "RULE-PERSIST-RUN-TEMP": ["user_writable_path", "suspicious_persistence"],
    "RULE-PERSIST-RUN-NONSTANDARD": ["suspicious_persistence"],
    "RULE-PERSIST-RUN-ORPHAN": ["suspicious_persistence"],
    "RULE-PERSIST-RUN-UNSIGNED": ["unsigned_binary", "suspicious_persistence"],
    "RULE-PERSIST-STARTUP-FILE": ["user_writable_path", "suspicious_persistence"],
    "RULE-PERSIST-STARTUP-ENTROPY": ["high_entropy", "suspicious_persistence"],
    "RULE-PERSIST-SVC-UNQUOTED": ["unquoted_path"],
    "RULE-PERSIST-SVC-TEMP": ["user_writable_path", "suspicious_persistence"],
    "RULE-PERSIST-SVC-MASQ": ["process_masquerading", "suspicious_persistence"],
    "RULE-PERSIST-TASK-UNQUOTED": ["unquoted_path"],
    "RULE-PERSIST-TASK-TEMP": ["user_writable_path", "suspicious_persistence"],

    # Process Spoofing & AV Evasion
    "RULE-PROC-TYPOSQUAT": ["process_masquerading"],
    "RULE-PROC-MASQUERADE": ["process_masquerading"],
    "RULE-PROC-INACCESSIBLE": ["process_masquerading"],
    "RULE-PROC-KEYWORD": ["suspicious_cmdline"],
    "RULE-PROC-UNSIGNED": ["unsigned_binary"],
    "RULE-PROC-PACKED": ["high_entropy"],

    # Keylogger
    "RULE-KEYLOG-APPINIT": ["suspicious_persistence"],
    "RULE-KEYLOG-CMDLINE": ["suspicious_cmdline"],
    "RULE-KEYLOG-MODULE": ["known_attack_tool"],

    # Credential Theft
    "RULE-CRED-TOOL": ["known_attack_tool"],
    "RULE-CRED-LSASS-SYNTAX": ["known_attack_tool", "suspicious_cmdline"],
    "RULE-CRED-COMSVCS-LOLBAS": ["known_attack_tool", "suspicious_cmdline"],
    "RULE-CRED-LSASS-ACCESS": ["suspicious_cmdline"],

    # Surveillance
    "RULE-SURV-PROCESS": ["known_attack_tool"],
    "RULE-SURV-SERVICE": ["suspicious_persistence"],
    "RULE-SURV-TASK": ["suspicious_cmdline"],

    # Hidden Install
    "RULE-HIDDEN-SVC-UNQUOTED": ["unquoted_path"],
    "RULE-HIDDEN-SVC-TEMP": ["user_writable_path"],
    "RULE-HIDDEN-SVC-STEALTH": ["stealth_profile"],
    "RULE-HIDDEN-TASK-UNQUOTED": ["unquoted_path"],
    "RULE-HIDDEN-TASK-TEMP": ["user_writable_path"],
}


class HeuristicScorer:
    """
    Centralized heuristic risk-scoring and confidence calculation engine.
    Calculates explainable risk scores (0-100) and confidence metrics (0.0-1.0)
    with human-readable risk factor breakdowns.
    """

    @classmethod
    def calculate_score(
        cls,
        severity: str,
        category: Optional[str] = None,
        rule_id: Optional[str] = None,
        signals: Optional[Dict[str, bool]] = None,
        base_risk: Optional[int] = None,
        base_confidence: Optional[float] = None
    ) -> Tuple[int, float, List[str]]:
        """
        Calculate transparent risk score, confidence, and explainable risk factors.

        Args:
            severity: Finding severity ("CRITICAL", "ALERT", "WARN", "INFO").
            category: Finding category string.
            rule_id: Unique rule identifier (used to seed default signals).
            signals: Dictionary of boolean signal flags (e.g. {"user_writable_path": True}).
            base_risk: Optional manual override for base risk score.
            base_confidence: Optional manual override for base confidence.

        Returns:
            Tuple of (risk_score: int, confidence: float, risk_factors: List[str]).
        """
        sev_clean = str(severity).upper().strip() if severity else "WARN"
        if sev_clean not in SEVERITY_BASE_SCORES:
            sev_clean = "WARN"

        # 1. Base Scores
        initial_risk = base_risk if base_risk is not None else SEVERITY_BASE_SCORES[sev_clean]
        initial_conf = base_confidence if base_confidence is not None else SEVERITY_BASE_CONFIDENCE[sev_clean]

        risk_factors: List[str] = [f"Base {sev_clean} severity: +{initial_risk}"]

        # 2. Compile Active Signals
        active_signals: Dict[str, bool] = {}
        if rule_id and rule_id in RULE_SIGNAL_MAP:
            for sig in RULE_SIGNAL_MAP[rule_id]:
                active_signals[sig] = True

        if signals:
            for sig_name, is_active in signals.items():
                if is_active:
                    active_signals[sig_name] = True
                elif is_active is False and sig_name in active_signals:
                    del active_signals[sig_name]

        # 3. Check for multiple compounding indicators
        positive_signal_count = sum(
            1 for s in active_signals if s in SIGNAL_WEIGHTS and s != "multiple_indicators"
        )
        if positive_signal_count >= 2:
            active_signals["multiple_indicators"] = True

        accumulated_risk = initial_risk
        accumulated_conf = initial_conf

        # 4. Apply Positive Signal Weights
        for sig_name, weight in SIGNAL_WEIGHTS.items():
            if active_signals.get(sig_name):
                accumulated_risk += weight
                accumulated_conf += SIGNAL_CONFIDENCE_DELTAS.get(sig_name, 0.0)
                readable_name = sig_name.replace("_", " ").capitalize()
                risk_factors.append(f"{readable_name}: +{weight}")

        # 5. Apply Mitigating Reductions
        for red_name, reduction in REDUCTION_WEIGHTS.items():
            if active_signals.get(red_name):
                accumulated_risk += reduction
                accumulated_conf += REDUCTION_CONFIDENCE_DELTAS.get(red_name, 0.0)
                readable_name = red_name.replace("_", " ").capitalize()
                risk_factors.append(f"{readable_name}: {reduction}")

        # 6. Enforce Mathematical Bounds
        # Risk score strictly clamped to [0, 100]
        final_risk_score = max(0, min(100, int(accumulated_risk)))

        # Confidence strictly clamped to [0.05, 0.99]
        final_confidence = round(max(0.05, min(0.99, accumulated_conf)), 2)

        return final_risk_score, final_confidence, risk_factors
