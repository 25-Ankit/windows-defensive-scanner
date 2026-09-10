"""
Standardized Finding Model for Windows Defensive Security Scanner.

Provides a unified, structured schema for security findings produced across
all detection modules, ensuring consistent typing, transparent scoring,
and full backward compatibility with dictionary consumers and JSON serialization.
"""

import os
import uuid
import platform
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Union, List

try:
    from .scoring import HeuristicScorer
except ImportError:
    from scoring import HeuristicScorer


# Standard severity classifications
VALID_SEVERITIES = ("CRITICAL", "ALERT", "WARN", "INFO")

# Severity-based default scoring heuristics
DEFAULT_SEVERITY_CONFIDENCE = {
    "CRITICAL": 0.95,
    "ALERT": 0.85,
    "WARN": 0.60,
    "INFO": 0.30,
}

DEFAULT_SEVERITY_RISK_SCORE = {
    "CRITICAL": 95,
    "ALERT": 80,
    "WARN": 50,
    "INFO": 20,
}


class Finding(dict):
    """
    Standardized security finding dictionary.

    Inherits from dict to guarantee 100% backward compatibility with dictionary
    subscripting (finding['severity']), iteration, and json.dumps(), while providing
    standardized attribute access and schema validation.
    """

    SCHEMA_KEYS = (
        "finding_id",
        "rule_id",
        "category",
        "severity",
        "confidence",
        "risk_score",
        "description",
        "evidence",
        "recommendation",
        "timestamp",
        "host",
        "process",
        "pid",
        "path",
        "risk_factors",
    )

    def __init__(
        self,
        category: str,
        severity: str,
        description: str,
        evidence: Any,
        rule_id: Optional[str] = None,
        confidence: Optional[float] = None,
        risk_score: Optional[int] = None,
        recommendation: Optional[str] = None,
        host: Optional[str] = None,
        process: Optional[str] = None,
        pid: Optional[Union[int, str]] = None,
        path: Optional[str] = None,
        finding_id: Optional[str] = None,
        timestamp: Optional[str] = None,
        signals: Optional[Dict[str, bool]] = None,
        risk_factors: Optional[List[str]] = None,
        **extra: Any
    ):
        # 1. Clean severity
        sev_clean = str(severity).upper().strip() if severity else "WARN"
        if sev_clean not in VALID_SEVERITIES:
            sev_clean = "WARN"

        # 2. Assign unique finding ID
        f_id = str(finding_id).strip() if finding_id else f"FIND-{uuid.uuid4().hex[:12].upper()}"

        # 3. Clean rule_id
        r_id = str(rule_id).strip() if rule_id else None

        # 4. Calculate Risk Score, Confidence, and Explainable Risk Factors
        factors: List[str] = list(risk_factors) if risk_factors else []
        if risk_score is None or confidence is None:
            calc_risk, calc_conf, calc_factors = HeuristicScorer.calculate_score(
                severity=sev_clean,
                category=category,
                rule_id=r_id,
                signals=signals,
                base_risk=risk_score,
                base_confidence=confidence,
            )
            risk_val = calc_risk if risk_score is None else int(max(0, min(100, int(risk_score))))
            conf_val = calc_conf if confidence is None else round(max(0.0, min(1.0, float(confidence))), 2)
            if not factors:
                factors = calc_factors
        else:
            conf_val = round(max(0.0, min(1.0, float(confidence))), 2)
            risk_val = int(max(0, min(100, int(risk_score))))
            if not factors:
                factors = [f"Base {sev_clean} severity: {risk_val}"]

        # 5. Timestamp (ISO 8601 UTC)
        ts_str = str(timestamp).strip() if timestamp else datetime.now(timezone.utc).isoformat()

        # 6. Host
        host_str = str(host).strip() if host else platform.node() or "localhost"

        # 7. Process & PID
        proc_str = str(process).strip() if process else None
        pid_int = None
        if pid is not None:
            try:
                pid_int = int(pid)
            except (ValueError, TypeError):
                pid_int = None

        # 8. Path & Recommendation
        path_str = str(path).strip() if path else None
        rec_str = str(recommendation).strip() if recommendation else None

        # Initialize dictionary storage
        super().__init__(
            finding_id=f_id,
            rule_id=r_id,
            category=str(category).strip(),
            severity=sev_clean,
            confidence=conf_val,
            risk_score=risk_val,
            description=str(description).strip(),
            evidence=str(evidence),
            recommendation=rec_str,
            timestamp=ts_str,
            host=host_str,
            process=proc_str,
            pid=pid_int,
            path=path_str,
            risk_factors=factors,
            **extra
        )

    # Enable attribute-style access (e.g. finding.rule_id, finding.severity)
    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError:
            raise AttributeError(f"'Finding' object has no attribute '{name}'")

    def __setattr__(self, name: str, value: Any) -> None:
        self[name] = value

    def to_dict(self) -> Dict[str, Any]:
        """Return finding data as a standard Python dictionary."""
        return dict(self)

    def validate(self) -> bool:
        """
        Validate that all required schema keys are present and conform to type constraints.
        """
        for key in self.SCHEMA_KEYS:
            if key not in self:
                return False

        if not isinstance(self["finding_id"], str) or not self["finding_id"]:
            return False
        if self["rule_id"] is not None and not isinstance(self["rule_id"], str):
            return False
        if not isinstance(self["category"], str) or not self["category"]:
            return False
        if self["severity"] not in VALID_SEVERITIES:
            return False
        if not isinstance(self["confidence"], float) or not (0.0 <= self["confidence"] <= 1.0):
            return False
        if not isinstance(self["risk_score"], int) or not (0 <= self["risk_score"] <= 100):
            return False
        if not isinstance(self["description"], str):
            return False
        if not isinstance(self["evidence"], str):
            return False
        if self["recommendation"] is not None and not isinstance(self["recommendation"], str):
            return False
        if not isinstance(self["timestamp"], str) or not self["timestamp"]:
            return False
        if not isinstance(self["host"], str) or not self["host"]:
            return False
        if self["process"] is not None and not isinstance(self["process"], str):
            return False
        if self["pid"] is not None and not isinstance(self["pid"], int):
            return False
        if self["path"] is not None and not isinstance(self["path"], str):
            return False
        if not isinstance(self["risk_factors"], list):
            return False

        return True
