"""
Tests for Standardized Finding Model (Phase 3).

Verifies:
1. Schema conformity across all detection modules.
2. Consistent types for required and optional fields.
3. Backward compatibility as a dict subclass.
4. Attribute-style and dict-subscript access.
5. JSON serializability.
6. Type coercion and default value heuristics.
7. Schema validation helper (finding.validate()).
"""

import json
import pytest
from detectors.finding import Finding
from detectors.base_detector import BaseDetector
from detectors.persistence_detector import PersistenceDetector
from detectors.process_detector import ProcessDetector
from detectors.keylogger_detector import KeyloggerDetector
from detectors.credential_theft_detector import CredentialTheftDetector
from detectors.surveillance_detector import SurveillanceDetector
from detectors.hidden_install_detector import HiddenInstallDetector


def test_finding_schema_keys_and_types():
    """Verify that a newly instantiated Finding contains all required schema keys."""
    finding = Finding(
        category="Persistence",
        severity="ALERT",
        description="Suspicious run key detected",
        evidence="HKCU\\Run\\evil -> C:\\Temp\\evil.exe",
        rule_id="RULE-PERSIST-RUN-TEMP",
        confidence=0.90,
        risk_score=85,
        recommendation="Remove unauthorized run key",
        process="evil.exe",
        pid=1234,
        path=r"C:\Temp\evil.exe"
    )

    assert finding.validate() is True
    assert isinstance(finding, dict)
    assert finding["finding_id"].startswith("FIND-")
    assert finding["rule_id"] == "RULE-PERSIST-RUN-TEMP"
    assert finding["category"] == "Persistence"
    assert finding["severity"] == "ALERT"
    assert finding["confidence"] == 0.90
    assert finding["risk_score"] == 85
    assert finding["description"] == "Suspicious run key detected"
    assert "evil.exe" in finding["evidence"]
    assert finding["recommendation"] == "Remove unauthorized run key"
    assert isinstance(finding["timestamp"], str)
    assert "T" in finding["timestamp"]
    assert isinstance(finding["host"], str)
    assert finding["process"] == "evil.exe"
    assert finding["pid"] == 1234
    assert finding["path"] == r"C:\Temp\evil.exe"


def test_finding_attribute_and_item_access():
    """Verify both attribute access and dict indexing work identically."""
    finding = Finding(
        category="Process Spoofing",
        severity="ALERT",
        description="Lookalike process",
        evidence="svch0st.exe",
        rule_id="RULE-PROC-TYPOSQUAT"
    )

    # Subscript access
    assert finding["category"] == "Process Spoofing"
    assert finding["severity"] == "ALERT"
    assert finding["rule_id"] == "RULE-PROC-TYPOSQUAT"

    # Attribute access
    assert finding.category == "Process Spoofing"
    assert finding.severity == "ALERT"
    assert finding.rule_id == "RULE-PROC-TYPOSQUAT"

    # Modification via attribute and item
    finding.confidence = 0.95
    assert finding["confidence"] == 0.95

    finding["risk_score"] = 90
    assert finding.risk_score == 90


def test_finding_optional_fields_null_when_unavailable():
    """Verify that optional fields are None (null in JSON) when unavailable, without inventing data."""
    finding = Finding(
        category="General",
        severity="INFO",
        description="Informational note",
        evidence="System booted"
    )

    assert finding.validate() is True
    assert finding["rule_id"] is None
    assert finding["process"] is None
    assert finding["pid"] is None
    assert finding["path"] is None
    assert finding["recommendation"] is None


def test_finding_json_serialization():
    """Verify that Finding can be serialized to JSON without custom encoders."""
    finding = Finding(
        category="Keylogging",
        severity="ALERT",
        description="AppInit_DLLs injection",
        evidence="hook.dll",
        rule_id="RULE-KEYLOG-APPINIT",
        pid=555
    )

    json_str = json.dumps(finding)
    assert isinstance(json_str, str)

    parsed = json.loads(json_str)
    assert parsed["category"] == "Keylogging"
    assert parsed["pid"] == 555
    assert parsed["rule_id"] == "RULE-KEYLOG-APPINIT"


def test_finding_type_coercion_and_clamping():
    """Verify severity coercion, confidence clamping [0.0, 1.0], and risk score clamping [0, 100]."""
    # Invalid severity defaults to WARN
    f1 = Finding(category="Test", severity="unknown_sev", description="desc", evidence="ev")
    assert f1.severity == "WARN"

    # Confidence clamped between 0.0 and 1.0
    f2 = Finding(category="Test", severity="ALERT", description="desc", evidence="ev", confidence=1.5)
    assert f2.confidence == 1.0

    f3 = Finding(category="Test", severity="ALERT", description="desc", evidence="ev", confidence=-0.5)
    assert f3.confidence == 0.0

    # Risk score clamped between 0 and 100
    f4 = Finding(category="Test", severity="ALERT", description="desc", evidence="ev", risk_score=150)
    assert f4.risk_score == 100

    f5 = Finding(category="Test", severity="ALERT", description="desc", evidence="ev", risk_score=-20)
    assert f5.risk_score == 0

    # String pid cast to int
    f6 = Finding(category="Test", severity="ALERT", description="desc", evidence="ev", pid="8080")
    assert f6.pid == 8080


def test_all_detectors_produce_valid_findings(mock_registry):
    """Verify that every detector produces findings that conform to the standardized schema."""
    detectors = [
        PersistenceDetector(),
        ProcessDetector(),
        KeyloggerDetector(),
        CredentialTheftDetector(),
        SurveillanceDetector(),
        HiddenInstallDetector(),
    ]

    mock_registry.store[("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run")] = [
        {"name": "BadApp", "data": r"C:\Temp\bad.exe", "type": 1}
    ]
    mock_registry.store[("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows")] = [
        {"name": "AppInit_DLLs", "data": r"C:\Temp\hook.dll", "type": 1}
    ]

    sample_procs = [
        {"pid": 1001, "name": "svch0st.exe", "exe": r"C:\Temp\svch0st.exe", "cmdline": "svch0st.exe"},
        {"pid": 1002, "name": "mimikatz.exe", "exe": r"C:\Tools\mimikatz.exe", "cmdline": "mimikatz.exe sekurlsa::logonpasswords"},
        {"pid": 1003, "name": "winvnc.exe", "exe": r"C:\Tools\winvnc.exe", "cmdline": "winvnc.exe -run"},
    ]
    sample_services = [
        {"name": "TempSvc", "display_name": "Temp Svc", "binpath": r"C:\Temp\svc.exe", "status": "RUNNING"}
    ]
    sample_tasks = [
        {"name": "TempTask", "task_to_run": r"C:\Users\Public\task.exe", "author": "Attacker"}
    ]

    total_findings = 0
    for d in detectors:
        d.registry_provider = mock_registry
        d.process_provider = lambda: sample_procs
        d.service_provider = lambda: sample_services
        d.task_provider = lambda: sample_tasks

        findings = d.run()
        total_findings += len(findings)
        for f in findings:
            assert isinstance(f, Finding), f"Detector {d.__class__.__name__} did not return Finding instance"
            assert f.validate() is True, f"Finding {f} failed schema validation"
            assert f.rule_id is not None, f"Finding {f} produced by {d.__class__.__name__} missing rule_id"
            assert isinstance(f.finding_id, str)
            assert isinstance(f.host, str)

    assert total_findings > 0, "No findings were generated during detector validation"
