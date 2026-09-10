"""
Tests for Centralized Heuristic Scoring Engine (Phase 4).

Validates:
1. Low-risk findings (e.g. INFO, single low-weight signal).
2. Medium-risk findings (e.g. WARN, single moderate-weight signal).
3. High-risk findings (e.g. ALERT, known attack tool, masquerading).
4. Compounding multiple independent indicators (+10 multiple_indicators bonus).
5. Mitigating allowlist and standard path reductions (-30, -15).
6. Mathematical boundary conditions (risk score strictly in [0, 100], confidence in [0.05, 0.99]).
7. Explainable risk factors list generation.
"""

import pytest
from detectors.scoring import HeuristicScorer
from detectors.finding import Finding
from detectors.base_detector import BaseDetector


def test_low_risk_finding_scoring():
    """Verify scoring for low-risk findings with minimal or informational signals."""
    score, conf, factors = HeuristicScorer.calculate_score(severity="INFO")
    assert 0 <= score <= 20
    assert 0.10 <= conf <= 0.40
    assert any("Base INFO severity" in f for f in factors)

    # Low-risk WARN with unquoted path
    score_warn, conf_warn, factors_warn = HeuristicScorer.calculate_score(
        severity="WARN",
        signals={"unquoted_path": True}
    )
    # Base 25 + unquoted 10 = 35
    assert score_warn == 35
    assert conf_warn == 0.55
    assert any("Unquoted path: +10" in f for f in factors_warn)


def test_medium_risk_finding_scoring():
    """Verify scoring for medium-risk findings (e.g. WARN with suspicious persistence or high entropy)."""
    score, conf, factors = HeuristicScorer.calculate_score(
        severity="WARN",
        signals={"suspicious_persistence": True}
    )
    # Base 25 + persistence 15 = 40
    assert score == 40
    assert conf == 0.55
    assert any("Suspicious persistence: +15" in f for f in factors)


def test_high_risk_finding_scoring():
    """Verify scoring for high-risk findings (e.g. ALERT with known attack tool or masquerading)."""
    score, conf, factors = HeuristicScorer.calculate_score(
        severity="ALERT",
        signals={"known_attack_tool": True}
    )
    # Base 45 + tool 25 = 70
    assert score == 70
    assert conf == 0.80
    assert any("Known attack tool: +25" in f for f in factors)

    # Masquerading process
    score_masq, conf_masq, factors_masq = HeuristicScorer.calculate_score(
        severity="ALERT",
        signals={"process_masquerading": True}
    )
    # Base 45 + masquerading 25 = 70
    assert score_masq == 70
    assert conf_masq == 0.80


def test_multiple_independent_indicators_bonus():
    """Verify that multiple independent risk indicators trigger compounding factor bonus."""
    # Two signals: user_writable_path (+20) and unsigned_binary (+15)
    # Plus multiple_indicators (+10)
    score, conf, factors = HeuristicScorer.calculate_score(
        severity="ALERT",
        signals={
            "user_writable_path": True,
            "unsigned_binary": True
        }
    )
    # Base 45 + 20 + 15 + 10 = 90
    assert score == 90
    assert conf >= 0.85
    assert any("Multiple indicators: +10" in f for f in factors)
    assert any("User writable path: +20" in f for f in factors)
    assert any("Unsigned binary: +15" in f for f in factors)


def test_mitigating_reductions():
    """Verify that allowlist matches and standard system paths reduce risk score and confidence."""
    # ALERT with allowlist reduction
    score, conf, factors = HeuristicScorer.calculate_score(
        severity="ALERT",
        signals={
            "allowlist_match": True
        }
    )
    # Base 45 - 30 = 15
    assert score == 15
    assert conf <= 0.50
    assert any("Allowlist match: -30" in f for f in factors)

    # Standard system path reduction
    score_sys, conf_sys, factors_sys = HeuristicScorer.calculate_score(
        severity="WARN",
        signals={
            "standard_system_path": True
        }
    )
    # Base 25 - 15 = 10
    assert score_sys == 10
    assert any("Standard system path: -15" in f for f in factors_sys)


def test_score_boundary_conditions():
    """Verify that risk scores and confidence are clamped strictly to defined limits."""
    # Underflow boundary (heavy reductions)
    score_low, conf_low, _ = HeuristicScorer.calculate_score(
        severity="INFO",
        signals={
            "allowlist_match": True,
            "standard_system_path": True
        }
    )
    assert score_low == 0
    assert conf_low >= 0.05

    # Overflow boundary (multiple compounding high-severity signals)
    score_high, conf_high, _ = HeuristicScorer.calculate_score(
        severity="CRITICAL",
        signals={
            "known_attack_tool": True,
            "process_masquerading": True,
            "user_writable_path": True,
            "high_entropy": True,
            "suspicious_cmdline": True
        }
    )
    assert score_high == 100
    assert conf_high <= 0.99


def test_base_detector_heuristic_integration():
    """Verify BaseDetector.calculate_heuristic_score and create_finding automatic scoring."""
    detector = BaseDetector()
    score, conf, factors = detector.calculate_heuristic_score(
        severity="ALERT",
        rule_id="RULE-CRED-TOOL"
    )
    assert score >= 70
    assert conf >= 0.80
    assert len(factors) >= 2

    # Verify create_finding uses heuristic score when risk_score/confidence omitted
    finding = detector.create_finding(
        category="Credential Theft",
        severity="ALERT",
        description="Mimikatz executed",
        evidence="PID: 1234",
        rule_id="RULE-CRED-TOOL"
    )
    assert isinstance(finding, Finding)
    assert finding.risk_score == score
    assert finding.confidence == conf
    assert len(finding.risk_factors) >= 2
