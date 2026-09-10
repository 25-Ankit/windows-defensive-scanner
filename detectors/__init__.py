"""
Windows Defensive Security Scanner - Detection Modules
"""

from .finding import Finding
from .scoring import HeuristicScorer
from .allowlist import (
    is_allowlisted_process,
    is_allowlisted_service,
    is_allowlisted_dll,
    register_benign_process,
    register_benign_service,
    register_benign_dll,
    reset_custom_allowlists,
)
from .base_detector import BaseDetector
from .persistence_detector import PersistenceDetector
from .process_detector import ProcessDetector
from .keylogger_detector import KeyloggerDetector
from .credential_theft_detector import CredentialTheftDetector
from .surveillance_detector import SurveillanceDetector
from .hidden_install_detector import HiddenInstallDetector

__all__ = [
    "Finding",
    "HeuristicScorer",
    "is_allowlisted_process",
    "is_allowlisted_service",
    "is_allowlisted_dll",
    "register_benign_process",
    "register_benign_service",
    "register_benign_dll",
    "reset_custom_allowlists",
    "BaseDetector",
    "PersistenceDetector",
    "ProcessDetector",
    "KeyloggerDetector",
    "CredentialTheftDetector",
    "SurveillanceDetector",
    "HiddenInstallDetector",
]
