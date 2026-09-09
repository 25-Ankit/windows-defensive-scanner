"""
Windows Defensive Security Scanner - Detection Modules
"""

from .base_detector import BaseDetector
from .persistence_detector import PersistenceDetector
from .process_detector import ProcessDetector
from .keylogger_detector import KeyloggerDetector
from .credential_theft_detector import CredentialTheftDetector
from .surveillance_detector import SurveillanceDetector
from .hidden_install_detector import HiddenInstallDetector

__all__ = [
    "BaseDetector",
    "PersistenceDetector",
    "ProcessDetector",
    "KeyloggerDetector",
    "CredentialTheftDetector",
    "SurveillanceDetector",
    "HiddenInstallDetector",
]
