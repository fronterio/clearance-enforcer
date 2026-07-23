"""Fronterio Clearance Enforcer for LiteLLM.

Fronterio decides — your runtime enforces. MIT licensed.
"""

from .client import ClearanceBlockedError, ClearanceClient, ClearanceConfig, verify_bundle_jws
from .evaluator import Verdict, evaluate

__version__ = "0.1.0"

__all__ = [
    "ClearanceBlockedError",
    "ClearanceClient",
    "ClearanceConfig",
    "Verdict",
    "evaluate",
    "verify_bundle_jws",
]
