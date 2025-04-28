"""
Security module for the Wireshark MCP A2A implementation.
This module provides security controls for A2A communications, including
threat detection, prompt injection protection, and content filtering.
"""

import re
import json
import logging
import hashlib
import secrets
import time
from typing import Dict, Any, List, Optional, Union, Tuple, Set
from enum import Enum
from dataclasses import dataclass

# Configure logging
logger = logging.getLogger(__name__)


class SecurityLevel(Enum):
    """Security levels for the A2A security module."""
    LOW = 0
    MEDIUM = 1
    HIGH = 2


class SecurityEventType(Enum):
    """Types of security events that can be detected."""
    PROMPT_INJECTION = "prompt_injection"
    DATA_LEAKAGE = "data_leakage"
    AUTHENTICATION_FAILURE = "authentication_failure"
    AUTHORIZATION_FAILURE = "authorization_failure"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    MALICIOUS_CONTENT = "malicious_content"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    INVALID_INPUT = "invalid_input"


@dataclass
class SecurityEvent:
    """Represents a security event detected by the security module."""
    event_type: SecurityEventType
    severity: float  # 0.0 to 1.0
    timestamp: float
    details: str
    source: str
    mitigation_applied: Optional[str] = None
