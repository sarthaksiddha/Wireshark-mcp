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


class SecurityMonitor:
    """
    Security monitor for tracking and responding to security events.
    Implements the Observer pattern to allow components to register for notifications.
    """
    
    def __init__(self, max_events: int = 1000):
        """
        Initialize the security monitor.
        
        Args:
            max_events: Maximum number of events to store in history
        """
        self.events: List[SecurityEvent] = []
        self.max_events = max_events
        self.observers: List[callable] = []
    
    def add_event(self, event: SecurityEvent) -> None:
        """
        Add a security event to the monitor.
        
        Args:
            event: The security event to add
        """
        self.events.append(event)
        
        # Trim history if needed
        if len(self.events) > self.max_events:
            self.events = self.events[-self.max_events:]
            
        # Notify observers
        self._notify_observers(event)
        
        # Log the event
        log_level = logging.WARNING if event.severity < 0.7 else logging.ERROR
        logger.log(log_level, f"Security event: {event.event_type.value}, "
                              f"Severity: {event.severity}, Details: {event.details}")
    
    def register_observer(self, observer: callable) -> None:
        """
        Register an observer to be notified of security events.
        
        Args:
            observer: Callable that takes a SecurityEvent as an argument
        """
        if observer not in self.observers:
            self.observers.append(observer)
    
    def _notify_observers(self, event: SecurityEvent) -> None:
        """
        Notify all observers of a security event.
        
        Args:
            event: The security event to notify about
        """
        for observer in self.observers:
            try:
                observer(event)
            except Exception as e:
                logger.error(f"Error notifying observer of security event: {e}")
    
    def get_recent_events(self, count: int = 10) -> List[SecurityEvent]:
        """
        Get the most recent security events.
        
        Args:
            count: Number of events to retrieve
            
        Returns:
            List of recent security events
        """
        return self.events[-count:]
    
    def get_events_by_type(self, event_type: SecurityEventType) -> List[SecurityEvent]:
        """
        Get events of a specific type.
        
        Args:
            event_type: Type of events to retrieve
            
        Returns:
            List of events of the specified type
        """
        return [e for e in self.events if e.event_type == event_type]
    
    def get_high_severity_events(self, threshold: float = 0.7) -> List[SecurityEvent]:
        """
        Get high severity events.
        
        Args:
            threshold: Severity threshold (0.0 to 1.0)
            
        Returns:
            List of high severity events
        """
        return [e for e in self.events if e.severity >= threshold]


class PromptInjectionDefense:
    """
    Defense mechanisms against prompt injection attacks.
    Detects and mitigates attempts to manipulate AI agent behavior.
    """
    
    # Patterns that might indicate prompt injection attempts
    INJECTION_PATTERNS = [
        r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions",
        r"disregard\s+(?:all\s+)?(?:previous|prior|above)",
        r"forget\s+(?:all\s+)?(?:previous|prior|above)",
        r"do\s+not\s+(?:follow|adhere\s+to)\s+(?:previous|prior|above)",
        r"new\s+instructions:(?!.*secure|sanitize|verify)",
        r"instead,?\s+(?:do|generate|create|provide|give\s+me)",
        r"(?:actually|in\s+reality),?\s+(?:do|generate|create|provide|give\s+me)",
        r"(?:context|system|role)\s+prompt",
        r"act\s+as\s+(?:if\s+)?you\s+(?:are|were)\s+(?:not|never)",
        r"you\s+are\s+now\s+(?:a|an)\s+(?!secure|sanitizer|validator)",
        r"never\s+mind\s+safety",
        r"bypass",
        r"workaround",
        r"hack\s+the\s+system",
        r"circumvent",
        r"prompt\s+injection"
    ]
    
    # Content types we should be particularly cautious about
    SENSITIVE_CONTENT_TYPES = {
        "instruction": 0.8,  # Instructions/commands have high risk
        "role_definition": 0.7,  # Attempts to redefine agent role
        "security_bypass": 0.9,  # Explicit bypass attempts
        "unexpected_directive": 0.6  # Unusual directives
    }
    
    @classmethod
    def detect_prompt_injection(cls, text: str) -> Optional[Dict[str, Any]]:
        """
        Detect potential prompt injection attempts in text.
        
        Args:
            text: The text to analyze
            
        Returns:
            Dictionary with details if injection detected, None otherwise
        """
        if not text:
            return None
            
        # Convert to lowercase for pattern matching
        text_lower = text.lower()
        
        # Check for injection patterns
        pattern_matches = []
        for pattern in cls.INJECTION_PATTERNS:
            matches = re.findall(pattern, text_lower)
            if matches:
                pattern_matches.extend(matches)
        
        # If we have pattern matches, classify the injection attempt
        if pattern_matches:
            # Determine the content type
            content_type = cls._classify_content_type(text_lower)
            
            # Calculate severity based on pattern matches and content type
            base_severity = 0.5 if len(pattern_matches) == 1 else min(0.9, 0.5 + (len(pattern_matches) - 1) * 0.1)
            severity_multiplier = cls.SENSITIVE_CONTENT_TYPES.get(content_type, 0.5)
            severity = base_severity * severity_multiplier
            
            return {
                "detected": True,
                "matches": pattern_matches,
                "content_type": content_type,
                "severity": severity,
                "description": f"Potential prompt injection detected with {len(pattern_matches)} matching patterns"
            }
        
        return None
    
    @classmethod
    def _classify_content_type(cls, text: str) -> str:
        """
        Classify the type of content in the text.
        
        Args:
            text: The text to classify
            
        Returns:
            Content type classification
        """
        if re.search(r"ignore|disregard|forget|do\s+not\s+follow", text):
            return "instruction"
        
        if re.search(r"you\s+are\s+now|act\s+as|you\s+will\s+be|you\s+have\s+become", text):
            return "role_definition"
        
        if re.search(r"bypass|workaround|hack|circumvent|override|security", text):
            return "security_bypass"
        
        return "unexpected_directive"
    
    @classmethod
    def sanitize_prompt(cls, text: str, detection_result: Optional[Dict[str, Any]] = None) -> str:
        """
        Sanitize text that might contain prompt injection attempts.
        
        Args:
            text: The text to sanitize
            detection_result: Result from detect_prompt_injection if already performed
            
        Returns:
            Sanitized text
        """
        if not text:
            return ""
            
        # If detection result not provided, perform detection
        if detection_result is None:
            detection_result = cls.detect_prompt_injection(text)
            
        # If no injection detected, return the original text
        if not detection_result:
            return text
            
        # Sanitize based on the detected patterns
        sanitized_text = text
        for match in detection_result.get("matches", []):
            # Replace the match with a sanitized version
            sanitized_text = sanitized_text.replace(match, "[FILTERED CONTENT]")
            
        return sanitized_text
