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
