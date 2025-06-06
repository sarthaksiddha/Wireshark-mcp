#!/usr/bin/env python3
"""
Security module for Wireshark MCP

This module implements security controls for Wireshark MCP, particularly focused
on protecting against LLM-based attacks, prompt injections, and other AI-specific
security concerns when agents communicate with each other or with external systems.

The security controls are inspired by the MAESTRO framework and follow best practices 
from the AI security community.
"""

import re
import json
import logging
import hashlib
import hmac
import base64
import functools
import inspect
import secrets
import time
from typing import Dict, List, Any, Callable, Optional, Tuple, Union

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SecurityRisk:
    """Represents a security risk with severity and description."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    
    def __init__(self, severity: str, description: str, remediation: str = None):
        self.severity = severity
        self.description = description
        self.remediation = remediation or "No specific remediation provided"
    
    def __str__(self):
        return f"{self.severity}: {self.description}"
    
    def to_dict(self):
        return {
            "severity": self.severity,
            "description": self.description,
            "remediation": self.remediation
        }

class SecurityPolicy:
    """Defines a security policy with rules and actions."""
    def __init__(self, name: str, description: str = None):
        self.name = name
        self.description = description
        self.rules = []
    
    def add_rule(self, rule_func: Callable, description: str = None):
        """Add a rule function to the policy."""
        self.rules.append((rule_func, description or rule_func.__name__))
        return self
    
    def evaluate(self, content: str) -> List[SecurityRisk]:
        """Evaluate content against all rules in the policy."""
        risks = []
        for rule_func, description in self.rules:
            try:
                result = rule_func(content)
                if result:
                    if isinstance(result, SecurityRisk):
                        risks.append(result)
                    elif isinstance(result, (list, tuple)) and all(isinstance(r, SecurityRisk) for r in result):
                        risks.extend(result)
                    elif isinstance(result, bool) and result:
                        risks.append(SecurityRisk(SecurityRisk.MEDIUM, 
                                                f"Security rule violated: {description}"))
            except Exception as e:
                logger.error(f"Error evaluating rule {description}: {e}")
        
        return risks

class PromptInjectionDefense:
    """Defends against prompt injection attacks in LLM-based systems."""
    
    @staticmethod
    def detect_prompt_injection(text: str) -> Optional[SecurityRisk]:
        """
        Detect potential prompt injection patterns in text.
        
        Args:
            text: The text to analyze
            
        Returns:
            SecurityRisk if a potential injection is detected, None otherwise
        """
        # Common prompt injection patterns
        patterns = [
            (r"ignore (?:all|previous).*instructions", "Instruction override attempt"),
            (r"forget (?:all|your|previous).*instructions", "Instruction erasure attempt"),
            (r"disregard (?:all|your|previous).*instructions", "Instruction disregard attempt"),
            (r"you (?:are|will be|become) [^.]*\b(?!an assistant\b)", "Identity manipulation attempt"),
            (r"new persona", "Persona manipulation attempt"),
            (r"system prompt", "System prompt reference attempt"),
            (r"your instructions (are|were)", "Instruction reference attempt"),
            (r"\<(?!antml|\/antml)[a-zA-Z0-9_\-]+\>", "XML tag injection attempt"),
            (r"You are a \S+ model", "Model identity manipulation attempt"),
            (r"jailbreak", "Explicit jailbreak attempt"),
            (r"output the (content|text) (above|before) (the|this) line", "Data extraction attempt")
        ]
        
        for pattern, description in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return SecurityRisk(
                    SecurityRisk.HIGH,
                    f"Potential prompt injection detected: {description}",
                    "Implement strict input validation and sanitization for all user inputs"
                )
        
        return None

class DataLeakageDefense:
    """Prevents sensitive data leakage through LLM-based systems."""
    
    @staticmethod
    def detect_pii(text: str) -> List[SecurityRisk]:
        """
        Detect personally identifiable information in text.
        
        Args:
            text: The text to analyze
            
        Returns:
            List of SecurityRisk objects for each type of PII detected
        """
        risks = []
        
        # PII detection patterns
        patterns = [
            (r"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b", "SSN", SecurityRisk.HIGH),
            (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "Email address", SecurityRisk.MEDIUM),
            (r"\b(?:\+\d{1,2}\s)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b", "Phone number", SecurityRisk.MEDIUM),
            (r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b", "Credit card number", SecurityRisk.CRITICAL),
            (r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "IP address", SecurityRisk.LOW)
        ]
        
        for pattern, pii_type, severity in patterns:
            if re.search(pattern, text):
                risks.append(SecurityRisk(
                    severity,
                    f"Potential {pii_type} detected in content",
                    f"Implement data masking for {pii_type} in all outputs"
                ))
        
        return risks

class SecurityMonitor:
    """
    Monitors and logs security events for audit and compliance purposes.
    Implements the Observer pattern to detect and respond to security events.
    """
    
    def __init__(self):
        self.observers = []
        self.event_log = []
    
    def add_observer(self, observer: Callable):
        """Add an observer function to be notified of security events."""
        self.observers.append(observer)
    
    def notify(self, event: Dict[str, Any]):
        """Notify all observers of a security event."""
        self.event_log.append(event)
        for observer in self.observers:
            observer(event)
    
    def log_event(self, event_type: str, description: str, severity: str, metadata: Dict[str, Any] = None):
        """Log a security event."""
        event = {
            "type": event_type,
            "description": description,
            "severity": severity,
            "metadata": metadata or {}
        }
        self.notify(event)
    
    def get_event_log(self) -> List[Dict[str, Any]]:
        """Get the event log."""
        return self.event_log
    
    def clear_event_log(self):
        """Clear the event log."""
        self.event_log = []

class AgentSecurityWrapper:
    """
    Wraps an agent with security controls and monitoring.
    Acts as a security proxy for the agent, implementing the Proxy pattern.
    """
    
    def __init__(self, agent, security_monitor: SecurityMonitor = None, 
                 policies: List[SecurityPolicy] = None):
        self.agent = agent
        self.security_monitor = security_monitor or SecurityMonitor()
        self.policies = policies or []
        self.signatures = {}  # For tracking message signatures
        self.secrets = {}  # For storing HMAC keys
    
    def sign_message(self, message: str) -> str:
        """Sign a message to ensure integrity."""
        signature = hashlib.sha256(message.encode()).hexdigest()
        self.signatures[signature] = message
        return signature
    
    def generate_message_signature(self, message: str, 
                                  key: Optional[str] = None,
                                  algorithm: str = "hmac-sha256",
                                  include_timestamp: bool = True) -> Dict[str, Any]:
        """
        Generate a robust message signature for secure agent-to-agent communication.
        
        This method provides more advanced signature generation than sign_message, 
        including support for HMAC, multiple hash algorithms, timestamps, and
        customizable security options.
        
        Args:
            message: The message to sign
            key: Secret key for HMAC (if None, a secure random key will be generated 
                 and stored in self.secrets)
            algorithm: The hash algorithm to use ('sha256', 'sha512', 'hmac-sha256', or 'hmac-sha512')
            include_timestamp: Whether to include a timestamp in the signature
            
        Returns:
            A dictionary containing the signature and related metadata:
            {
                'signature': '<signature value>',
                'algorithm': '<algorithm used>',
                'timestamp': <unix timestamp> (if include_timestamp is True),
                'key_id': '<key identifier>' (for HMAC algorithms)
            }
        """
        if not message:
            raise ValueError("Message cannot be empty")
        
        timestamp = int(time.time()) if include_timestamp else None
        message_to_sign = message
        
        # Add timestamp to the message if requested
        if include_timestamp:
            message_to_sign = f"{message}|{timestamp}"
        
        signature_data = {"algorithm": algorithm}
        
        # Generate the signature based on the specified algorithm
        if algorithm == "sha256":
            signature = hashlib.sha256(message_to_sign.encode()).hexdigest()
        
        elif algorithm == "sha512":
            signature = hashlib.sha512(message_to_sign.encode()).hexdigest()
        
        elif algorithm.startswith("hmac-"):
            # Handle HMAC-based algorithms
            hash_algo = algorithm.split("-")[1]
            hmac_algo = getattr(hashlib, hash_algo)
            
            # Generate a key if none is provided
            if key is None:
                key_id = secrets.token_hex(8)
                key = secrets.token_hex(32)
                self.secrets[key_id] = key
                signature_data["key_id"] = key_id
            else:
                # For externally provided keys, we'll use a hash of the key as the ID
                key_id = hashlib.sha256(key.encode()).hexdigest()[:16]
                signature_data["key_id"] = key_id
            
            # Create HMAC signature
            h = hmac.new(key.encode(), message_to_sign.encode(), hmac_algo)
            signature = h.hexdigest()
            
            # For additional security with HMAC, we can also store the message
            self.signatures[signature] = message
            
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        # Build the complete signature data
        signature_data["signature"] = signature
        if include_timestamp:
            signature_data["timestamp"] = timestamp
        
        # Log the signature creation
        if hasattr(self, 'security_monitor'):
            self.security_monitor.log_event(
                "SIGNATURE_CREATED",
                f"Message signature created using {algorithm}",
                SecurityRisk.LOW,
                {"algorithm": algorithm, "timestamp": timestamp}
            )
        
        return signature_data
    
    def verify_message(self, message: str, signature: str) -> bool:
        """Verify a message signature."""
        computed_signature = hashlib.sha256(message.encode()).hexdigest()
        stored_message = self.signatures.get(signature)
        
        if not stored_message:
            self.security_monitor.log_event(
                "SIGNATURE_UNKNOWN", 
                "Message with unknown signature received",
                SecurityRisk.MEDIUM
            )
            return False
        
        if computed_signature != signature:
            self.security_monitor.log_event(
                "SIGNATURE_MISMATCH", 
                "Message signature verification failed",
                SecurityRisk.HIGH
            )
            return False
        
        if stored_message != message:
            self.security_monitor.log_event(
                "MESSAGE_TAMPERED", 
                "Message content does not match signed message",
                SecurityRisk.HIGH
            )
            return False
        
        return True
    
    def verify_message_signature(self, message: str, signature_data: Dict[str, Any]) -> bool:
        """
        Verify a message signature generated by generate_message_signature.
        
        Args:
            message: The message to verify
            signature_data: The signature data returned by generate_message_signature
            
        Returns:
            True if the signature is valid, False otherwise
        """
        if not isinstance(signature_data, dict):
            self.security_monitor.log_event(
                "INVALID_SIGNATURE_FORMAT",
                "Signature data must be a dictionary",
                SecurityRisk.MEDIUM
            )
            return False
        
        # Extract signature components
        algorithm = signature_data.get("algorithm")
        signature = signature_data.get("signature")
        timestamp = signature_data.get("timestamp")
        key_id = signature_data.get("key_id")
        
        if not all([algorithm, signature]):
            self.security_monitor.log_event(
                "MISSING_SIGNATURE_COMPONENTS",
                "Signature data is missing required components",
                SecurityRisk.MEDIUM
            )
            return False
        
        # Reconstruct the message with timestamp if needed
        message_to_verify = message
        if timestamp:
            message_to_verify = f"{message}|{timestamp}"
            
            # Optionally check for timestamp expiration
            current_time = int(time.time())
            time_diff = current_time - timestamp
            if time_diff > 300:  # 5 minutes
                self.security_monitor.log_event(
                    "SIGNATURE_EXPIRED",
                    f"Message signature expired (age: {time_diff} seconds)",
                    SecurityRisk.MEDIUM
                )
                return False
        
        # Verify the signature based on the algorithm
        if algorithm == "sha256":
            computed_signature = hashlib.sha256(message_to_verify.encode()).hexdigest()
            result = computed_signature == signature
        
        elif algorithm == "sha512":
            computed_signature = hashlib.sha512(message_to_verify.encode()).hexdigest()
            result = computed_signature == signature
        
        elif algorithm.startswith("hmac-"):
            # Handle HMAC verification
            if not key_id:
                self.security_monitor.log_event(
                    "MISSING_KEY_ID",
                    "HMAC verification requires key_id",
                    SecurityRisk.MEDIUM
                )
                return False
            
            key = self.secrets.get(key_id)
            if not key:
                self.security_monitor.log_event(
                    "UNKNOWN_KEY_ID",
                    f"Unknown key ID: {key_id}",
                    SecurityRisk.MEDIUM
                )
                return False
            
            hash_algo = algorithm.split("-")[1]
            hmac_algo = getattr(hashlib, hash_algo)
            
            h = hmac.new(key.encode(), message_to_verify.encode(), hmac_algo)
            computed_signature = h.hexdigest()
            result = computed_signature == signature
            
            # Check stored message for HMAC (if available)
            if result and signature in self.signatures:
                stored_message = self.signatures.get(signature)
                if stored_message != message:
                    self.security_monitor.log_event(
                        "MESSAGE_TAMPERED",
                        "Message content does not match signed message",
                        SecurityRisk.HIGH
                    )
                    return False
        else:
            self.security_monitor.log_event(
                "UNSUPPORTED_ALGORITHM",
                f"Unsupported algorithm: {algorithm}",
                SecurityRisk.MEDIUM
            )
            return False
        
        # Log the verification result
        if result:
            self.security_monitor.log_event(
                "SIGNATURE_VERIFIED",
                f"Message signature verified successfully using {algorithm}",
                SecurityRisk.LOW
            )
        else:
            self.security_monitor.log_event(
                "SIGNATURE_VERIFICATION_FAILED",
                f"Message signature verification failed using {algorithm}",
                SecurityRisk.HIGH
            )
        
        return result
    
    def evaluate_security(self, content: str) -> List[SecurityRisk]:
        """Evaluate content against all security policies."""
        all_risks = []
        
        # Apply prompt injection defense
        prompt_injection_risk = PromptInjectionDefense.detect_prompt_injection(content)
        if prompt_injection_risk:
            all_risks.append(prompt_injection_risk)
        
        # Apply data leakage defense
        pii_risks = DataLeakageDefense.detect_pii(content)
        all_risks.extend(pii_risks)
        
        # Apply all policies
        for policy in self.policies:
            policy_risks = policy.evaluate(content)
            all_risks.extend(policy_risks)
        
        # Log security risks
        for risk in all_risks:
            self.security_monitor.log_event(
                "SECURITY_RISK", 
                risk.description,
                risk.severity,
                {"remediation": risk.remediation}
            )
        
        return all_risks
    
    def secure_input(self, content: str) -> Tuple[str, bool, List[SecurityRisk]]:
        """
        Secure an input message. Returns the secured message, a flag indicating
        whether it's safe, and a list of detected risks.
        """
        risks = self.evaluate_security(content)
        
        # Check if any high or critical risks were detected
        has_critical_risks = any(risk.severity in [SecurityRisk.HIGH, SecurityRisk.CRITICAL] 
                                for risk in risks)
        
        if has_critical_risks:
            # Consider sanitizing or rejecting the input
            return content, False, risks
        
        return content, True, risks
    
    def secure_output(self, content: str) -> Tuple[str, bool, List[SecurityRisk]]:
        """
        Secure an output message. Returns the secured message, a flag indicating
        whether it's safe, and a list of detected risks.
        """
        risks = self.evaluate_security(content)
        
        # Check if any high or critical risks were detected
        has_critical_risks = any(risk.severity in [SecurityRisk.HIGH, SecurityRisk.CRITICAL] 
                                for risk in risks)
        
        if has_critical_risks:
            # Consider sanitizing or blocking the output
            return content, False, risks
        
        # Sign the output message
        signature = self.sign_message(content)
        
        return content, True, risks

def secure_agent_method(method_name: str = None):
    """
    Decorator for adding security controls to agent methods.
    
    Args:
        method_name: Optional name of the method being secured, for logging purposes
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(self, *args, **kwargs):
            # Get the actual method name if not provided
            actual_method_name = method_name or func.__name__
            
            # Log method call
            if hasattr(self, 'security_monitor'):
                args_str = ", ".join([str(arg) for arg in args])
                kwargs_str = ", ".join([f"{k}={v}" for k, v in kwargs.items()])
                self.security_monitor.log_event(
                    "METHOD_CALL",
                    f"Method {actual_method_name} called with args: {args_str}, kwargs: {kwargs_str}",
                    SecurityRisk.LOW
                )
            
            # Get method parameters and check for security risks in string arguments
            risks = []
            if hasattr(self, 'evaluate_security'):
                sig = inspect.signature(func)
                param_names = list(sig.parameters.keys())[1:]  # Skip 'self'
                
                # Check security risks in string arguments
                for i, arg in enumerate(args):
                    if isinstance(arg, str) and i < len(param_names):
                        content_risks = self.evaluate_security(arg)
                        if content_risks:
                            risks.extend(content_risks)
                
                # Check security risks in string keyword arguments
                for key, value in kwargs.items():
                    if isinstance(value, str):
                        content_risks = self.evaluate_security(value)
                        if content_risks:
                            risks.extend(content_risks)
            
            # If high or critical risks were detected, we might want to prevent the method call
            has_critical_risks = any(risk.severity in [SecurityRisk.HIGH, SecurityRisk.CRITICAL] 
                                    for risk in risks)
            
            if has_critical_risks and hasattr(self, 'security_monitor'):
                self.security_monitor.log_event(
                    "METHOD_BLOCKED",
                    f"Method {actual_method_name} was blocked due to security risks",
                    SecurityRisk.HIGH,
                    {"risks": [risk.to_dict() for risk in risks]}
                )
                
                # Return a default value or raise an exception
                return None
            
            # Call the original method
            result = func(self, *args, **kwargs)
            
            # Check security risks in the result if it's a string
            if hasattr(self, 'evaluate_security') and isinstance(result, str):
                result_risks = self.evaluate_security(result)
                if result_risks:
                    risks.extend(result_risks)
            
            return result
        
        return wrapper
    
    return decorator

# Default security policies
def create_default_prompt_injection_policy() -> SecurityPolicy:
    """Create a default security policy for prompt injection detection."""
    policy = SecurityPolicy(
        "Default Prompt Injection Policy",
        "Detects common prompt injection patterns"
    )
    
    policy.add_rule(
        PromptInjectionDefense.detect_prompt_injection,
        "Detect prompt injection patterns"
    )
    
    return policy

def create_default_data_leakage_policy() -> SecurityPolicy:
    """Create a default security policy for data leakage detection."""
    policy = SecurityPolicy(
        "Default Data Leakage Policy",
        "Detects common data leakage patterns"
    )
    
    policy.add_rule(
        lambda text: DataLeakageDefense.detect_pii(text),
        "Detect PII in content"
    )
    
    return policy

# Create a default set of security policies
DEFAULT_SECURITY_POLICIES = [
    create_default_prompt_injection_policy(),
    create_default_data_leakage_policy()
]

# Common functions
def sanitize_input(text: str) -> str:
    """
    Sanitize input to prevent XSS, command injection, etc.
    This is a simple example - in a real system, you'd want more comprehensive sanitization.
    """
    # Replace potentially dangerous characters
    sanitized = text.replace("<", "&lt;").replace(">", "&gt;")
    
    # Remove potential command injection sequences
    sanitized = re.sub(r"[;&|`$]", "", sanitized)
    
    return sanitized

def validate_input(text: str, min_length: int = 1, max_length: int = 10000) -> bool:
    """Validate input basic constraints."""
    if not isinstance(text, str):
        return False
    
    if len(text) < min_length or len(text) > max_length:
        return False
    
    return True
