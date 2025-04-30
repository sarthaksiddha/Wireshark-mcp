import logging
from typing import Dict, List, Any, Optional, Tuple, Union

from .security import (
    SecurityRisk, SecurityPolicy, SecurityMonitor, 
    AgentSecurityWrapper, DEFAULT_SECURITY_POLICIES
)
from .ip_protection import IPProtectionManager

class SecurityManager:
    """
    Integrated security management system for Wireshark MCP.
    
    This class integrates various security components including IP protection,
    content security controls, agent security, and monitoring capabilities into
    a unified security management system for network packet analysis.
    """
    
    def __init__(self):
        """
        Initialize the Security Manager with default components.
        """
        self.ip_protection = IPProtectionManager()
        self.security_monitor = SecurityMonitor()
        self.security_policies = DEFAULT_SECURITY_POLICIES.copy()
        self.custom_policies = []
        self.hmac_keys = {}  # For storing HMAC keys used in message signing
        self.logger = logging.getLogger(__name__)
    
    def add_security_policy(self, policy: SecurityPolicy):
        """
        Add a custom security policy.
        
        Args:
            policy: The SecurityPolicy to add
        """
        self.custom_policies.append(policy)
        self.logger.info(f"Added custom security policy: {policy.name}")
    
    def configure_ip_protection(self, mode: str = IPProtectionManager.PARTIAL_MASK):
        """
        Configure the IP protection component.
        
        Args:
            mode: The protection mode to use
        """
        self.ip_protection.protection_mode = mode
        self.logger.info(f"Set IP protection mode to {mode}")
    
    def add_protected_ip_range(self, cidr_range: str):
        """
        Add an IP range that should be protected.
        
        Args:
            cidr_range: IP range in CIDR notation
        """
        self.ip_protection.add_protected_range(cidr_range)
    
    def protect_packet(self, packet: Dict[str, Any], mode: Optional[str] = None) -> Dict[str, Any]:
        """
        Apply IP protection to a packet.
        
        Args:
            packet: The packet to protect
            mode: Optional protection mode to use
            
        Returns:
            The protected packet
        """
        return self.ip_protection.protect_packet(packet, mode)
    
    def protect_packets(self, packets: List[Dict[str, Any]], mode: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Apply IP protection to a list of packets.
        
        Args:
            packets: The packets to protect
            mode: Optional protection mode to use
            
        Returns:
            The protected packets
        """
        return [self.protect_packet(packet, mode) for packet in packets]
    
    def evaluate_content_security(self, content: str) -> List[SecurityRisk]:
        """
        Evaluate content against all security policies.
        
        Args:
            content: The content to evaluate
            
        Returns:
            List of identified security risks
        """
        all_risks = []
        
        # Apply all standard security policies
        for policy in self.security_policies + self.custom_policies:
            policy_risks = policy.evaluate(content)
            all_risks.extend(policy_risks)
        
        # Log all identified risks
        for risk in all_risks:
            self.security_monitor.log_event(
                "CONTENT_SECURITY_RISK",
                risk.description,
                risk.severity,
                {"remediation": risk.remediation}
            )
        
        return all_risks
    
    def create_agent_wrapper(self, agent) -> AgentSecurityWrapper:
        """
        Create a security wrapper for an agent.
        
        Args:
            agent: The agent to wrap
            
        Returns:
            The wrapped agent with security controls
        """
        return AgentSecurityWrapper(
            agent, 
            security_monitor=self.security_monitor,
            policies=self.security_policies + self.custom_policies
        )
    
    def sign_message(self, message: str, algorithm: str = "hmac-sha256") -> Dict[str, Any]:
        """
        Generate a secure signature for a message.
        
        Args:
            message: The message to sign
            algorithm: The signature algorithm to use
            
        Returns:
            Signature data dictionary
        """
        # Create a temporary wrapper to use its signature capabilities
        temp_wrapper = AgentSecurityWrapper(None, security_monitor=self.security_monitor)
        signature_data = temp_wrapper.generate_message_signature(message, algorithm=algorithm)
        
        # Store any HMAC keys for future verification
        if algorithm.startswith("hmac-") and "key_id" in signature_data:
            key_id = signature_data["key_id"]
            if key_id in temp_wrapper.secrets:
                self.hmac_keys[key_id] = temp_wrapper.secrets[key_id]
        
        return signature_data
    
    def verify_message(self, message: str, signature_data: Dict[str, Any]) -> bool:
        """
        Verify a message signature.
        
        Args:
            message: The message to verify
            signature_data: The signature data to verify against
            
        Returns:
            True if the signature is valid, False otherwise
        """
        temp_wrapper = AgentSecurityWrapper(None, security_monitor=self.security_monitor)
        
        # If using HMAC, add the key to the wrapper's secrets
        if signature_data.get("algorithm", "").startswith("hmac-") and "key_id" in signature_data:
            key_id = signature_data["key_id"]
            if key_id in self.hmac_keys:
                temp_wrapper.secrets[key_id] = self.hmac_keys[key_id]
        
        return temp_wrapper.verify_message_signature(message, signature_data)
    
    def get_security_events(self) -> List[Dict[str, Any]]:
        """
        Get the security event log.
        
        Returns:
            List of security events
        """
        return self.security_monitor.get_event_log()
    
    def clear_security_events(self):
        """
        Clear the security event log.
        """
        self.security_monitor.clear_event_log()