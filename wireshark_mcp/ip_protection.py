import logging
import ipaddress
import copy
from typing import Dict, List, Any, Optional, Set

class IPProtectionManager:
    """
    Manages IP address protection strategies for network packet analysis.
    
    This class provides capabilities to anonymize, obscure, or redact IP addresses
    within packet captures to protect sensitive network information while still 
    allowing for meaningful analysis. It supports various protection strategies 
    including pseudonymization, partial obfuscation, and full redaction.
    """
    
    REDACT_FULL = "REDACT_FULL"  # Replace entire IP with a marker
    REDACT_HOST = "REDACT_HOST"  # Preserve network portion, redact host portion
    PSEUDONYMIZE = "PSEUDONYMIZE"  # Replace with consistent pseudonym
    PARTIAL_MASK = "PARTIAL_MASK"  # Mask parts of the IP (like 192.168.x.x)
    
    def __init__(self, protection_mode: str = PARTIAL_MASK):
        """
        Initialize the IP Protection Manager.
        
        Args:
            protection_mode: The default protection strategy to use
        """
        self.protection_mode = protection_mode
        self.ip_mapping = {}  # For pseudonymization
        self.protected_ranges = []  # IP ranges requiring protection
        self.pseudonym_counter = 0  # Counter for generating pseudonyms
        self.logger = logging.getLogger(__name__)
    
    def add_protected_range(self, cidr_range: str):
        """
        Add an IP range that should be protected.
        
        Args:
            cidr_range: IP range in CIDR notation (e.g., '192.168.0.0/16')
        """
        try:
            network = ipaddress.ip_network(cidr_range, strict=False)
            self.protected_ranges.append(network)
            self.logger.info(f"Added protected IP range: {cidr_range}")
        except ValueError as e:
            self.logger.error(f"Invalid CIDR range '{cidr_range}': {e}")
    
    def should_protect_ip(self, ip_address: str) -> bool:
        """
        Determine if an IP address should be protected.
        
        Args:
            ip_address: The IP address to check
            
        Returns:
            True if the IP should be protected, False otherwise
        """
        try:
            ip = ipaddress.ip_address(ip_address)
            
            # Check if IP is in any protected range
            for network in self.protected_ranges:
                if ip in network:
                    return True
            
            # Always protect private addresses by default
            return ip.is_private
            
        except ValueError:
            self.logger.warning(f"Invalid IP address format: {ip_address}")
            return False
    
    def protect_ip(self, ip_address: str, mode: Optional[str] = None) -> str:
        """
        Apply protection to an IP address using the specified mode.
        
        Args:
            ip_address: The IP address to protect
            mode: The protection mode to use (defaults to self.protection_mode)
            
        Returns:
            The protected version of the IP address
        """
        if not mode:
            mode = self.protection_mode
            
        if not self.should_protect_ip(ip_address):
            return ip_address
        
        try:
            ip = ipaddress.ip_address(ip_address)
            is_ipv4 = isinstance(ip, ipaddress.IPv4Address)
            
            if mode == self.REDACT_FULL:
                return "[REDACTED]" if is_ipv4 else "[REDACTED_IPV6]"
                
            elif mode == self.REDACT_HOST:
                if is_ipv4:
                    # For IPv4, preserve network portion (first two octets)
                    octets = ip_address.split('.')
                    return f"{octets[0]}.{octets[1]}.[x].[x]"
                else:
                    # For IPv6, preserve network portion (first 4 hextets)
                    hextets = ip_address.split(':')
                    preserved = hextets[:4]
                    return ':'.join(preserved) + ':[x]:[x]:[x]:[x]'
                    
            elif mode == self.PSEUDONYMIZE:
                if ip_address not in self.ip_mapping:
                    # Generate a new pseudonym
                    self.pseudonym_counter += 1
                    if is_ipv4:
                        self.ip_mapping[ip_address] = f"10.0.{self.pseudonym_counter // 256}.{self.pseudonym_counter % 256}"
                    else:
                        self.ip_mapping[ip_address] = f"fd00::{self.pseudonym_counter:x}"
                
                return self.ip_mapping[ip_address]
                
            elif mode == self.PARTIAL_MASK:
                if is_ipv4:
                    octets = ip_address.split('.')
                    return f"{octets[0]}.{octets[1]}.x.{octets[3]}"
                else:
                    hextets = ip_address.split(':')
                    # Mask middle 4 hextets
                    masked = hextets[:2] + ['x', 'x', 'x', 'x'] + hextets[-2:]
                    return ':'.join(masked)
            
            else:
                self.logger.warning(f"Unknown protection mode: {mode}")
                return ip_address
                
        except ValueError:
            self.logger.warning(f"Invalid IP address format: {ip_address}")
            return ip_address
    
    def protect_packet(self, packet: Dict[str, Any], mode: Optional[str] = None) -> Dict[str, Any]:
        """
        Apply IP protection to all IP addresses in a packet.
        
        Args:
            packet: The packet data dictionary
            mode: The protection mode to use
            
        Returns:
            The packet with protected IP addresses
        """
        if not mode:
            mode = self.protection_mode
            
        # Create a deep copy to avoid modifying the original
        protected_packet = copy.deepcopy(packet)
        
        # Protect IP addresses in the IP layer
        if 'ip' in protected_packet:
            if 'src' in protected_packet['ip']:
                protected_packet['ip']['src'] = self.protect_ip(protected_packet['ip']['src'], mode)
            if 'dst' in protected_packet['ip']:
                protected_packet['ip']['dst'] = self.protect_ip(protected_packet['ip']['dst'], mode)
        
        # Recursively search for IP addresses in other fields
        # This is a simplified approach - a real implementation would be more comprehensive
        # to detect IP addresses in all packet fields and protocols
        
        return protected_packet
    
    def get_ip_mapping(self) -> Dict[str, str]:
        """
        Get the mapping of original IPs to pseudonyms.
        
        Returns:
            Dictionary mapping original IPs to their pseudonyms
        """
        return self.ip_mapping
    
    def reset_mapping(self):
        """
        Reset the IP pseudonym mapping.
        """
        self.ip_mapping = {}
        self.pseudonym_counter = 0