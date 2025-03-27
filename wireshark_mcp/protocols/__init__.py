"""
Protocol module that defines supported protocols and protocol analyzers.
"""

from enum import Enum
from typing import Dict, Type, Any

class Protocol(Enum):
    """Enum of supported network protocols."""
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    DNS = "DNS"
    TLS = "TLS"
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    DHCP = "DHCP"
    ARP = "ARP"
    FTP = "FTP"
    SMTP = "SMTP"
    SSH = "SSH"
    TELNET = "TELNET"
    NTP = "NTP"
    SSDP = "SSDP"
    MDNS = "MDNS"
    QUIC = "QUIC"
    SMB = "SMB"
    
    def __str__(self):
        return self.value

# Import protocol analyzers
from .base import BaseProtocolAnalyzer
from .http import HTTPProtocolAnalyzer
from .dns import DNSProtocolAnalyzer

# Registry of protocol analyzers
_PROTOCOL_ANALYZERS: Dict[Protocol, Type[BaseProtocolAnalyzer]] = {
    Protocol.HTTP: HTTPProtocolAnalyzer,
    Protocol.DNS: DNSProtocolAnalyzer,
    # Add more protocol analyzers as they are implemented
}

def get_protocol_analyzer(protocol: Protocol) -> Type[BaseProtocolAnalyzer]:
    """
    Get the protocol analyzer class for a given protocol.
    
    Args:
        protocol: Protocol enum value
    
    Returns:
        Protocol analyzer class
        
    Raises:
        ValueError: If no analyzer is available for the protocol
    """
    if protocol not in _PROTOCOL_ANALYZERS:
        raise ValueError(f"No analyzer available for protocol: {protocol}")
    
    return _PROTOCOL_ANALYZERS[protocol]

def register_protocol_analyzer(analyzer_class: Type[BaseProtocolAnalyzer]) -> None:
    """
    Register a custom protocol analyzer.
    
    Args:
        analyzer_class: Protocol analyzer class to register
    """
    protocol_name = analyzer_class.protocol_name
    try:
        protocol = Protocol(protocol_name)
        _PROTOCOL_ANALYZERS[protocol] = analyzer_class
    except ValueError:
        # If the protocol is not in the enum, add it dynamically
        # This is a placeholder - Python's Enum doesn't support dynamic addition
        # In a real implementation, this would need a different approach
        print(f"Warning: Protocol {protocol_name} not in Protocol enum, skipping registration")
