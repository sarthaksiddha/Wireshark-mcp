from enum import Enum, auto
from typing import Dict, Type, List

class Protocol(Enum):
    """
    Enumeration of common network protocols that can be analyzed.
    """
    # Layer 2 protocols
    ETHERNET = "eth"
    
    # Layer 3 protocols
    IP = "ip"
    IPV6 = "ipv6"
    ICMP = "icmp"
    ICMPV6 = "icmpv6"
    ARP = "arp"
    
    # Layer 4 protocols
    TCP = "tcp"
    UDP = "udp"
    SCTP = "sctp"
    
    # Application protocols
    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    DHCP = "dhcp"
    SMTP = "smtp"
    FTP = "ftp"
    SSH = "ssh"
    TELNET = "telnet"
    TLS = "tls"
    SSL = "ssl"
    RTP = "rtp"
    SIP = "sip"
    RTSP = "rtsp"
    MQTT = "mqtt"
    COAP = "coap"
    SMB = "smb"
    NTP = "ntp"
    SNMP = "snmp"
    LDAP = "ldap"
    RADIUS = "radius"
    KERBEROS = "kerberos"
    
    # Misc protocols
    LLDP = "lldp"
    STP = "stp"
    IGMP = "igmp"
    
    def __str__(self) -> str:
        return self.value

# Import analyzer base class and concrete implementations
from .base import BaseProtocolAnalyzer
from .http import HTTPAnalyzer
from .dns import DNSAnalyzer
from .tls import TLSAnalyzer

# Registry of protocol analyzers
_protocol_analyzers: Dict[Protocol, BaseProtocolAnalyzer] = {
    Protocol.HTTP: HTTPAnalyzer(),
    Protocol.DNS: DNSAnalyzer(),
    Protocol.TLS: TLSAnalyzer(),
}

def register_protocol_analyzer(analyzer: BaseProtocolAnalyzer) -> None:
    """
    Register a new protocol analyzer.
    
    Args:
        analyzer: Protocol analyzer instance
    """
    protocol = getattr(Protocol, analyzer.protocol_name.upper(), None)
    if not protocol:
        raise ValueError(f"Unknown protocol: {analyzer.protocol_name}")
    
    _protocol_analyzers[protocol] = analyzer

def get_protocol_analyzer(protocol: Protocol) -> BaseProtocolAnalyzer:
    """
    Get the analyzer for a specific protocol.
    
    Args:
        protocol: Protocol to get analyzer for
        
    Returns:
        Protocol analyzer instance or None if not available
    """
    return _protocol_analyzers.get(protocol)

def get_available_analyzers() -> List[Protocol]:
    """
    Get the list of protocols with available analyzers.
    
    Returns:
        List of protocols
    """
    return list(_protocol_analyzers.keys())

__all__ = [
    'Protocol', 
    'BaseProtocolAnalyzer',
    'register_protocol_analyzer',
    'get_protocol_analyzer',
    'get_available_analyzers'
]