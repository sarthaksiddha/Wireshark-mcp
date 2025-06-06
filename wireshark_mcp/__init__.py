"""
Wireshark MCP (Model Context Protocol)

A specialized protocol for extracting, structuring, and transmitting network packet data 
from Wireshark to AI systems like Claude in a context-optimized format.
"""

from .core import WiresharkMCP
from .protocols import Protocol
from .filter import Filter
from .ip_protection import IPProtectionManager
from .security_manager import SecurityManager

__version__ = "0.1.0"
__all__ = [
    "WiresharkMCP", 
    "Protocol", 
    "Filter", 
    "IPProtectionManager", 
    "SecurityManager"
]