"""
Extractors for Wireshark MCP.

This module provides packet extraction interfaces for various sources,
such as tshark, pcap files, and network interfaces.
"""

from .base import BaseExtractor
from .tshark import TsharkExtractor

__all__ = ['BaseExtractor', 'TsharkExtractor']
