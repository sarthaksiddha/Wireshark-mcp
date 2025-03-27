"""
Claude-specific formatter for Wireshark MCP.

This module provides formatters optimized for Claude AI,
structuring network data in ways that maximize Claude's understanding
and analysis capabilities.
"""

import json
import logging
from typing import Dict, Any, List, Optional, Union
import textwrap
import re

from .base import BaseFormatter

logger = logging.getLogger(__name__)

class ClaudeFormatter(BaseFormatter):
    """
    Formatter specifically designed for Claude AI.
    
    Includes specialized formatting for different types of network data,
    optimized context generation, and Claude-specific prompt engineering.
    """
    
    def __init__(self, max_context_length: int = 20000):
        """
        Initialize the Claude formatter.
        
        Args:
            max_context_length: Maximum number of characters for context
        """
        super().__init__()
        self.max_context_length = max_context_length
        
    def format_context(self, 
                      context: Dict[str, Any], 
                      query: Optional[str] = None) -> str:
        """
        Format a general packet context for Claude.
        
        Args:
            context: Dictionary containing context data
            query: Optional query to append to the context
            
        Returns:
            String containing Claude-optimized context
        """
        # Get summary information
        summary = context.get('summary', {})
        total_packets = summary.get('total_packets', 0)
        included_packets = summary.get('included_packets', 0)
        capture_duration = summary.get('capture_duration', 0)
        protocols = summary.get('protocols', {})
        
        # Get statistics
        statistics = context.get('statistics', {})
        top_talkers = statistics.get('top_talkers', {})
        top_ports = statistics.get('top_ports', {})
        packet_sizes = statistics.get('packet_sizes', {})
        
        # Format the basic summary section
        formatted_context = [
            "# Wireshark Packet Capture Analysis",
            "",
            "## Capture Summary",
            f"- Total Packets: {total_packets}",
            f"- Included Packets: {included_packets}",
            f"- Capture Duration: {capture_duration:.2f} seconds",
            "",
            "## Protocol Distribution",
        ]
        
        # Add protocol distribution
        for protocol, count in protocols.items():
            formatted_context.append(f"- {protocol}: {count} packets")
        
        # Add statistics section if available
        if statistics:
            formatted_context.extend([
                "",
                "## Network Statistics",
                "",
                "### Top IP Addresses (Talkers)",
            ])
            
            for ip, count in top_talkers.items():
                formatted_context.append(f"- {ip}: {count} packets")
            
            formatted_context.extend([
                "",
                "### Top Ports",
            ])
            
            for port, count in top_ports.items():
                formatted_context.append(f"- {port}: {count} packets")
            
            if packet_sizes:
                formatted_context.extend([
                    "",
                    "### Packet Size Statistics",
                    f"- Average Size: {packet_sizes.get('average', 0):.2f} bytes",
                    f"- Minimum Size: {packet_sizes.get('min', 0)} bytes",
                    f"- Maximum Size: {packet_sizes.get('max', 0)} bytes",
                ])
        
        # Add protocol-specific data if available
        protocol_data = context.get('protocol_data', {})
        if protocol_data:
            formatted_context.extend([
                "",
                "## Protocol Details",
            ])
            
            for protocol, proto_context in protocol_data.items():
                formatted_context.append(f"\n### {protocol} Analysis")
                formatted_context.append(self._format_protocol_context(proto_context, protocol))
        
        # Get packets with limited details
        packets = context.get('packets', [])
        if packets:
            formatted_context.extend([
                "",
                "## Packet Samples",
                "```",
            ])
            
            # Add a few packet samples (limited for context efficiency)
            for i, packet in enumerate(packets[:10]):  # Limit to 10 packets
                packet_str = self._format_packet_sample(packet, i+1)
                formatted_context.append(packet_str)
            
            formatted_context.append("```")
        
        # Join all sections and check length
        full_context = "\n".join(formatted_context)
        
        # If we're close to the limit, truncate intelligently
        if len(full_context) > self.max_context_length:
            logger.warning("Context exceeds maximum length, truncating")
            full_context = self._truncate_context(full_context)
        
        # Append query if provided
        if query:
            full_context += f"\n\n## Query\n{query}"
        
        return full_context
