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
    
    def _format_protocol_context(self, 
                               protocol_context: Dict[str, Any], 
                               protocol_name: str) -> str:
        """Format a protocol-specific context."""
        formatted_lines = []
        
        # Add basic protocol info
        summary = protocol_context.get('summary', {})
        if summary:
            for key, value in summary.items():
                formatted_key = ' '.join(word.capitalize() for word in key.split('_'))
                formatted_lines.append(f"- {formatted_key}: {value}")
        
        # Add a brief sample of transactions if available
        transactions = protocol_context.get('transactions', [])
        if transactions and len(transactions) > 0:
            formatted_lines.extend([
                "",
                f"Notable {protocol_name} transactions:",
            ])
            
            # Add a few example transactions
            for i, transaction in enumerate(transactions[:2]):  # Limit to 2 examples
                transaction_summary = self._summarize_transaction(transaction, protocol_name)
                formatted_lines.append(f"- Transaction {i+1}: {transaction_summary}")
        
        # Join with newlines
        return "\n".join(formatted_lines)
    
    def _format_packet_sample(self, 
                            packet: Dict[str, Any], 
                            index: int) -> str:
        """Format a packet for display in the context."""
        # Basic packet information
        timestamp = packet.get('timestamp', 0)
        length = packet.get('length', 0)
        
        # Try to get source and destination from IP layer
        src = dst = "Unknown"
        if 'ip' in packet:
            src = packet['ip'].get('src', 'Unknown')
            dst = packet['ip'].get('dst', 'Unknown')
        
        # Try to get protocol information
        protocol = "Unknown"
        for layer in packet.get('layers', []):
            if 'protocol' in layer:
                protocol = layer['protocol']
                break
        
        # Format as a simple line
        return f"Packet {index}: {timestamp} | {protocol} | {src} -> {dst} | {length} bytes"
    
    def _summarize_transaction(self, 
                             transaction: Dict[str, Any], 
                             protocol_name: str) -> str:
        """Create a one-line summary of a transaction."""
        if protocol_name == "HTTP":
            # HTTP transaction summary
            request = transaction.get('query', {})
            response = transaction.get('response', {})
            
            method = request.get('method', 'GET')
            uri = request.get('uri', '')
            host = request.get('headers', {}).get('host', '')
            status = response.get('status_code', '')
            
            return f"{method} {host}{uri} -> {status}"
            
        elif protocol_name == "DNS":
            # DNS transaction summary
            query = transaction.get('query', {})
            response = transaction.get('response', {})
            
            questions = query.get('questions', [])
            question_str = "Unknown"
            if questions and len(questions) > 0:
                name = questions[0].get('name', '')
                qtype = questions[0].get('type', '')
                question_str = f"{name} ({qtype})"
            
            resp_name = response.get('response_code_name', 'Unknown') if response else "No response"
            
            return f"Query: {question_str} -> {resp_name}"
            
        else:
            # Generic transaction summary
            return f"{protocol_name} transaction"
    
    def _truncate_context(self, context: str) -> str:
        """
        Intelligently truncate the context to fit within the maximum length.
        
        This tries to preserve section headers and important information
        while reducing excessive details.
        """
        if len(context) <= self.max_context_length:
            return context
        
        # Split the context into sections (by headers)
        sections = []
        current_section = []
        current_header = "Header"
        
        for line in context.split('\n'):
            if line.startswith('#'):
                # This is a header, store the previous section
                if current_section:
                    sections.append({
                        'header': current_header,
                        'content': current_section
                    })
                current_header = line
                current_section = []
            else:
                current_section.append(line)
        
        # Add the last section
        if current_section:
            sections.append({
                'header': current_header,
                'content': current_section
            })
        
        # Calculate total content length
        total_content_length = sum(len('\n'.join(section['content'])) for section in sections)
        headers_length = sum(len(section['header']) + 1 for section in sections)  # +1 for newline
        
        # If we need to truncate, do it proportionally across all sections
        if headers_length + total_content_length + len(sections) > self.max_context_length:
            # How much content we can keep
            content_budget = self.max_context_length - headers_length - len(sections)
            
            # Build the truncated context
            truncated_context = []
            
            for section in sections:
                # Add the header
                truncated_context.append(section['header'])
                
                # Calculate how much content to keep for this section
                content_text = '\n'.join(section['content'])
                content_length = len(content_text)
                
                # Keep this section's proportional share of the content budget
                if total_content_length > 0:
                    keep_ratio = content_budget / total_content_length
                    keep_length = int(content_length * keep_ratio)
                else:
                    keep_length = 0
                
                # Add truncated content
                if keep_length > 0:
                    if keep_length >= content_length:
                        # Can keep the whole section
                        truncated_context.append(content_text)
                    else:
                        # Need to truncate this section
                        truncated_context.append(content_text[:keep_length] + "\n... [content truncated]")
                else:
                    truncated_context.append("... [content truncated]")
            
            return '\n'.join(truncated_context)
        
        # No truncation needed
        return context
