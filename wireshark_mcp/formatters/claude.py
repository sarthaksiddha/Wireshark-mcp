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
    
    def format_protocol_analysis(self, 
                               protocol_context: Dict[str, Any],
                               query: Optional[str] = None) -> str:
        """
        Format protocol-specific analysis for Claude.
        
        Args:
            protocol_context: Dictionary containing protocol analysis
            query: Optional query to append to the context
            
        Returns:
            String containing Claude-optimized protocol analysis
        """
        protocol_name = protocol_context.get('protocol', 'Unknown')
        
        # Start with protocol header
        formatted_context = [
            f"# {protocol_name} Protocol Analysis",
            "",
            "## Protocol Summary",
        ]
        
        # Add summary statistics if available
        summary = protocol_context.get('summary', {})
        if summary:
            for key, value in summary.items():
                # Convert underscores to spaces and capitalize
                formatted_key = ' '.join(word.capitalize() for word in key.split('_'))
                formatted_context.append(f"- {formatted_key}: {value}")
        
        # Add conversations/transactions if available
        transactions = protocol_context.get('transactions', [])
        if transactions:
            formatted_context.extend([
                "",
                f"## {protocol_name} Conversations",
            ])
            
            for i, transaction in enumerate(transactions):
                formatted_context.append(f"\n### Conversation {i+1}")
                formatted_context.append(self._format_transaction(transaction, protocol_name))
        
        # Add insights if available
        insights = protocol_context.get('insights', [])
        if insights:
            formatted_context.extend([
                "",
                "## Analysis Insights",
            ])
            
            for insight in insights:
                insight_type = insight.get('type', 'observation')
                description = insight.get('description', 'No description')
                formatted_context.extend([
                    f"- **{insight_type.replace('_', ' ').title()}**: {description}"
                ])
                
                # Add details for some insight types
                if 'domains' in insight:
                    domains = insight.get('domains', [])
                    domain_str = ', '.join(domains)
                    formatted_context.append(f"  - Domains: {domain_str}")
        
        # Join all sections and check length
        full_context = "\n".join(formatted_context)
        
        # Truncate if necessary
        if len(full_context) > self.max_context_length:
            logger.warning("Protocol context exceeds maximum length, truncating")
            full_context = self._truncate_context(full_context)
        
        # Append query if provided
        if query:
            full_context += f"\n\n## Query\n{query}"
        
        return full_context
    
    def format_flows(self,
                   flows: Dict[str, Any],
                   query: Optional[str] = None) -> str:
        """
        Format flow analysis for Claude.
        
        Args:
            flows: Dictionary containing flow analysis
            query: Optional query to append to the context
            
        Returns:
            String containing Claude-optimized flow analysis
        """
        # Start with flow analysis header
        formatted_context = [
            "# Network Flow Analysis",
            "",
            "## Flow Summary",
        ]
        
        # Add summary statistics if available
        summary = flows.get('summary', {})
        if summary:
            for key, value in summary.items():
                # Convert underscores to spaces and capitalize
                formatted_key = ' '.join(word.capitalize() for word in key.split('_'))
                formatted_context.append(f"- {formatted_key}: {value}")
        
        # Add flow details
        flow_list = flows.get('flows', [])
        if flow_list:
            formatted_context.extend([
                "",
                "## Individual Flows",
            ])
            
            for i, flow in enumerate(flow_list):
                formatted_context.append(f"\n### Flow {i+1}")
                
                # Basic flow information
                src = flow.get('src_ip', 'Unknown')
                dst = flow.get('dst_ip', 'Unknown')
                proto = flow.get('protocol', 'Unknown')
                src_port = flow.get('src_port', '')
                dst_port = flow.get('dst_port', '')
                
                formatted_context.extend([
                    f"- Source: {src}" + (f":{src_port}" if src_port else ""),
                    f"- Destination: {dst}" + (f":{dst_port}" if dst_port else ""),
                    f"- Protocol: {proto}",
                    f"- Packets: {flow.get('packets', 0)}",
                    f"- Bytes: {flow.get('bytes', 0)}",
                ])
                
                # Add timing information if available
                if 'start_time' in flow and 'end_time' in flow:
                    duration = flow.get('end_time', 0) - flow.get('start_time', 0)
                    formatted_context.append(f"- Duration: {duration:.2f} seconds")
                
                # Add flags information for TCP flows
                flags = flow.get('flags', [])
                if flags:
                    formatted_context.append(f"- TCP Flags: {', '.join(flags)}")
                
                # Add application-level protocol if identified
                app_proto = flow.get('application_protocol')
                if app_proto:
                    formatted_context.append(f"- Application Protocol: {app_proto}")
        
        # Add flow insights if available
        insights = flows.get('insights', [])
        if insights:
            formatted_context.extend([
                "",
                "## Flow Insights",
            ])
            
            for insight in insights:
                insight_type = insight.get('type', 'observation')
                description = insight.get('description', 'No description')
                formatted_context.append(f"- **{insight_type.replace('_', ' ').title()}**: {description}")
        
        # Join all sections and check length
        full_context = "\n".join(formatted_context)
        
        # Truncate if necessary
        if len(full_context) > self.max_context_length:
            logger.warning("Flow context exceeds maximum length, truncating")
            full_context = self._truncate_context(full_context)
        
        # Append query if provided
        if query:
            full_context += f"\n\n## Query\n{query}"
        
        return full_context
    
    def format_security_context(self,
                               security_context: Dict[str, Any],
                               query: Optional[str] = None) -> str:
        """
        Format security analysis for Claude.
        
        Args:
            security_context: Dictionary containing security analysis
            query: Optional query to append to the context
            
        Returns:
            String containing Claude-optimized security analysis
        """
        # Start with security analysis header
        formatted_context = [
            "# Network Security Analysis",
            "",
            "## Security Summary",
        ]
        
        # Add summary statistics if available
        summary = security_context.get('summary', {})
        if summary:
            for key, value in summary.items():
                # Convert underscores to spaces and capitalize
                formatted_key = ' '.join(word.capitalize() for word in key.split('_'))
                formatted_context.append(f"- {formatted_key}: {value}")
        
        # Add security alerts if available
        alerts = security_context.get('alerts', [])
        if alerts:
            formatted_context.extend([
                "",
                "## Security Alerts",
            ])
            
            # Group alerts by severity
            severity_groups = {
                'high': [],
                'medium': [],
                'low': []
            }
            
            for alert in alerts:
                severity = alert.get('severity', 'medium')
                if severity in severity_groups:
                    severity_groups[severity].append(alert)
            
            # Add high severity alerts first
            if severity_groups['high']:
                formatted_context.append("\n### High Severity Alerts")
                for alert in severity_groups['high']:
                    self._format_alert(alert, formatted_context)
            
            # Add medium severity alerts
            if severity_groups['medium']:
                formatted_context.append("\n### Medium Severity Alerts")
                for alert in severity_groups['medium']:
                    self._format_alert(alert, formatted_context)
            
            # Add low severity alerts
            if severity_groups['low']:
                formatted_context.append("\n### Low Severity Alerts")
                for alert in severity_groups['low']:
                    self._format_alert(alert, formatted_context)
        
        # Add port scanning information if available
        port_scanning = security_context.get('port_scanning', {})
        if port_scanning:
            formatted_context.extend([
                "",
                "## Port Scanning Detection",
            ])
            
            # Add potential scanners
            scanners = port_scanning.get('potential_scanners', [])
            if scanners:
                formatted_context.append("\n### Potential Scanners")
                for scanner in scanners:
                    ip = scanner.get('ip', 'Unknown')
                    scan_type = scanner.get('scan_type', 'Unknown')
                    ports_count = scanner.get('unique_ports', 0)
                    hosts_count = scanner.get('unique_hosts', 0)
                    
                    formatted_context.append(f"- **{ip}**: {scan_type.title()} scan")
                    formatted_context.append(f"  - {ports_count} unique ports across {hosts_count} hosts")
        
        # Add malware indicators if available
        malware = security_context.get('malware_indicators', {})
        if malware:
            formatted_context.extend([
                "",
                "## Malware Indicators",
            ])
            
            indicators = malware.get('indicators', [])
            if indicators:
                for indicator in indicators:
                    ip = indicator.get('ip', 'Unknown')
                    indicator_type = indicator.get('type', 'Unknown')
                    description = indicator.get('description', 'No description')
                    
                    formatted_context.append(f"- **{ip}**: {indicator_type.replace('_', ' ').title()}")
                    formatted_context.append(f"  - {description}")
        
        # Add encryption analysis if available
        encryption = security_context.get('encryption_analysis', {})
        if encryption:
            formatted_context.extend([
                "",
                "## Encryption Analysis",
            ])
            
            # Add unencrypted services
            unencrypted = encryption.get('unencrypted_services', [])
            if unencrypted:
                formatted_context.append("\n### Unencrypted Services")
                for service in unencrypted:
                    service_name = service.get('service', 'Unknown')
                    port = service.get('port', 'Unknown')
                    conn_count = service.get('connection_count', 0)
                    
                    formatted_context.append(f"- **{service_name}** on port {port}")
                    formatted_context.append(f"  - {conn_count} unencrypted connections")
            
            # Add encryption statistics
            stats = encryption.get('encryption_statistics', {})
            if stats:
                formatted_context.append("\n### Encryption Statistics")
                formatted_context.append(f"- Encrypted Packets: {stats.get('encrypted_packets', 0)}")
                formatted_context.append(f"- Unencrypted Packets: {stats.get('unencrypted_packets', 0)}")
                
                # Calculate percentage if both values are present
                encrypted = stats.get('encrypted_packets', 0)
                unencrypted = stats.get('unencrypted_packets', 0)
                total = encrypted + unencrypted
                if total > 0:
                    percent_encrypted = (encrypted / total) * 100
                    formatted_context.append(f"- Percent Encrypted: {percent_encrypted:.1f}%")
        
        # Join all sections and check length
        full_context = "\n".join(formatted_context)
        
        # Truncate if necessary
        if len(full_context) > self.max_context_length:
            logger.warning("Security context exceeds maximum length, truncating")
            full_context = self._truncate_context(full_context)
        
        # Append query if provided
        if query:
            full_context += f"\n\n## Query\n{query}"
        
        return full_context
    
    def format_protocol_insights(self,
                               protocol_insights: Dict[str, Any],
                               query: Optional[str] = None) -> str:
        """
        Format protocol-specific insights for Claude.
        
        Args:
            protocol_insights: Dictionary containing protocol insights
            query: Optional query to append to the context
            
        Returns:
            String containing Claude-optimized protocol insights
        """
        protocol_name = protocol_insights.get('protocol', 'Unknown')
        
        # Start with protocol insights header
        formatted_context = [
            f"# {protocol_name} Protocol Insights",
            "",
        ]
        
        # Add query insights if available
        query_insights = protocol_insights.get('query_insights', [])
        if query_insights:
            formatted_context.extend([
                "## Query Pattern Analysis",
                "",
            ])
            
            for insight in query_insights:
                insight_type = insight.get('type', 'observation')
                description = insight.get('description', 'No description')
                formatted_context.append(f"- **{insight_type.replace('_', ' ').title()}**: {description}")
                
                # Add examples if available
                if 'examples' in insight:
                    examples = insight.get('examples', [])
                    formatted_context.append(f"  - Examples: {', '.join(examples[:3])}" + (", ..." if len(examples) > 3 else ""))
        
        # Add response insights if available
        response_insights = protocol_insights.get('response_insights', [])
        if response_insights:
            formatted_context.extend([
                "",
                "## Response Pattern Analysis",
                "",
            ])
            
            for insight in response_insights:
                insight_type = insight.get('type', 'observation')
                description = insight.get('description', 'No description')
                formatted_context.append(f"- **{insight_type.replace('_', ' ').title()}**: {description}")
        
        # Add tunneling indicators if available
        tunneling = protocol_insights.get('tunneling_indicators', [])
        if tunneling:
            formatted_context.extend([
                "",
                "## Potential Protocol Tunneling",
                "",
            ])
            
            for insight in tunneling:
                insight_type = insight.get('type', 'observation')
                description = insight.get('description', 'No description')
                formatted_context.append(f"- **{insight_type.replace('_', ' ').title()}**: {description}")
                
                # Add candidates if available
                if 'candidates' in insight:
                    candidates = insight.get('candidates', [])
                    formatted_context.extend(["  - Suspicious domains:"])
                    for candidate in candidates[:3]:  # Limit to 3 examples
                        domain = candidate.get('domain', 'Unknown')
                        count = candidate.get('unique_subdomains', 0)
                        formatted_context.append(f"    - {domain} ({count} unique subdomains)")
                    
                    if len(candidates) > 3:
                        formatted_context.append(f"    - ... and {len(candidates) - 3} more")
        
        # Join all sections and check length
        full_context = "\n".join(formatted_context)
        
        # Truncate if necessary
        if len(full_context) > self.max_context_length:
            logger.warning("Protocol insights context exceeds maximum length, truncating")
            full_context = self._truncate_context(full_context)
        
        # Append query if provided
        if query:
            full_context += f"\n\n## Query\n{query}"
        
        return full_context
