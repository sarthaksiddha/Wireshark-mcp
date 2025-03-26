"""
Core module for Wireshark MCP.
Contains the main WiresharkMCP class that handles packet extraction and context generation.
"""

import os
import subprocess
import json
import tempfile
from typing import List, Dict, Any, Optional, Union
import logging

from .protocols import Protocol, get_protocol_analyzer
from .filter import Filter
from .extractors import TsharkExtractor

logger = logging.getLogger(__name__)

class WiresharkMCP:
    """
    Main class for extracting and analyzing network packet captures.
    
    This class provides methods to extract packet data from pcap files,
    analyze protocols, generate contexts for AI models, and perform
    specialized analysis.
    """
    
    def __init__(self, pcap_path: str, tshark_path: Optional[str] = None):
        """
        Initialize the Wireshark MCP with a packet capture file.
        
        Args:
            pcap_path: Path to the pcap file to analyze
            tshark_path: Optional path to tshark executable
        
        Raises:
            FileNotFoundError: If the pcap file doesn't exist
            ValueError: If tshark is not found
        """
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"Packet capture file not found: {pcap_path}")
        
        self.pcap_path = pcap_path
        self.tshark_path = tshark_path or self._find_tshark()
        self.extractor = TsharkExtractor(self.tshark_path)
        self._protocol_analyzers = {}  # Initialized when needed
        self._cached_packets = None
        
    def _find_tshark(self) -> str:
        """Find the tshark executable on the system."""
        # Common paths where tshark might be installed
        common_paths = [
            "tshark",  # If in PATH
            "/usr/bin/tshark",
            "/usr/local/bin/tshark",
            "C:\\Program Files\\Wireshark\\tshark.exe",
        ]
        
        for path in common_paths:
            try:
                subprocess.run([path, "--version"], 
                               stdout=subprocess.PIPE, 
                               stderr=subprocess.PIPE, 
                               check=False)
                return path
            except (FileNotFoundError, subprocess.SubprocessError):
                continue
                
        raise ValueError("tshark not found. Please install Wireshark/tshark or provide the path.")
    
    def _get_protocol_analyzer(self, protocol: Union[str, Protocol]):
        """Get the appropriate protocol analyzer instance."""
        if isinstance(protocol, str):
            protocol = Protocol(protocol)
            
        if protocol not in self._protocol_analyzers:
            analyzer_class = get_protocol_analyzer(protocol)
            self._protocol_analyzers[protocol] = analyzer_class()
            
        return self._protocol_analyzers[protocol]
    
    def extract_protocol(self, 
                        protocol: Union[str, Protocol], 
                        filter: Optional[Filter] = None,
                        include_headers: bool = True,
                        include_body: bool = False,
                        max_conversations: int = 10) -> Dict[str, Any]:
        """
        Extract and analyze packets for a specific protocol.
        
        Args:
            protocol: Protocol to extract (e.g., HTTP, DNS)
            filter: Optional Wireshark display filter
            include_headers: Whether to include protocol headers
            include_body: Whether to include message bodies
            max_conversations: Maximum number of conversations to include
            
        Returns:
            Dictionary containing analyzed protocol data
        """
        protocol_obj = protocol if isinstance(protocol, Protocol) else Protocol(protocol)
        filter_str = str(filter) if filter else f"{protocol_obj.value.lower()}"
        
        packets = self.extractor.extract_packets(
            self.pcap_path, 
            filter_str, 
            max_packets=max_conversations * 10  # Extract more than needed to find full conversations
        )
        
        analyzer = self._get_protocol_analyzer(protocol_obj)
        features = analyzer.extract_features(
            packets,
            include_headers=include_headers,
            include_body=include_body
        )
        
        context = analyzer.generate_context(
            features,
            max_conversations=max_conversations
        )
        
        return context
    
    def generate_context(self,
                        max_packets: int = 100,
                        focus_protocols: Optional[List[Union[str, Protocol]]] = None,
                        include_statistics: bool = True) -> Dict[str, Any]:
        """
        Generate a comprehensive context from the packet capture.
        
        Args:
            max_packets: Maximum number of packets to include
            focus_protocols: List of protocols to focus on
            include_statistics: Whether to include statistical summaries
            
        Returns:
            Dictionary containing the analyzed context
        """
        # Extract basic packet data
        if not self._cached_packets:
            self._cached_packets = self.extractor.extract_packets(
                self.pcap_path, max_packets=max_packets
            )
        
        # Initialize context structure
        context = {
            "packets": self._cached_packets[:max_packets],
            "summary": {
                "total_packets": len(self._cached_packets),
                "included_packets": min(max_packets, len(self._cached_packets)),
                "capture_duration": self._calculate_duration(self._cached_packets),
                "protocols": self._identify_protocols(self._cached_packets)
            },
            "protocol_data": {}
        }
        
        # Add focused protocol details
        if focus_protocols:
            for protocol in focus_protocols:
                proto_obj = protocol if isinstance(protocol, Protocol) else Protocol(protocol)
                try:
                    proto_context = self.extract_protocol(
                        proto_obj,
                        max_conversations=5  # Limited for the general context
                    )
                    context["protocol_data"][proto_obj.value] = proto_context
                except Exception as e:
                    logger.warning(f"Error analyzing protocol {proto_obj.value}: {e}")
        
        # Add statistical data if requested
        if include_statistics:
            context["statistics"] = self._generate_statistics(self._cached_packets)
            
        return context
    
    def extract_flows(self,
                     client_ip: Optional[str] = None,
                     include_details: bool = True,
                     max_flows: int = 5) -> Dict[str, Any]:
        """
        Extract conversation flows from the packet capture.
        
        Args:
            client_ip: Optional client IP to focus on
            include_details: Whether to include detailed packet data
            max_flows: Maximum number of flows to include
            
        Returns:
            Dictionary containing flow data
        """
        # This would be implemented by the specialized flow analyzer
        # For now, we'll return a placeholder
        from .flow_analyzer import FlowAnalyzer
        
        if not self._cached_packets:
            self._cached_packets = self.extractor.extract_packets(self.pcap_path)
            
        flow_analyzer = FlowAnalyzer(self._cached_packets)
        flows = flow_analyzer.analyze_flows(
            client_ip=client_ip,
            include_details=include_details,
            max_flows=max_flows
        )
        
        return flows
    
    def security_analysis(self,
                         detect_scanning: bool = True,
                         detect_malware_patterns: bool = True,
                         highlight_unusual_ports: bool = True,
                         check_encryption: bool = True) -> Dict[str, Any]:
        """
        Perform security-focused analysis on the packet capture.
        
        Args:
            detect_scanning: Whether to look for port scanning patterns
            detect_malware_patterns: Whether to check for known malware patterns
            highlight_unusual_ports: Whether to highlight unusual port usage
            check_encryption: Whether to analyze encryption usage
            
        Returns:
            Dictionary containing security analysis results
        """
        # This would be implemented by the specialized security analyzer
        # For now, we'll return a placeholder
        from .security_analyzer import SecurityAnalyzer
        
        if not self._cached_packets:
            self._cached_packets = self.extractor.extract_packets(self.pcap_path)
            
        security_analyzer = SecurityAnalyzer(self._cached_packets)
        security_results = security_analyzer.analyze(
            detect_scanning=detect_scanning,
            detect_malware_patterns=detect_malware_patterns,
            highlight_unusual_ports=highlight_unusual_ports,
            check_encryption=check_encryption
        )
        
        return security_results
    
    def protocol_insights(self,
                         protocol: Union[str, Protocol],
                         extract_queries: bool = True,
                         analyze_response_codes: bool = True,
                         detect_tunneling: bool = False) -> Dict[str, Any]:
        """
        Generate in-depth insights for a specific protocol.
        
        Args:
            protocol: Protocol to analyze
            extract_queries: Whether to extract query data
            analyze_response_codes: Whether to analyze response codes
            detect_tunneling: Whether to look for protocol tunneling
            
        Returns:
            Dictionary containing protocol insights
        """
        proto_obj = protocol if isinstance(protocol, Protocol) else Protocol(protocol)
        analyzer = self._get_protocol_analyzer(proto_obj)
        
        # Extract protocol-specific packets
        proto_packets = self.extractor.extract_packets(
            self.pcap_path, 
            filter_str=f"{proto_obj.value.lower()}"
        )
        
        features = analyzer.extract_features(proto_packets)
        context = analyzer.generate_context(features)
        
        # Add additional insights based on parameters
        if hasattr(analyzer, 'extract_insights'):
            insights = analyzer.extract_insights(
                proto_packets,
                extract_queries=extract_queries,
                analyze_response_codes=analyze_response_codes,
                detect_tunneling=detect_tunneling
            )
            context['insights'] = insights
            
        return context
    
    def _calculate_duration(self, packets: List[Dict[str, Any]]) -> float:
        """Calculate the duration of the packet capture in seconds."""
        if not packets:
            return 0.0
            
        start_time = float(packets[0].get('timestamp', 0))
        end_time = float(packets[-1].get('timestamp', 0))
        
        return end_time - start_time
    
    def _identify_protocols(self, packets: List[Dict[str, Any]]) -> Dict[str, int]:
        """Identify protocols and their frequency in the packet capture."""
        protocols = {}
        
        for packet in packets:
            for layer in packet.get('layers', []):
                protocol = layer.get('protocol')
                if protocol:
                    protocols[protocol] = protocols.get(protocol, 0) + 1
                    
        return protocols
    
    def _generate_statistics(self, packets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate statistical summaries from the packet data."""
        if not packets:
            return {}
            
        ip_counts = {}
        port_counts = {}
        packet_sizes = []
        
        for packet in packets:
            # Collect packet sizes
            packet_sizes.append(int(packet.get('length', 0)))
            
            # Collect IP addresses
            if 'ip' in packet:
                src_ip = packet['ip'].get('src')
                dst_ip = packet['ip'].get('dst')
                
                if src_ip:
                    ip_counts[src_ip] = ip_counts.get(src_ip, 0) + 1
                if dst_ip:
                    ip_counts[dst_ip] = ip_counts.get(dst_ip, 0) + 1
            
            # Collect port information
            if 'tcp' in packet:
                src_port = packet['tcp'].get('srcport')
                dst_port = packet['tcp'].get('dstport')
                
                if src_port:
                    port_counts[f"TCP:{src_port}"] = port_counts.get(f"TCP:{src_port}", 0) + 1
                if dst_port:
                    port_counts[f"TCP:{dst_port}"] = port_counts.get(f"TCP:{dst_port}", 0) + 1
                    
            if 'udp' in packet:
                src_port = packet['udp'].get('srcport')
                dst_port = packet['udp'].get('dstport')
                
                if src_port:
                    port_counts[f"UDP:{src_port}"] = port_counts.get(f"UDP:{src_port}", 0) + 1
                if dst_port:
                    port_counts[f"UDP:{dst_port}"] = port_counts.get(f"UDP:{dst_port}", 0) + 1
        
        # Find top talkers (IPs with most packets)
        top_talkers = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Find top ports
        top_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Calculate packet size statistics
        avg_size = sum(packet_sizes) / len(packet_sizes) if packet_sizes else 0
        min_size = min(packet_sizes) if packet_sizes else 0
        max_size = max(packet_sizes) if packet_sizes else 0
        
        return {
            "top_talkers": dict(top_talkers),
            "top_ports": dict(top_ports),
            "packet_sizes": {
                "average": avg_size,
                "min": min_size,
                "max": max_size
            }
        }
