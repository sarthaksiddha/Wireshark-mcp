"""
Base formatter class that defines the interface for all formatters.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List


class BaseFormatter(ABC):
    """
    Abstract base class for formatters.
    
    Formatters convert packet analysis data into formats optimized for specific
    AI systems. Each target system (Claude, GPT, etc.) should have its own
    formatter that inherits from this base class.
    """
    
    @abstractmethod
    def format_context(self, 
                      context: Dict[str, Any], 
                      query: Optional[str] = None) -> str:
        """
        Format a general context for the AI system.
        
        Args:
            context: Context dictionary from the analysis
            query: Optional query to include with the context
            
        Returns:
            Formatted string for the AI system
        """
        pass
    
    @abstractmethod
    def format_protocol_analysis(self, 
                               protocol_data: Dict[str, Any], 
                               query: Optional[str] = None) -> str:
        """
        Format protocol-specific analysis data.
        
        Args:
            protocol_data: Protocol analysis data
            query: Optional query to include with the analysis
            
        Returns:
            Formatted string for the AI system
        """
        pass
    
    @abstractmethod
    def format_flows(self, 
                    flows: Dict[str, Any], 
                    query: Optional[str] = None) -> str:
        """
        Format network flow data.
        
        Args:
            flows: Flow analysis data
            query: Optional query to include with the flow data
            
        Returns:
            Formatted string for the AI system
        """
        pass
    
    @abstractmethod
    def format_security_context(self, 
                              security_data: Dict[str, Any], 
                              query: Optional[str] = None) -> str:
        """
        Format security analysis data.
        
        Args:
            security_data: Security analysis data
            query: Optional query to include with the security data
            
        Returns:
            Formatted string for the AI system
        """
        pass
    
    @abstractmethod
    def format_protocol_insights(self, 
                               insights: Dict[str, Any],
                               query: Optional[str] = None) -> str:
        """
        Format protocol insights data.
        
        Args:
            insights: Protocol insights data
            query: Optional query to include with the insights
            
        Returns:
            Formatted string for the AI system
        """
        pass
    
    def add_query(self, content: str, query: Optional[str]) -> str:
        """
        Add a query to the formatted content.
        
        Args:
            content: Formatted content
            query: Query to add
            
        Returns:
            Content with the query added
        """
        if not query:
            return content
            
        return f"{content}\n\n{query}"
    
    def format_packet_samples(self,
                             packets: List[Dict[str, Any]], 
                             max_packets: int = 5,
                             include_details: bool = True) -> str:
        """
        Format a sample of packets for display.
        
        Args:
            packets: List of packet dictionaries
            max_packets: Maximum number of packets to include
            include_details: Whether to include packet details
            
        Returns:
            Formatted packet samples
        """
        if not packets:
            return "No packets available."
            
        # Default base implementation - subclasses should override for better formatting
        formatted = "Packet Samples:\n\n"
        
        for i, packet in enumerate(packets[:max_packets]):
            if i > 0:
                formatted += "\n" + "-" * 40 + "\n\n"
                
            formatted += f"Packet {i+1}:\n"
            formatted += f"  Time: {packet.get('timestamp', 'N/A')}\n"
            formatted += f"  Length: {packet.get('length', 'N/A')} bytes\n"
            
            # Basic IP info
            if 'ip' in packet:
                ip = packet['ip']
                formatted += f"  Source IP: {ip.get('src', 'N/A')}\n"
                formatted += f"  Destination IP: {ip.get('dst', 'N/A')}\n"
            
            # Transport layer info
            if 'tcp' in packet:
                tcp = packet['tcp']
                formatted += f"  Protocol: TCP\n"
                formatted += f"  Source Port: {tcp.get('srcport', 'N/A')}\n"
                formatted += f"  Destination Port: {tcp.get('dstport', 'N/A')}\n"
            elif 'udp' in packet:
                udp = packet['udp']
                formatted += f"  Protocol: UDP\n"
                formatted += f"  Source Port: {udp.get('srcport', 'N/A')}\n"
                formatted += f"  Destination Port: {udp.get('dstport', 'N/A')}\n"
            
            # Include application layer details if requested
            if include_details:
                formatted += "\n  Application Layer:\n"
                for layer_name, layer_data in packet.items():
                    if layer_name not in ('ip', 'tcp', 'udp', 'frame', 'eth', 'timestamp', 'length', 'layers'):
                        formatted += f"    {layer_name.upper()}:\n"
                        for field, value in layer_data.items():
                            # Skip binary data or large fields
                            if isinstance(value, str) and len(value) > 100:
                                value = value[:100] + "... [truncated]"
                            formatted += f"      {field}: {value}\n"
        
        # Indicate if more packets are available
        if len(packets) > max_packets:
            formatted += f"\n... and {len(packets) - max_packets} more packets"
            
        return formatted
