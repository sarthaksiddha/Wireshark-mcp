"""
Base protocol analyzer class that defines the interface for all protocol analyzers.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional


class BaseProtocolAnalyzer(ABC):
    """
    Abstract base class for protocol analyzers.
    
    Protocol analyzers extract features from packet data and generate
    context for AI models. Each specific protocol (HTTP, DNS, etc.)
    should have its own analyzer that inherits from this base class.
    """
    
    # Protocol name should be overridden by subclasses
    protocol_name = "UNKNOWN"
    
    @abstractmethod
    def extract_features(self, 
                        packets: List[Dict[str, Any]], 
                        **kwargs) -> Dict[str, Any]:
        """
        Extract protocol-specific features from packet data.
        
        Args:
            packets: List of packet dictionaries
            **kwargs: Additional extraction parameters
            
        Returns:
            Dictionary of extracted features
        """
        pass
    
    @abstractmethod
    def generate_context(self, 
                        features: Dict[str, Any], 
                        detail_level: int = 2,
                        **kwargs) -> Dict[str, Any]:
        """
        Generate AI-friendly context from the extracted features.
        
        Args:
            features: Dictionary of extracted features
            detail_level: Level of detail (1-3, where 3 is most detailed)
            **kwargs: Additional context parameters
            
        Returns:
            Dictionary with formatted context
        """
        pass
    
    def summarize(self, 
                features: Dict[str, Any], 
                max_length: int = 1000) -> str:
        """
        Generate a text summary of the protocol data.
        
        Args:
            features: Dictionary of extracted features
            max_length: Maximum length of the summary in characters
            
        Returns:
            Text summary
        """
        # Default implementation - should be overridden for better summaries
        context = self.generate_context(features, detail_level=1)
        summary = f"{self.protocol_name} Summary:\n"
        
        # Add key statistics
        if "statistics" in context:
            stats = context["statistics"]
            summary += f"- {stats.get('total_messages', 0)} messages processed\n"
            summary += f"- {stats.get('total_bytes', 0)} bytes transferred\n"
        
        # Add key findings if available
        if "findings" in context:
            summary += "- Key findings:\n"
            for finding in context["findings"][:3]:  # Top 3 findings
                summary += f"  - {finding}\n"
        
        # Truncate if needed
        if len(summary) > max_length:
            summary = summary[:max_length-3] + "..."
            
        return summary
    
    def extract_insights(self, 
                        packets: List[Dict[str, Any]], 
                        **kwargs) -> Dict[str, Any]:
        """
        Extract deeper insights from protocol data.
        
        This method allows for specialized analysis beyond basic feature extraction.
        Subclasses should override this for protocol-specific insights.
        
        Args:
            packets: List of packet dictionaries
            **kwargs: Insight extraction parameters
            
        Returns:
            Dictionary of protocol insights
        """
        # Base implementation - should be overridden by subclasses
        return {
            "protocol": self.protocol_name,
            "message": "No specialized insights available for this protocol"
        }
    
    def _filter_packets(self, 
                      packets: List[Dict[str, Any]], 
                      protocol: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Filter packets for a specific protocol.
        
        Args:
            packets: List of packet dictionaries
            protocol: Protocol name to filter for (defaults to self.protocol_name)
            
        Returns:
            Filtered list of packets
        """
        proto = protocol or self.protocol_name.lower()
        
        return [
            packet for packet in packets
            if any(layer.get('protocol', '').lower() == proto.lower() 
                  for layer in packet.get('layers', []))
        ]
    
    def _extract_conversations(self, 
                              packets: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Group packets into conversations.
        
        A conversation is typically identified by the 5-tuple:
        (src_ip, dst_ip, src_port, dst_port, protocol)
        
        Args:
            packets: List of packet dictionaries
            
        Returns:
            Dictionary of conversation IDs to packet lists
        """
        conversations = {}
        
        for packet in packets:
            # Extract IP information
            ip_layer = packet.get('ip', {})
            src_ip = ip_layer.get('src', '')
            dst_ip = ip_layer.get('dst', '')
            
            # Extract port information from TCP or UDP
            src_port = None
            dst_port = None
            
            if 'tcp' in packet:
                tcp_layer = packet['tcp']
                src_port = tcp_layer.get('srcport', '')
                dst_port = tcp_layer.get('dstport', '')
                transport = 'tcp'
            elif 'udp' in packet:
                udp_layer = packet['udp']
                src_port = udp_layer.get('srcport', '')
                dst_port = udp_layer.get('dstport', '')
                transport = 'udp'
            else:
                transport = 'other'
            
            # Create conversation ID
            if None not in (src_ip, dst_ip, src_port, dst_port):
                # Create bidirectional conversation ID (order IPs and ports consistently)
                if f"{src_ip}:{src_port}" < f"{dst_ip}:{dst_port}":
                    conv_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{transport}"
                else:
                    conv_id = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{transport}"
            else:
                # Fallback for packets without complete information
                conv_id = f"{src_ip}-{dst_ip}-{transport}"
            
            # Add to conversations
            if conv_id not in conversations:
                conversations[conv_id] = []
            
            conversations[conv_id].append(packet)
            
        return conversations
