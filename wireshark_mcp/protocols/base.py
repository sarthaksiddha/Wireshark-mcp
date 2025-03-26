from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional

class BaseProtocolAnalyzer(ABC):
    """
    Abstract base class for protocol-specific analyzers.
    Each protocol should implement this interface.
    """
    
    # Protocol name - must be overridden in subclasses
    protocol_name = ""
    
    @abstractmethod
    def analyze(self, capture_file: str, **kwargs) -> Dict[str, Any]:
        """
        Analyze a capture file for data related to this protocol.
        
        Args:
            capture_file: Path to the capture file
            **kwargs: Protocol-specific options
            
        Returns:
            Analysis results as a dictionary
        """
        pass
    
    @abstractmethod
    def extract_features(self, packets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Extract protocol-specific features from a list of packets.
        
        Args:
            packets: List of packet dictionaries
            
        Returns:
            Extracted features
        """
        pass
    
    @abstractmethod
    def generate_context(self, features: Dict[str, Any], detail_level: int = 2) -> Dict[str, Any]:
        """
        Convert extracted features into a Claude-friendly context.
        
        Args:
            features: Protocol features
            detail_level: How much detail to include (1-3)
            
        Returns:
            Context dictionary suitable for Claude
        """
        pass
    
    def summarize(self, context: Dict[str, Any], max_tokens: int = 1000) -> str:
        """
        Generate a natural language summary of the context.
        
        Args:
            context: Protocol context
            max_tokens: Approximate token limit for the summary
            
        Returns:
            Summary text
        """
        # Default implementation - should be overridden for better results
        summary_parts = []
        
        # Add protocol identifier
        summary_parts.append(f"Protocol: {self.protocol_name.upper()}")
        
        # Add packet count if available
        if "packet_count" in context:
            summary_parts.append(f"Packets: {context['packet_count']}")
            
        # Add conversation count if available
        if "conversations" in context:
            summary_parts.append(f"Conversations: {len(context['conversations'])}")
            
        # Add any statistics if available
        if "statistics" in context:
            stats = context["statistics"]
            for key, value in stats.items():
                summary_parts.append(f"{key.replace('_', ' ').title()}: {value}")
                
        # Return the combined summary
        return "\n".join(summary_parts)
    
    def get_display_filter(self) -> str:
        """
        Get the display filter string for this protocol.
        
        Returns:
            Display filter expression
        """
        return self.protocol_name.lower()
    
    @classmethod
    def register(cls):
        """
        Register this analyzer with the protocol registry.
        
        Returns:
            The analyzer instance
        """
        from . import register_protocol_analyzer
        analyzer = cls()
        register_protocol_analyzer(analyzer)
        return analyzer