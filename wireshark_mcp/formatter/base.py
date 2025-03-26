from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

class BaseFormatter(ABC):
    """
    Abstract base class for formatters that prepare Wireshark data
    for AI models.
    """
    
    @abstractmethod
    def format_context(self, context: Dict[str, Any], query: Optional[str] = None) -> str:
        """
        Format a context dictionary for an AI model.
        
        Args:
            context: Context dictionary from a protocol analyzer
            query: Optional query to include
            
        Returns:
            Formatted string for the AI model
        """
        pass
    
    @abstractmethod
    def format_flows(self, flows: Dict[str, Any], query: Optional[str] = None) -> str:
        """
        Format flow information for an AI model.
        
        Args:
            flows: Flow dictionary
            query: Optional query to include
            
        Returns:
            Formatted string for the AI model
        """
        pass
    
    @abstractmethod
    def format_security_context(self, security_context: Dict[str, Any], 
                              query: Optional[str] = None) -> str:
        """
        Format security analysis context for an AI model.
        
        Args:
            security_context: Security analysis dictionary
            query: Optional query to include
            
        Returns:
            Formatted string for the AI model
        """
        pass
    
    @abstractmethod
    def format_protocol_insights(self, insights: Dict[str, Any], 
                               query: Optional[str] = None) -> str:
        """
        Format protocol-specific insights for an AI model.
        
        Args:
            insights: Protocol insights dictionary
            query: Optional query to include
            
        Returns:
            Formatted string for the AI model
        """
        pass
    
    @abstractmethod
    def format_protocol_analysis(self, analysis: Dict[str, Any], 
                               query: Optional[str] = None) -> str:
        """
        Format protocol analysis for an AI model.
        
        Args:
            analysis: Protocol analysis dictionary
            query: Optional query to include
            
        Returns:
            Formatted string for the AI model
        """
        pass