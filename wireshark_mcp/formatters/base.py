"""
Base formatter abstract class.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional


class BaseFormatter(ABC):
    """
    Abstract base class for formatters.
    
    Formatters convert extracted packet data and analysis contexts
    into formats suitable for specific AI models.
    """
    
    @abstractmethod
    def format_context(self,
                      context: Dict[str, Any],
                      query: Optional[str] = None,
                      max_tokens: Optional[int] = None) -> str:
        """
        Format a general context for the AI model.
        
        Args:
            context: Context dictionary from WiresharkMCP.generate_context()
            query: Optional query to include with the context
            max_tokens: Optional maximum token limit
            
        Returns:
            Formatted context string
        """
        pass
    
    @abstractmethod
    def format_flows(self,
                    flows: Dict[str, Any],
                    query: Optional[str] = None,
                    max_tokens: Optional[int] = None) -> str:
        """
        Format flow analysis data for the AI model.
        
        Args:
            flows: Flow data from WiresharkMCP.extract_flows()
            query: Optional query to include with the context
            max_tokens: Optional maximum token limit
            
        Returns:
            Formatted flow analysis string
        """
        pass
    
    @abstractmethod
    def format_security_context(self,
                              security_context: Dict[str, Any],
                              query: Optional[str] = None,
                              max_tokens: Optional[int] = None) -> str:
        """
        Format security analysis data for the AI model.
        
        Args:
            security_context: Security data from WiresharkMCP.security_analysis()
            query: Optional query to include with the context
            max_tokens: Optional maximum token limit
            
        Returns:
            Formatted security analysis string
        """
        pass
    
    @abstractmethod
    def format_protocol_insights(self,
                               protocol_insights: Dict[str, Any],
                               query: Optional[str] = None,
                               max_tokens: Optional[int] = None) -> str:
        """
        Format protocol-specific insights for the AI model.
        
        Args:
            protocol_insights: Protocol data from WiresharkMCP.protocol_insights()
            query: Optional query to include with the context
            max_tokens: Optional maximum token limit
            
        Returns:
            Formatted protocol insights string
        """
        pass
    
    @abstractmethod
    def format_protocol_analysis(self,
                               protocol_data: Dict[str, Any],
                               query: Optional[str] = None,
                               max_tokens: Optional[int] = None) -> str:
        """
        Format protocol analysis data for the AI model.
        
        Args:
            protocol_data: Protocol data from WiresharkMCP.extract_protocol()
            query: Optional query to include with the context
            max_tokens: Optional maximum token limit
            
        Returns:
            Formatted protocol analysis string
        """
        pass
    
    def _estimate_tokens(self, text: str) -> int:
        """
        Estimate the number of tokens in a string.
        
        This is a very rough approximation. Different models have
        different tokenization schemes.
        
        Args:
            text: Input text
            
        Returns:
            Estimated token count
        """
        # Simple estimation: ~4 characters per token on average
        return len(text) // 4
    
    def _truncate_for_tokens(self, text: str, max_tokens: int) -> str:
        """
        Truncate text to fit within a token limit.
        
        Args:
            text: Input text
            max_tokens: Maximum token limit
            
        Returns:
            Truncated text
        """
        if not max_tokens:
            return text
            
        # Estimate characters per token
        chars_per_token = 4
        max_chars = max_tokens * chars_per_token
        
        if len(text) <= max_chars:
            return text
            
        # Simple truncation with ellipsis
        return text[:max_chars-3] + "..."
