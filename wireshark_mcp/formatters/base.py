"""
Base formatter interface for Wireshark MCP.

This module provides the base class for all formatters in the system,
defining the common interface that all AI-specific formatters must implement.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Union, List

class BaseFormatter(ABC):
    """
    Base class for all formatters.
    
    This abstract class defines the common interface that all
    AI-specific formatters must implement to ensure consistent
    behavior across the system.
    """
    
    def __init__(self):
        """Initialize the base formatter."""
        pass
    
    @abstractmethod
    def format_context(self, 
                      context: Dict[str, Any], 
                      query: Optional[str] = None) -> str:
        """
        Format a general packet context.
        
        Args:
            context: Dictionary containing context data
            query: Optional query to append to the context
            
        Returns:
            String containing formatted context
        """
        pass
    
    @abstractmethod
    def _format_protocol_context(self, 
                               protocol_context: Dict[str, Any], 
                               protocol_name: str) -> str:
        """
        Format a protocol-specific context.
        
        Args:
            protocol_context: Dictionary containing protocol data
            protocol_name: Name of the protocol
            
        Returns:
            String containing formatted protocol context
        """
        pass
    
    @abstractmethod
    def _format_packet_sample(self, 
                            packet: Dict[str, Any], 
                            index: int) -> str:
        """
        Format a packet for display in the context.
        
        Args:
            packet: Dictionary containing packet data
            index: Packet index for reference
            
        Returns:
            String containing formatted packet
        """
        pass
    
    @abstractmethod
    def _truncate_context(self, context: str) -> str:
        """
        Truncate a context string to fit within the allowed length.
        
        Args:
            context: Context string to truncate
            
        Returns:
            Truncated context string
        """
        pass
    
    def format_protocol_analysis(self, 
                               protocol_context: Dict[str, Any],
                               query: Optional[str] = None) -> str:
        """
        Format protocol-specific analysis.
        
        Args:
            protocol_context: Dictionary containing protocol analysis
            query: Optional query to append to the context
            
        Returns:
            String containing formatted protocol analysis
        """
        # Default implementation - should be overridden by subclasses
        raise NotImplementedError("Subclasses must implement format_protocol_analysis")
    
    def format_flows(self,
                   flows: Dict[str, Any],
                   query: Optional[str] = None) -> str:
        """
        Format flow analysis.
        
        Args:
            flows: Dictionary containing flow analysis
            query: Optional query to append to the context
            
        Returns:
            String containing formatted flow analysis
        """
        # Default implementation - should be overridden by subclasses
        raise NotImplementedError("Subclasses must implement format_flows")
    
    def format_security_context(self,
                              security_context: Dict[str, Any],
                              query: Optional[str] = None) -> str:
        """
        Format security analysis.
        
        Args:
            security_context: Dictionary containing security analysis
            query: Optional query to append to the context
            
        Returns:
            String containing formatted security analysis
        """
        # Default implementation - should be overridden by subclasses
        raise NotImplementedError("Subclasses must implement format_security_context")
    
    def format_protocol_insights(self,
                              protocol_insights: Dict[str, Any],
                              query: Optional[str] = None) -> str:
        """
        Format protocol-specific insights.
        
        Args:
            protocol_insights: Dictionary containing protocol insights
            query: Optional query to append to the context
            
        Returns:
            String containing formatted protocol insights
        """
        # Default implementation - should be overridden by subclasses
        raise NotImplementedError("Subclasses must implement format_protocol_insights")
