"""
Base extractor interface for Wireshark MCP.

This module provides the base class for all packet extractors,
defining the common interface that all extractors must implement.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional

class BaseExtractor(ABC):
    """
    Base class for all packet extractors.
    
    This abstract class defines the common interface that all
    packet extractors must implement to ensure consistent
    behavior across the system.
    """
    
    def __init__(self):
        """Initialize the base extractor."""
        pass
    
    @abstractmethod
    def extract_packets(self, 
                       capture_file: str, 
                       filter_str: Optional[str] = None,
                       max_packets: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Extract packets from a capture file.
        
        Args:
            capture_file: Path to the capture file
            filter_str: Optional filter string to apply
            max_packets: Maximum number of packets to extract
            
        Returns:
            List of packet dictionaries
        """
        pass
    
    @abstractmethod
    def _process_packets(self, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Process raw packet data into a standardized format.
        
        Args:
            packets: Raw packet data
            
        Returns:
            Processed packet data
        """
        pass
