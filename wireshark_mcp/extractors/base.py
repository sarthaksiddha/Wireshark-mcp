from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional

from ..protocols import Protocol
from ..filter import Filter

class BaseExtractor(ABC):
    """
    Abstract base class for packet extractors.
    Defines the interface that all extractors must implement.
    """
    
    def __init__(self, capture_file: Optional[str] = None):
        """
        Initialize with an optional capture file path.
        
        Args:
            capture_file: Path to the packet capture file
        """
        self.capture_file = capture_file
    
    def set_capture_file(self, capture_file: str):
        """
        Set or change the capture file path.
        
        Args:
            capture_file: New capture file path
        """
        self.capture_file = capture_file
    
    @abstractmethod
    def extract_packets(self, max_packets: int = 1000, 
                      protocols: Optional[List[Protocol]] = None) -> List[Dict[str, Any]]:
        """
        Extract packets from the capture file.
        
        Args:
            max_packets: Maximum number of packets to extract
            protocols: Optional list of protocols to filter by
            
        Returns:
            List of packet dictionaries
        """
        pass
    
    @abstractmethod
    def generate_statistics(self) -> Dict[str, Any]:
        """
        Generate statistical information about the capture.
        
        Returns:
            Dictionary of statistics
        """
        pass
    
    @abstractmethod
    def extract_flows(self, filter_expr: Optional[Filter] = None,
                    include_details: bool = True,
                    max_flows: int = 10) -> Dict[str, Any]:
        """
        Extract conversation flows from the capture.
        
        Args:
            filter_expr: Optional filter to apply
            include_details: Whether to include packet details
            max_flows: Maximum number of flows to extract
            
        Returns:
            Dictionary of flow information
        """
        pass
    
    @abstractmethod
    def extract_protocol(self, protocol: Protocol,
                       filter_expr: Optional[Filter] = None,
                       **kwargs) -> Dict[str, Any]:
        """
        Extract data for a specific protocol.
        
        Args:
            protocol: The protocol to extract
            filter_expr: Optional filter to apply
            **kwargs: Protocol-specific options
            
        Returns:
            Protocol-specific data
        """
        pass
    
    @abstractmethod
    def get_protocol_analyzer(self, protocol: Protocol):
        """
        Get a protocol-specific analyzer.
        
        Args:
            protocol: The protocol to get an analyzer for
            
        Returns:
            Protocol analyzer or None if not available
        """
        pass