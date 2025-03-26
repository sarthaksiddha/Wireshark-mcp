"""
Base extractor abstract class.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional


class BaseExtractor(ABC):
    """
    Abstract base class for packet extractors.
    
    Packet extractors are responsible for extracting packet data from
    packet capture files in a format that can be processed by protocol analyzers.
    """
    
    @abstractmethod
    def extract_packets(self, 
                       pcap_path: str, 
                       filter_str: Optional[str] = None,
                       max_packets: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Extract packets from a pcap file.
        
        Args:
            pcap_path: Path to the pcap file
            filter_str: Optional Wireshark display filter string
            max_packets: Maximum number of packets to extract
            
        Returns:
            List of packet dictionaries
        """
        pass
    
    @abstractmethod
    def extract_packet_count(self, 
                           pcap_path: str, 
                           filter_str: Optional[str] = None) -> int:
        """
        Count the number of packets in a pcap file.
        
        Args:
            pcap_path: Path to the pcap file
            filter_str: Optional Wireshark display filter string
            
        Returns:
            Number of matching packets
        """
        pass
    
    @abstractmethod
    def extract_protocols(self, pcap_path: str) -> Dict[str, int]:
        """
        Extract protocol distribution from a pcap file.
        
        Args:
            pcap_path: Path to the pcap file
            
        Returns:
            Dictionary mapping protocol names to packet counts
        """
        pass
    
    @abstractmethod
    def extract_conversations(self, 
                            pcap_path: str,
                            protocol: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
        """
        Extract conversation statistics from a pcap file.
        
        Args:
            pcap_path: Path to the pcap file
            protocol: Optional protocol filter
            
        Returns:
            Dictionary of conversation statistics
        """
        pass
