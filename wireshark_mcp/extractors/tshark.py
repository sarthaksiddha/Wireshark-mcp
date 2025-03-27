"""
tshark extractor for Wireshark MCP.

This module provides packet extraction using tshark, 
the command-line version of Wireshark.
"""

import subprocess
import json
import os
import tempfile
import logging
from typing import List, Dict, Any, Optional, Union

from .base import BaseExtractor

logger = logging.getLogger(__name__)

class TsharkExtractor(BaseExtractor):
    """
    Packet extractor using tshark.
    
    This extractor uses tshark (command-line Wireshark) to extract
    packet data from capture files in various formats.
    """
    
    def __init__(self, tshark_path: str):
        """
        Initialize the tshark extractor.
        
        Args:
            tshark_path: Path to the tshark executable
            
        Raises:
            ValueError: If tshark executable is not found or not executable
        """
        super().__init__()
        self.tshark_path = tshark_path
        
        # Verify tshark is available
        if not os.path.exists(tshark_path) and tshark_path != "tshark":
            raise ValueError(f"tshark executable not found at {tshark_path}")
        
        # Test that tshark can be executed
        try:
            result = subprocess.run(
                [tshark_path, "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
                text=True
            )
            logger.debug(f"tshark version: {result.stdout.splitlines()[0]}")
        except (subprocess.SubprocessError, OSError) as e:
            raise ValueError(f"Error executing tshark: {e}")
    
    def extract_packets(self, 
                       capture_file: str, 
                       filter_str: Optional[str] = None,
                       max_packets: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Extract packets from a capture file using tshark.
        
        Args:
            capture_file: Path to the capture file
            filter_str: Optional Wireshark display filter
            max_packets: Maximum number of packets to extract
            
        Returns:
            List of packet dictionaries
            
        Raises:
            ValueError: If tshark execution fails
        """
        if not os.path.exists(capture_file):
            raise ValueError(f"Capture file not found: {capture_file}")
        
        # Build tshark command
        command = [
            self.tshark_path,
            "-r", capture_file,  # Read from file
            "-T", "json",        # Output as JSON
            "-x",                # Include hex dump
        ]
        
        # Add packet limit if specified
        if max_packets is not None:
            command.extend(["-c", str(max_packets)])
        
        # Add filter if specified
        if filter_str:
            command.extend(["-Y", filter_str])
        
        # Run tshark
        try:
            logger.debug(f"Running tshark command: {' '.join(command)}")
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
                text=True
            )
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr.strip() if e.stderr else "Unknown error"
            raise ValueError(f"tshark execution failed: {error_msg}")
        
        # Parse JSON output
        try:
            packets_json = result.stdout
            if not packets_json:
                return []
                
            packets = json.loads(packets_json)
            
            # Handle different tshark JSON formats
            if isinstance(packets, dict) and "packets" in packets:
                # Newer tshark versions wrap in a "packets" array
                packets = packets["packets"]
            
            # Process and clean up the packet data
            processed_packets = self._process_packets(packets)
            
            return processed_packets
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse tshark JSON output: {e}")
            logger.debug(f"tshark stdout: {result.stdout[:500]}...")
            logger.debug(f"tshark stderr: {result.stderr}")
            raise ValueError(f"Failed to parse tshark output: {e}")
