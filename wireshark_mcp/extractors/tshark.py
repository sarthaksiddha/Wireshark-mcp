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
            
    def _process_packets(self, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Process and clean up packet data from tshark.
        
        Args:
            packets: Raw packet data from tshark
            
        Returns:
            Processed packet data
        """
        processed = []
        
        for packet in packets:
            # Extract timestamp
            timestamp = None
            if "_source" in packet and "timestamp" in packet["_source"]:
                timestamp = packet["_source"]["timestamp"]
            
            # Extract layers
            layers = {}
            if "_source" in packet and "layers" in packet["_source"]:
                raw_layers = packet["_source"]["layers"]
                
                # Process each layer
                for layer_name, layer_data in raw_layers.items():
                    if layer_name == "frame":
                        # Get basic frame information
                        frame_number = layer_data.get("frame.number", ["0"])[0]
                        frame_len = layer_data.get("frame.len", ["0"])[0]
                        
                        layers["frame"] = {
                            "number": frame_number,
                            "length": frame_len,
                            "protocols": layer_data.get("frame.protocols", [""])[0],
                        }
                    elif layer_name == "eth":
                        # Ethernet layer
                        layers["eth"] = {
                            "src": layer_data.get("eth.src", [""])[0],
                            "dst": layer_data.get("eth.dst", [""])[0],
                            "type": layer_data.get("eth.type", [""])[0],
                        }
                    elif layer_name == "ip":
                        # IP layer
                        layers["ip"] = {
                            "src": layer_data.get("ip.src", [""])[0],
                            "dst": layer_data.get("ip.dst", [""])[0],
                            "version": layer_data.get("ip.version", [""])[0],
                            "ttl": layer_data.get("ip.ttl", [""])[0],
                            "protocol": layer_data.get("ip.proto", [""])[0],
                        }
                    elif layer_name == "tcp":
                        # TCP layer
                        flags = {}
                        for flag_name in ["syn", "ack", "fin", "rst", "psh", "urg"]:
                            flag_key = f"tcp.flags.{flag_name}"
                            if flag_key in layer_data:
                                flags[flag_name] = layer_data[flag_key][0]
                        
                        layers["tcp"] = {
                            "srcport": layer_data.get("tcp.srcport", [""])[0],
                            "dstport": layer_data.get("tcp.dstport", [""])[0],
                            "seq": layer_data.get("tcp.seq", [""])[0],
                            "ack": layer_data.get("tcp.ack", [""])[0],
                            "flags": flags,
                        }
                    elif layer_name == "udp":
                        # UDP layer
                        layers["udp"] = {
                            "srcport": layer_data.get("udp.srcport", [""])[0],
                            "dstport": layer_data.get("udp.dstport", [""])[0],
                            "length": layer_data.get("udp.length", [""])[0],
                        }
                    elif layer_name == "http":
                        # HTTP layer - special handling for request/response
                        http_data = {}
                        
                        # Check if this is a request or response
                        if "http.request" in layer_data:
                            http_data["type"] = "request"
                            http_data["method"] = layer_data.get("http.request.method", [""])[0]
                            http_data["uri"] = layer_data.get("http.request.uri", [""])[0]
                            http_data["version"] = layer_data.get("http.request.version", [""])[0]
                        elif "http.response" in layer_data:
                            http_data["type"] = "response"
                            http_data["code"] = layer_data.get("http.response.code", [""])[0]
                            http_data["phrase"] = layer_data.get("http.response.phrase", [""])[0]
                        
                        # Extract headers
                        headers = {}
                        for key, value in layer_data.items():
                            if key.startswith("http.") and len(value) > 0:
                                # Clean up header names
                                header_name = key.replace("http.", "")
                                if header_name not in ["request", "response", "request.method", 
                                                      "request.uri", "request.version", 
                                                      "response.code", "response.phrase"]:
                                    headers[header_name] = value[0]
                        
                        http_data["headers"] = headers
                        layers["http"] = http_data
                    else:
                        # Generic layer handling for other protocols
                        # Just store basic info
                        layers[layer_name] = {
                            "protocol": layer_name.upper()
                        }
                        
                        # Add some key layer data without overloading
                        layer_fields = {}
                        for key, value in layer_data.items():
                            if len(value) > 0 and not key.startswith("_"):
                                # Take just the first value and limit total fields
                                if len(layer_fields) < 10:  # Limit fields per layer
                                    layer_fields[key] = value[0]
                        
                        layers[layer_name].update(layer_fields)
            
            # Build final packet structure
            processed_packet = {
                "timestamp": timestamp,
                "length": int(layers.get("frame", {}).get("length", 0)),
                "layers": [],
            }
            
            # Add layer data to the packet
            for layer_name, layer_data in layers.items():
                processed_packet[layer_name] = layer_data
                
                # Also add to layers array for consistent access
                processed_packet["layers"].append({
                    "name": layer_name,
                    "protocol": layer_name.upper(),
                    "data": layer_data
                })
            
            processed.append(processed_packet)
        
        return processed
