"""
TShark-based packet extractor implementation.
"""

import os
import subprocess
import json
import tempfile
import logging
from typing import List, Dict, Any, Optional

from .base import BaseExtractor


logger = logging.getLogger(__name__)


class TsharkExtractor(BaseExtractor):
    """
    Packet extractor based on tshark (Wireshark command-line interface).
    
    This class uses tshark to extract packet data from pcap files and
    convert it to JSON format for further processing.
    """
    
    def __init__(self, tshark_path: str = "tshark"):
        """
        Initialize the TShark extractor.
        
        Args:
            tshark_path: Path to the tshark executable
            
        Raises:
            ValueError: If tshark is not found
        """
        self.tshark_path = tshark_path
        self._validate_tshark()
    
    def _validate_tshark(self) -> None:
        """
        Validate that tshark is available and executable.
        
        Raises:
            ValueError: If tshark is not found
        """
        try:
            result = subprocess.run(
                [self.tshark_path, "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                text=True
            )
            
            if result.returncode != 0:
                raise ValueError(f"tshark execution failed: {result.stderr}")
                
            logger.debug(f"tshark version: {result.stdout.splitlines()[0]}")
            
        except (FileNotFoundError, subprocess.SubprocessError) as e:
            raise ValueError(f"tshark not found at {self.tshark_path}: {e}")
    
    def extract_packets(self, 
                       pcap_path: str, 
                       filter_str: Optional[str] = None,
                       max_packets: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Extract packets from a pcap file using tshark.
        
        Args:
            pcap_path: Path to the pcap file
            filter_str: Optional Wireshark display filter string
            max_packets: Maximum number of packets to extract
            
        Returns:
            List of packet dictionaries
            
        Raises:
            FileNotFoundError: If the pcap file doesn't exist
            ValueError: If tshark execution fails
        """
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"Packet capture file not found: {pcap_path}")
        
        # Build tshark command
        cmd = [
            self.tshark_path,
            "-r", pcap_path,
            "-T", "json"
        ]
        
        # Add packet limit if specified
        if max_packets is not None:
            cmd.extend(["-c", str(max_packets)])
        
        # Add display filter if specified
        if filter_str:
            cmd.extend(["-Y", filter_str])
        
        # Execute tshark
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                text=True
            )
            
            if result.returncode != 0:
                raise ValueError(f"tshark execution failed: {result.stderr}")
                
            # Parse JSON output
            if not result.stdout.strip():
                return []
                
            packet_data = json.loads(result.stdout)
            
            # Extract and reorganize packet data
            return self._process_packets(packet_data)
            
        except subprocess.SubprocessError as e:
            raise ValueError(f"tshark execution failed: {e}")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse tshark output: {e}")
            logger.debug(f"tshark output: {result.stdout[:1000]}...")
            raise ValueError(f"Failed to parse tshark output: {e}")
    
    def extract_packet_count(self, 
                           pcap_path: str, 
                           filter_str: Optional[str] = None) -> int:
        """
        Count the number of packets in a pcap file using tshark.
        
        Args:
            pcap_path: Path to the pcap file
            filter_str: Optional Wireshark display filter string
            
        Returns:
            Number of matching packets
        """
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"Packet capture file not found: {pcap_path}")
        
        # Build tshark command
        cmd = [
            self.tshark_path,
            "-r", pcap_path,
            "-T", "fields",
            "-e", "frame.number"
        ]
        
        # Add display filter if specified
        if filter_str:
            cmd.extend(["-Y", filter_str])
        
        # Execute tshark
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                text=True
            )
            
            if result.returncode != 0:
                raise ValueError(f"tshark execution failed: {result.stderr}")
                
            # Count lines in output
            return len(result.stdout.strip().split("\n")) if result.stdout.strip() else 0
            
        except subprocess.SubprocessError as e:
            raise ValueError(f"tshark execution failed: {e}")
    
    def extract_protocols(self, pcap_path: str) -> Dict[str, int]:
        """
        Extract protocol distribution from a pcap file using tshark.
        
        Args:
            pcap_path: Path to the pcap file
            
        Returns:
            Dictionary mapping protocol names to packet counts
        """
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"Packet capture file not found: {pcap_path}")
        
        # Build tshark command to get protocol statistics
        cmd = [
            self.tshark_path,
            "-r", pcap_path,
            "-q",
            "-z", "io,phs"
        ]
        
        # Execute tshark
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                text=True
            )
            
            if result.returncode != 0:
                raise ValueError(f"tshark execution failed: {result.stderr}")
                
            # Parse protocol statistics output
            protocols = {}
            lines = result.stdout.strip().split("\n")
            parsing = False
            
            for line in lines:
                line = line.strip()
                
                if "Protocol Hierarchy Statistics" in line:
                    parsing = True
                    continue
                
                if parsing and line and not line.startswith("="):
                    parts = line.split()
                    if len(parts) >= 6:
                        protocol = parts[5]
                        count = int(parts[2])
                        protocols[protocol] = count
            
            return protocols
            
        except subprocess.SubprocessError as e:
            raise ValueError(f"tshark execution failed: {e}")
    
    def extract_conversations(self, 
                            pcap_path: str,
                            protocol: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
        """
        Extract conversation statistics from a pcap file using tshark.
        
        Args:
            pcap_path: Path to the pcap file
            protocol: Optional protocol filter (e.g., "tcp", "udp")
            
        Returns:
            Dictionary of conversation statistics
        """
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"Packet capture file not found: {pcap_path}")
        
        # Determine conversation type
        conv_type = protocol.lower() if protocol else "ip"
        
        # Build tshark command for conversation statistics
        cmd = [
            self.tshark_path,
            "-r", pcap_path,
            "-q",
            "-z", f"conv,{conv_type}"
        ]
        
        # Execute tshark
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                text=True
            )
            
            if result.returncode != 0:
                raise ValueError(f"tshark execution failed: {result.stderr}")
                
            # Parse conversation statistics
            conversations = {}
            lines = result.stdout.strip().split("\n")
            parsing = False
            headers = []
            
            for line in lines:
                line = line.strip()
                
                if f"{conv_type.upper()} Conversations" in line:
                    parsing = True
                    continue
                
                if parsing:
                    if "=" in line:
                        # End of section
                        parsing = False
                    elif "Frames" in line and "Bytes" in line:
                        # Headers line
                        headers = line.split()
                    elif line and line[0].isdigit():
                        # Conversation data line
                        parts = line.split()
                        if len(parts) >= 9:  # Most conversation types have at least 9 fields
                            if conv_type == "ip" or conv_type == "ipv6":
                                conv_id = f"{parts[0]} <-> {parts[2]}"
                            else:  # tcp, udp, etc.
                                conv_id = f"{parts[0]}:{parts[1]} <-> {parts[2]}:{parts[3]}"
                                
                            conversations[conv_id] = {
                                "frames": int(parts[-5]),
                                "bytes": int(parts[-4]),
                                "start_time": None,  # Would need different tshark command to get this
                                "duration": None     # Would need different tshark command to get this
                            }
            
            return conversations
            
        except subprocess.SubprocessError as e:
            raise ValueError(f"tshark execution failed: {e}")
    
    def _process_packets(self, packet_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Process and organize tshark JSON output into a more usable structure.
        
        Args:
            packet_data: Raw packet data from tshark
            
        Returns:
            Processed packet list
        """
        processed_packets = []
        
        for packet in packet_data:
            processed_packet = self._process_single_packet(packet)
            processed_packets.append(processed_packet)
            
        return processed_packets
    
    def _process_single_packet(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a single packet from tshark JSON output.
        
        Args:
            packet: Raw packet data
            
        Returns:
            Processed packet dictionary
        """
        # Extract basic packet info
        source = packet.get("_source", {})
        layers = source.get("layers", {})
        
        processed_packet = {
            "frame_number": layers.get("frame", {}).get("frame.number", ["0"])[0],
            "timestamp": float(layers.get("frame", {}).get("frame.time_epoch", ["0"])[0]),
            "length": int(layers.get("frame", {}).get("frame.len", ["0"])[0]),
            "protocols": layers.get("frame", {}).get("frame.protocols", [""])[0].split(":"),
            "layers": []
        }
        
        # Extract Ethernet layer
        if "eth" in layers:
            eth_layer = {
                "protocol": "eth",
                "src": layers["eth"].get("eth.src", [""])[0],
                "dst": layers["eth"].get("eth.dst", [""])[0],
                "type": layers["eth"].get("eth.type", [""])[0]
            }
            processed_packet["eth"] = eth_layer
            processed_packet["layers"].append(eth_layer)
        
        # Extract IP layer
        if "ip" in layers:
            ip_layer = {
                "protocol": "ip",
                "version": layers["ip"].get("ip.version", [""])[0],
                "src": layers["ip"].get("ip.src", [""])[0],
                "dst": layers["ip"].get("ip.dst", [""])[0],
                "ttl": layers["ip"].get("ip.ttl", [""])[0],
                "protocol": layers["ip"].get("ip.proto", [""])[0]
            }
            processed_packet["ip"] = ip_layer
            processed_packet["layers"].append(ip_layer)
        
        # Extract IPv6 layer
        if "ipv6" in layers:
            ipv6_layer = {
                "protocol": "ipv6",
                "version": layers["ipv6"].get("ipv6.version", [""])[0],
                "src": layers["ipv6"].get("ipv6.src", [""])[0],
                "dst": layers["ipv6"].get("ipv6.dst", [""])[0],
                "next_header": layers["ipv6"].get("ipv6.nxt", [""])[0]
            }
            processed_packet["ipv6"] = ipv6_layer
            processed_packet["layers"].append(ipv6_layer)
        
        # Extract TCP layer
        if "tcp" in layers:
            tcp_layer = {
                "protocol": "tcp",
                "srcport": layers["tcp"].get("tcp.srcport", [""])[0],
                "dstport": layers["tcp"].get("tcp.dstport", [""])[0],
                "stream": layers["tcp"].get("tcp.stream", [""])[0],
                "seq": layers["tcp"].get("tcp.seq", [""])[0],
                "ack": layers["tcp"].get("tcp.ack", [""])[0],
                "flags": self._extract_tcp_flags(layers["tcp"])
            }
            processed_packet["tcp"] = tcp_layer
            processed_packet["layers"].append(tcp_layer)
        
        # Extract UDP layer
        if "udp" in layers:
            udp_layer = {
                "protocol": "udp",
                "srcport": layers["udp"].get("udp.srcport", [""])[0],
                "dstport": layers["udp"].get("udp.dstport", [""])[0],
                "stream": layers["udp"].get("udp.stream", [""])[0],
                "length": layers["udp"].get("udp.length", [""])[0]
            }
            processed_packet["udp"] = udp_layer
            processed_packet["layers"].append(udp_layer)
        
        # Extract HTTP layer
        if "http" in layers:
            http_layer = {
                "protocol": "http"
            }
            
            # Determine if this is a request or response
            if "http.request" in layers["http"]:
                http_layer["request"] = True
                http_layer["request_method"] = layers["http"].get("http.request.method", [""])[0]
                http_layer["request_uri"] = layers["http"].get("http.request.uri", [""])[0]
                http_layer["request_version"] = layers["http"].get("http.request.version", [""])[0]
                
                # Extract request headers
                http_layer["request_header"] = self._extract_http_headers(
                    layers["http"], "http.request.line")
                    
                # Extract request body if available
                if "http.file_data" in layers["http"]:
                    http_layer["request_body"] = layers["http"]["http.file_data"][0]
                
            elif "http.response" in layers["http"]:
                http_layer["response"] = True
                http_layer["response_code"] = layers["http"].get("http.response.code", [""])[0]
                http_layer["response_phrase"] = layers["http"].get("http.response.phrase", [""])[0]
                http_layer["response_version"] = layers["http"].get("http.response.version", [""])[0]
                
                # Extract response headers
                http_layer["response_header"] = self._extract_http_headers(
                    layers["http"], "http.response.line")
                    
                # Extract response body if available
                if "http.file_data" in layers["http"]:
                    http_layer["response_body"] = layers["http"]["http.file_data"][0]
            
            processed_packet["http"] = http_layer
            processed_packet["layers"].append(http_layer)
        
        # Extract DNS layer
        if "dns" in layers:
            dns_layer = {
                "protocol": "dns",
                "transaction_id": layers["dns"].get("dns.id", [""])[0],
                "flags": self._extract_dns_flags(layers["dns"]),
                "questions": int(layers["dns"].get("dns.count.queries", ["0"])[0]),
                "answers": int(layers["dns"].get("dns.count.answers", ["0"])[0])
            }
            
            # Extract queries
            if "dns.qry.name" in layers["dns"]:
                queries = []
                for i, name in enumerate(layers["dns"]["dns.qry.name"]):
                    query = {"name": name}
                    if "dns.qry.type" in layers["dns"] and i < len(layers["dns"]["dns.qry.type"]):
                        query["type"] = layers["dns"]["dns.qry.type"][i]
                    queries.append(query)
                dns_layer["queries"] = queries
            
            # Extract answers
            if "dns.resp.name" in layers["dns"]:
                answers = []
                for i, name in enumerate(layers["dns"]["dns.resp.name"]):
                    answer = {"name": name}
                    if "dns.resp.type" in layers["dns"] and i < len(layers["dns"]["dns.resp.type"]):
                        answer["type"] = layers["dns"]["dns.resp.type"][i]
                    if "dns.resp.ttl" in layers["dns"] and i < len(layers["dns"]["dns.resp.ttl"]):
                        answer["ttl"] = layers["dns"]["dns.resp.ttl"][i]
                    if "dns.a" in layers["dns"] and i < len(layers["dns"]["dns.a"]):
                        answer["address"] = layers["dns"]["dns.a"][i]
                    elif "dns.aaaa" in layers["dns"] and i < len(layers["dns"]["dns.aaaa"]):
                        answer["address"] = layers["dns"]["dns.aaaa"][i]
                    elif "dns.cname" in layers["dns"] and i < len(layers["dns"]["dns.cname"]):
                        answer["cname"] = layers["dns"]["dns.cname"][i]
                    answers.append(answer)
                dns_layer["answers"] = answers
            
            processed_packet["dns"] = dns_layer
            processed_packet["layers"].append(dns_layer)
        
        # Extract TLS layer
        if "tls" in layers:
            tls_layer = {
                "protocol": "tls",
                "record_type": layers["tls"].get("tls.record.content_type", [""])[0]
            }
            
            # Extract handshake information
            if "tls.handshake" in layers["tls"]:
                handshake = {
                    "type": layers["tls"].get("tls.handshake.type", [""])[0]
                }
                
                # Client Hello
                if "tls.handshake.type" in layers["tls"] and layers["tls"]["tls.handshake.type"][0] == "1":
                    handshake["client_version"] = layers["tls"].get("tls.handshake.version", [""])[0]
                    
                    # Extract cipher suites
                    if "tls.handshake.ciphersuite" in layers["tls"]:
                        handshake["cipher_suites"] = layers["tls"]["tls.handshake.ciphersuite"]
                    
                    # Extract server name (SNI)
                    if "tls.handshake.extensions_server_name" in layers["tls"]:
                        handshake["server_name"] = layers["tls"]["tls.handshake.extensions_server_name"][0]
                
                # Server Hello
                elif "tls.handshake.type" in layers["tls"] and layers["tls"]["tls.handshake.type"][0] == "2":
                    handshake["server_version"] = layers["tls"].get("tls.handshake.version", [""])[0]
                    
                    # Extract selected cipher suite
                    if "tls.handshake.ciphersuite" in layers["tls"]:
                        handshake["cipher_suite"] = layers["tls"]["tls.handshake.ciphersuite"][0]
                
                tls_layer["handshake"] = handshake
            
            processed_packet["tls"] = tls_layer
            processed_packet["layers"].append(tls_layer)
        
        return processed_packet
    
    def _extract_tcp_flags(self, tcp_layer: Dict[str, Any]) -> Dict[str, bool]:
        """
        Extract TCP flags from a TCP layer.
        
        Args:
            tcp_layer: TCP layer data
            
        Returns:
            Dictionary of flag names to boolean values
        """
        flags = {}
        
        # Common TCP flags
        flag_fields = {
            "syn": "tcp.flags.syn",
            "ack": "tcp.flags.ack",
            "fin": "tcp.flags.fin",
            "rst": "tcp.flags.reset",
            "psh": "tcp.flags.push",
            "urg": "tcp.flags.urgent"
        }
        
        for name, field in flag_fields.items():
            if field in tcp_layer:
                flags[name] = tcp_layer[field][0] == "1"
            else:
                flags[name] = False
        
        return flags
    
    def _extract_dns_flags(self, dns_layer: Dict[str, Any]) -> Dict[str, bool]:
        """
        Extract DNS flags from a DNS layer.
        
        Args:
            dns_layer: DNS layer data
            
        Returns:
            Dictionary of flag names to boolean values
        """
        flags = {}
        
        # Common DNS flags
        flag_fields = {
            "response": "dns.flags.response",
            "authoritative": "dns.flags.authoritative",
            "truncated": "dns.flags.truncated",
            "recursion_desired": "dns.flags.recdesired",
            "recursion_available": "dns.flags.recavail"
        }
        
        for name, field in flag_fields.items():
            if field in dns_layer:
                flags[name] = dns_layer[field][0] == "1"
            else:
                flags[name] = False
        
        return flags
    
    def _extract_http_headers(self, http_layer: Dict[str, Any], prefix: str) -> List[Dict[str, str]]:
        """
        Extract HTTP headers from an HTTP layer.
        
        Args:
            http_layer: HTTP layer data
            prefix: Prefix for header fields (e.g., 'http.request.line')
            
        Returns:
            List of header dictionaries
        """
        headers = []
        header_fields = {}
        
        # Find all header fields
        for field in http_layer:
            if field.startswith(prefix) and field != prefix:
                parts = field.split(":")
                if len(parts) >= 2:
                    header_name = parts[1].strip()
                    header_fields[field] = header_name
        
        # Extract header values
        for field, name in header_fields.items():
            for value in http_layer[field]:
                if ":" in value:
                    # Split at the first colon for header name/value
                    name_val = value.split(":", 1)
                    header_name = name_val[0].strip()
                    header_value = name_val[1].strip()
                    
                    headers.append({
                        "name": header_name,
                        "value": header_value
                    })
        
        return headers
