#!/usr/bin/env python3
import argparse
import os
import tempfile
import subprocess
import json
from pathlib import Path
import logging
from typing import List, Dict, Any, Optional

from fastmcp import Server, Tools

# Import our Wireshark MCP functionality
from wireshark_mcp import WiresharkMCP, Protocol
from wireshark_mcp.formatters import ClaudeFormatter

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("wireshark-mcp")

class WiresharkMCPServer:
    def __init__(self):
        self.server = Server(
            name="wireshark-mcp-server",
            description="Wireshark Network Analysis through Model Context Protocol"
        )
        
        # Register tools
        tools = Tools()
        
        @tools.tool("capture_live_traffic")
        def capture_live_traffic(
            interface: str = "any", 
            duration: int = 10, 
            filter: str = "", 
            max_packets: int = 100
        ) -> Dict[str, Any]:
            """
            Capture live network traffic using tshark (Wireshark CLI)
            
            Args:
                interface: Network interface to capture from (default: "any")
                duration: Capture duration in seconds (default: 10)
                filter: Wireshark display filter (default: "")
                max_packets: Maximum number of packets to capture (default: 100)
                
            Returns:
                Dict containing the analysis results
            """
            # Create a temporary file to store the capture
            temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pcap')
            temp_file.close()
            
            try:
                # Build tshark command
                cmd = [
                    "tshark", 
                    "-i", interface, 
                    "-a", f"duration:{duration}",
                    "-w", temp_file.name,
                    "-c", str(max_packets)
                ]
                
                if filter:
                    cmd.extend(["-f", filter])
                
                # Run the capture
                logger.info(f"Starting packet capture with command: {' '.join(cmd)}")
                subprocess.run(cmd, check=True)
                
                # Process the capture file
                mcp = WiresharkMCP(temp_file.name)
                context = mcp.generate_context(
                    max_packets=max_packets,
                    include_statistics=True
                )
                
                # Return the results
                return {
                    "packet_count": context.get("summary", {}).get("total_packets", 0),
                    "protocols": list(context.get("summary", {}).get("protocols", {}).keys()),
                    "statistics": context.get("statistics", {}),
                    "summary": context.get("summary", {})
                }
                
            finally:
                # Clean up the temporary file
                if os.path.exists(temp_file.name):
                    os.unlink(temp_file.name)
        
        @tools.tool("analyze_pcap")
        def analyze_pcap(
            file_path: str,
            max_packets: int = 100,
            focus_protocols: Optional[List[str]] = None
        ) -> Dict[str, Any]:
            """
            Analyze an existing pcap file
            
            Args:
                file_path: Path to the pcap file
                max_packets: Maximum number of packets to analyze
                focus_protocols: List of protocols to focus on (e.g., ["HTTP", "DNS", "TLS"])
                
            Returns:
                Dict containing the analysis results
            """
            # Check if the file exists
            if not os.path.exists(file_path):
                return {"error": f"File not found: {file_path}"}
            
            # Convert string protocol names to Protocol enums if provided
            protocol_enums = None
            if focus_protocols:
                protocol_enums = []
                for p in focus_protocols:
                    try:
                        protocol_enums.append(Protocol[p.upper()])
                    except KeyError:
                        return {"error": f"Unknown protocol: {p}"}
            
            # Process the capture file
            mcp = WiresharkMCP(file_path)
            context = mcp.generate_context(
                max_packets=max_packets,
                focus_protocols=protocol_enums,
                include_statistics=True
            )
            
            # Return the results
            return {
                "file_path": file_path,
                "packet_count": context.get("summary", {}).get("total_packets", 0),
                "protocols": list(context.get("summary", {}).get("protocols", {}).keys()),
                "statistics": context.get("statistics", {}),
                "summary": context.get("summary", {})
            }
            
        @tools.tool("get_protocol_list")
        def get_protocol_list() -> List[str]:
            """
            Get a list of supported protocols for filtering
            
            Returns:
                List of protocol names
            """
            return [p.name for p in Protocol]
        
        # Register the tools with the server
        self.server.register_tools(tools)
    
    def run(self, host="127.0.0.1", port=5000, stdio=False):
        """
        Run the MCP server
        
        Args:
            host: Hostname to bind to (for SSE transport)
            port: Port to bind to (for SSE transport)
            stdio: Whether to use stdio transport instead of SSE
        """
        if stdio:
            logger.info("Starting Wireshark MCP server with stdio transport")
            self.server.serve_stdio()
        else:
            logger.info(f"Starting Wireshark MCP server with SSE transport on {host}:{port}")
            self.server.serve_sse(host=host, port=port)


def main():
    parser = argparse.ArgumentParser(description="Wireshark MCP Server")
    parser.add_argument("--host", default="127.0.0.1", help="Hostname to bind to (for SSE transport)")
    parser.add_argument("--port", type=int, default=5000, help="Port to bind to (for SSE transport)")
    parser.add_argument("--stdio", action="store_true", help="Use stdio transport instead of SSE")
    
    args = parser.parse_args()
    
    server = WiresharkMCPServer()
    server.run(host=args.host, port=args.port, stdio=args.stdio)


if __name__ == "__main__":
    main()
