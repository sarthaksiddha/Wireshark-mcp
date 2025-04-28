"""
Command-line interface for the Wireshark MCP A2A module.
This module provides a CLI for interacting with the A2A functionality of the Wireshark MCP.
"""

import argparse
import json
import logging
import os
import sys
from typing import Dict, Any, Optional, List

from .agent import WiresharkA2AAgent
from .server import WiresharkA2AServer
from .integration import WiresharkA2AIntegration
from .server_app import WiresharkA2AApp
from ..core import WiresharkMCP  # Import from core instead of wireshark


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def start_server(args: argparse.Namespace) -> None:
    """
    Start the A2A server.
    
    Args:
        args: Command-line arguments
    """
    logger.info(f"Starting A2A server on {args.host}:{args.port}")
    
    app_wrapper = WiresharkA2AApp(
        pcap_path=args.pcap_file,
        tshark_path=args.tshark_path,
        host=args.host,
        port=args.port,
        debug=args.debug
    )
    app_wrapper.run()


def get_agent_card(args: argparse.Namespace) -> None:
    """
    Get and display the agent card.
    
    Args:
        args: Command-line arguments
    """
    agent = WiresharkA2AAgent(
        name="Wireshark MCP Agent",
        description="An A2A agent for analyzing network traffic using Wireshark"
    )
    
    card = agent.get_agent_card()
    print(json.dumps(card, indent=2))


def analyze_pcap(args: argparse.Namespace) -> None:
    """
    Analyze a PCAP file and output results.
    
    Args:
        args: Command-line arguments
    """
    if not os.path.exists(args.file):
        logger.error(f"File not found: {args.file}")
        sys.exit(1)
    
    logger.info(f"Analyzing PCAP file: {args.file}")
    
    # Initialize components
    wireshark_mcp = WiresharkMCP(pcap_path=args.file, tshark_path=args.tshark_path)
    agent = WiresharkA2AAgent(
        name="Wireshark MCP Agent",
        description="An A2A agent for analyzing network traffic using Wireshark"
    )
    integration = WiresharkA2AIntegration(wireshark_mcp, agent)
    
    # Analyze the PCAP file
    result = integration.analyze_packet_capture(
        file_path=args.file,
        analysis_type=args.analysis_type,
        max_packets=args.max_packets
    )
    
    # Output the result
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=2)
        logger.info(f"Results written to {args.output}")
    else:
        print(json.dumps(result, indent=2))


def list_skills(args: argparse.Namespace) -> None:
    """
    List the skills available from the A2A agent.
    
    Args:
        args: Command-line arguments
    """
    agent = WiresharkA2AAgent(
        name="Wireshark MCP Agent",
        description="An A2A agent for analyzing network traffic using Wireshark"
    )
    
    skills = agent._define_skills()
    
    print("Available skills:")
    for skill in skills:
        print(f"\n{skill['name']}: {skill['description']}")
        print("Parameters:")
        for param_name, param_info in skill['parameters']['properties'].items():
            required = "Required" if param_name in skill['parameters'].get('required', []) else "Optional"
            print(f"  - {param_name}: {param_info.get('description', 'No description')} ({required})")


def main() -> None:
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(description="Wireshark MCP A2A CLI")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # Server command
    server_parser = subparsers.add_parser("server", help="Start the A2A server")
    server_parser.add_argument("--host", default="localhost", help="Host to bind to")
    server_parser.add_argument("--port", type=int, default=5000, help="Port to bind to")
    server_parser.add_argument("--debug", action="store_true", help="Run in debug mode")
    server_parser.add_argument("--pcap-file", help="Path to a PCAP file to analyze")
    server_parser.add_argument("--tshark-path", help="Path to the tshark executable")
    
    # Agent card command
    agent_card_parser = subparsers.add_parser("agent-card", help="Get the agent card")
    
    # Analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze a PCAP file")
    analyze_parser.add_argument("file", help="Path to the PCAP file")
    analyze_parser.add_argument("--analysis-type", choices=["basic", "security", "performance", "protocol"], 
                               default="basic", help="Type of analysis to perform")
    analyze_parser.add_argument("--max-packets", type=int, default=1000, help="Maximum number of packets to analyze")
    analyze_parser.add_argument("--output", help="Path to output file (default: stdout)")
    analyze_parser.add_argument("--tshark-path", help="Path to the tshark executable")
    
    # Skills command
    skills_parser = subparsers.add_parser("skills", help="List available skills")
    
    # Parse args and dispatch to the appropriate function
    args = parser.parse_args()
    
    if args.command == "server":
        start_server(args)
    elif args.command == "agent-card":
        get_agent_card(args)
    elif args.command == "analyze":
        analyze_pcap(args)
    elif args.command == "skills":
        list_skills(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
