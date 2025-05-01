#!/usr/bin/env python3
"""
IP Protection Example for Wireshark MCP

This example demonstrates how to use the IP address protection features 
of Wireshark MCP to anonymize, pseudonymize, or redact sensitive IP addresses
while preserving meaningful analysis capabilities.

Usage:
    python ip_protection_example.py path/to/capture.pcap
"""

import sys
import os
import argparse
import json
from datetime import datetime

# Add the parent directory to the module search path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import Wireshark MCP components
from wireshark_mcp import WiresharkMCP, IPProtectionManager
from wireshark_mcp.formatters import ClaudeFormatter


def demonstrate_ip_protection_modes(pcap_path: str, output_dir: str = None):
    """
    Demonstrate different IP protection modes on a packet capture.
    
    Args:
        pcap_path: Path to the PCAP file to analyze
        output_dir: Directory to write output files (defaults to current directory)
    """
    if not os.path.exists(pcap_path):
        print(f"Error: PCAP file not found: {pcap_path}")
        return
    
    if not output_dir:
        output_dir = os.getcwd()
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"Analyzing PCAP file: {pcap_path}")
    print(f"Output will be saved to: {output_dir}")
    
    # Initialize Wireshark MCP
    try:
        mcp = WiresharkMCP(pcap_path)
    except Exception as e:
        print(f"Error initializing Wireshark MCP: {e}")
        return
    
    # Extract base context
    print("Extracting packet data...")
    context = mcp.generate_context(max_packets=100)
    
    # Store original packet data for comparison
    original_packets = context["packets"][:5]  # Just keep a few for the example
    
    # Create formatter for Claude
    formatter = ClaudeFormatter()
    
    # Create IP protectors with different modes
    protection_modes = {
        "redact_full": IPProtectionManager(IPProtectionManager.REDACT_FULL),
        "redact_host": IPProtectionManager(IPProtectionManager.REDACT_HOST),
        "pseudonymize": IPProtectionManager(IPProtectionManager.PSEUDONYMIZE),
        "partial_mask": IPProtectionManager(IPProtectionManager.PARTIAL_MASK)
    }
    
    # Process with each protection mode
    results = {}
    
    print("\nApplying different IP protection modes...")
    for mode_name, protector in protection_modes.items():
        print(f"  - Processing with {mode_name} mode")
        
        # Apply protection to sample packets
        protected_packets = []
        for packet in original_packets:
            if 'ip' in packet:
                protected_packet = protector.protect_packet(packet)
                protected_packets.append(protected_packet)
        
        # Store results
        results[mode_name] = protected_packets
        
        # If using pseudonymization, show the mapping
        if mode_name == "pseudonymize":
            mapping = protector.get_ip_mapping()
            results["ip_mapping"] = mapping
    
    # Save results to file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(output_dir, f"ip_protection_comparison_{timestamp}.json")
    
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to: {output_file}")
    
    # Create example with additional protected ranges
    print("\nDemonstrating protected IP ranges...")
    range_protector = IPProtectionManager(IPProtectionManager.PSEUDONYMIZE)
    
    # Add specific ranges to protect
    range_protector.add_protected_range("192.168.0.0/16")  # Private networks
    range_protector.add_protected_range("10.0.0.0/8")      # More private networks
    range_protector.add_protected_range("172.16.0.0/12")   # More private networks
    range_protector.add_protected_range("203.0.113.0/24")  # TEST-NET-3 (example addresses)
    
    # Apply to original packets
    range_protected_packets = []
    for packet in original_packets:
        if 'ip' in packet:
            protected_packet = range_protector.protect_packet(packet)
            range_protected_packets.append(protected_packet)
    
    # Save results
    range_results = {
        "original_packets": original_packets,
        "range_protected_packets": range_protected_packets,
        "protected_ranges": [
            "192.168.0.0/16",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "203.0.113.0/24"
        ],
        "ip_mapping": range_protector.get_ip_mapping()
    }
    
    range_output_file = os.path.join(output_dir, f"ip_protection_ranges_{timestamp}.json")
    with open(range_output_file, 'w') as f:
        json.dump(range_results, f, indent=2)
    
    print(f"Results with protected ranges saved to: {range_output_file}")
    
    # Create formatted output for Claude
    print("\nCreating Claude-ready markdown with protected packet data...")
    
    # Apply pseudonymization to full context
    full_protector = IPProtectionManager(IPProtectionManager.PSEUDONYMIZE)
    protected_context = context.copy()
    protected_context["packets"] = []
    
    for packet in context["packets"]:
        if 'ip' in packet:
            protected_packet = full_protector.protect_packet(packet)
            protected_context["packets"].append(protected_packet)
        else:
            protected_context["packets"].append(packet)
    
    # Format for Claude
    claude_prompt = formatter.format_context(
        protected_context,
        query="Analyze this network traffic. Note that IP addresses have been pseudonymized for privacy."
    )
    
    # Save Claude prompt
    claude_output_file = os.path.join(output_dir, f"protected_claude_prompt_{timestamp}.md")
    with open(claude_output_file, 'w') as f:
        f.write(claude_prompt)
    
    print(f"Claude-ready markdown saved to: {claude_output_file}")
    print("\nIP protection demo complete!")


def main():
    # Set up command line argument parsing
    parser = argparse.ArgumentParser(description="Demonstrate IP protection features of Wireshark MCP")
    parser.add_argument("pcap_file", help="Path to the PCAP file to analyze")
    parser.add_argument("-o", "--output-dir", help="Directory to write output files")
    
    args = parser.parse_args()
    
    # Run the demonstration
    demonstrate_ip_protection_modes(args.pcap_file, args.output_dir)


if __name__ == "__main__":
    main()
