"""
Simple PCAP Analysis Script for Claude

This script uses subprocess to call TShark directly and format basic PCAP information for Claude.
It doesn't rely on the Wireshark-MCP modules, making it more robust against errors.
"""

import os
import sys
import subprocess
import json
from datetime import datetime

def check_tshark():
    """Check if TShark is available and return its path."""
    try:
        # First check if tshark is in PATH
        subprocess.run(["tshark", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return "tshark"
    except FileNotFoundError:
        # Check standard installation paths
        paths = [
            # Windows
            "C:\\Program Files\\Wireshark\\tshark.exe",
            # macOS
            "/usr/local/bin/tshark",
            "/Applications/Wireshark.app/Contents/MacOS/tshark",
            # Linux
            "/usr/bin/tshark",
            "/usr/local/bin/tshark",
        ]
        
        for path in paths:
            if os.path.exists(path):
                return path
        
        return None

def extract_packet_summary(pcap_path, tshark_path, max_packets=1000):
    """Extract basic packet summary information using TShark."""
    cmd = [
        tshark_path,
        "-r", pcap_path,
        "-T", "fields",
        "-e", "frame.number",
        "-e", "frame.time",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "ip.proto",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-e", "frame.len",
        "-E", "header=y",
        "-E", "separator=,",
        "-c", str(max_packets)
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Error running TShark: {result.stderr}")
            return None
        return result.stdout
    except Exception as e:
        print(f"Error extracting packet summary: {e}")
        return None

def extract_protocols(pcap_path, tshark_path):
    """Extract protocol hierarchy statistics."""
    cmd = [
        tshark_path,
        "-r", pcap_path,
        "-q",
        "-z", "io,phs"
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Error running TShark: {result.stderr}")
            return None
        return result.stdout
    except Exception as e:
        print(f"Error extracting protocols: {e}")
        return None

def extract_conversations(pcap_path, tshark_path):
    """Extract conversation statistics."""
    cmd = [
        tshark_path,
        "-r", pcap_path,
        "-q",
        "-z", "conv,ip"
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Error running TShark: {result.stderr}")
            return None
        return result.stdout
    except Exception as e:
        print(f"Error extracting conversations: {e}")
        return None

def format_for_claude(pcap_path, summary, protocols, conversations):
    """Format the output for Claude."""
    output = f"""# PCAP Analysis: {os.path.basename(pcap_path)}

## Overview

This is an analysis of the PCAP file: `{os.path.basename(pcap_path)}`
Analysis performed on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Protocol Hierarchy

The following protocols were detected in this capture:

```
{protocols}
```

## Conversations

The following IP conversations were detected:

```
{conversations}
```

## Packet Summary

Here's a summary of the packets in this capture:

```
{summary}
```

## Analysis Request

Please analyze this network traffic to identify:

1. What types of network traffic are present in this capture?
2. Are there any unusual patterns or anomalies?
3. What can you tell me about the IP conversations and protocols in this capture?
4. Are there any potential security issues or suspicious activities?
5. What is the general structure and purpose of this network communication?
"""
    return output

def main():
    if len(sys.argv) < 2:
        print("Usage: python simple_pcap_analysis.py <path_to_pcap>")
        sys.exit(1)
    
    pcap_path = sys.argv[1]
    
    if not os.path.exists(pcap_path):
        print(f"Error: PCAP file not found: {pcap_path}")
        sys.exit(1)
    
    tshark_path = check_tshark()
    if not tshark_path:
        print("Error: TShark not found. Please install Wireshark with TShark.")
        sys.exit(1)
    
    print(f"Using TShark at: {tshark_path}")
    print(f"Processing PCAP file: {pcap_path}")
    
    # Extract information from the PCAP
    print("Extracting packet summary...")
    summary = extract_packet_summary(pcap_path, tshark_path)
    
    print("Extracting protocol hierarchy...")
    protocols = extract_protocols(pcap_path, tshark_path)
    
    print("Extracting conversations...")
    conversations = extract_conversations(pcap_path, tshark_path)
    
    # Format for Claude
    print("Formatting for Claude...")
    claude_prompt = format_for_claude(pcap_path, summary, protocols, conversations)
    
    # Save to file
    output_file = f"claude_prompt_simple_{os.path.basename(pcap_path)}.md"
    with open(output_file, "w") as f:
        f.write(claude_prompt)
    
    print(f"\nClaude prompt saved to {output_file}")
    print("You can now copy this content to the Claude application.")
    print("Paste it into your conversation at https://claude.ai")

if __name__ == "__main__":
    main()
