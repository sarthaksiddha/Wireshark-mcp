"""
Wireshark MCP Analysis Script for Claude

This script processes a PCAP file using Wireshark MCP and formats it for Claude.
It handles module imports more robustly to avoid common issues.
"""

import os
import sys
import importlib
import subprocess

def check_tshark():
    """Check if TShark is available."""
    try:
        subprocess.run(["tshark", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except FileNotFoundError:
        return False

def find_tshark_path():
    """Find the TShark executable path on various platforms."""
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

def main():
    # Get the absolute path to the script's directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Get the repository root (one level up from scripts directory)
    repo_root = os.path.dirname(script_dir)
    
    # Add the repository root to the Python path
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)
    
    # Check command-line arguments
    if len(sys.argv) < 2:
        print("Usage: python analyze_pcap.py <path_to_pcap> [protocol]")
        print("Available protocols: HTTP, DNS, TLS, SMTP, TCP, UDP")
        sys.exit(1)
    
    pcap_path = sys.argv[1]
    protocol_name = sys.argv[2] if len(sys.argv) > 2 else None
    
    # Check if the PCAP file exists
    if not os.path.exists(pcap_path):
        print(f"Error: PCAP file not found: {pcap_path}")
        sys.exit(1)
    
    # Check TShark availability
    tshark_found = check_tshark()
    tshark_path = None
    
    if not tshark_found:
        # Try to find TShark in standard locations
        tshark_path = find_tshark_path()
        if not tshark_path:
            print("Error: TShark not found. Please install Wireshark with TShark.")
            sys.exit(1)
        print(f"TShark not in PATH, using: {tshark_path}")
    
    # Import the required modules
    try:
        # Import the core module
        from wireshark_mcp.core import WiresharkMCP
        
        # Import the Protocol enum from the protocols package
        from wireshark_mcp.protocols import Protocol
        
        # Import the Claude formatter
        from wireshark_mcp.formatters import ClaudeFormatter
        
        print("Successfully imported Wireshark MCP modules")
    except ImportError as e:
        print(f"Error importing modules: {e}")
        
        print("\nTry setting the PYTHONPATH environment variable to include the repository directory:")
        print(f"  Windows: set PYTHONPATH={repo_root}")
        print(f"  macOS/Linux: export PYTHONPATH=$PYTHONPATH:{repo_root}")
        
        print("\nOr try using the simpler analysis script that doesn't require imports:")
        print("  python simple_pcap_analysis.py", pcap_path)
        
        sys.exit(1)
    
    try:
        # Initialize MCP with the packet capture
        print(f"Processing PCAP file: {pcap_path}")
        mcp = WiresharkMCP(pcap_path, tshark_path=tshark_path)
        
        if protocol_name:
            # Extract specific protocol data
            try:
                protocol = getattr(Protocol, protocol_name.upper())
            except AttributeError:
                print(f"Error: Protocol '{protocol_name}' is not supported.")
                print("Available protocols: HTTP, DNS, TLS, SMTP, TCP, UDP")
                sys.exit(1)
                
            print(f"Extracting {protocol_name} protocol data...")
            context = mcp.extract_protocol(
                protocol=protocol,
                include_headers=True,
                include_body=False
            )
            query = f"Analyze this {protocol_name} traffic for patterns, anomalies, and security issues."
        else:
            # Generate general context
            print("Generating general network context...")
            context = mcp.generate_context(
                max_packets=100,
                include_statistics=True
            )
            query = "Analyze this network traffic for patterns, anomalies, and security issues."
        
        # Format for Claude
        print("Formatting for Claude...")
        formatter = ClaudeFormatter()
        prompt = formatter.format_context(
            context,
            query=query
        )
        
        # Save to file
        output_file = os.path.join(
            os.path.dirname(pcap_path), 
            f"claude_prompt_{protocol_name + '_' if protocol_name else ''}{os.path.basename(pcap_path)}.md"
        )
        with open(output_file, "w") as f:
            f.write(prompt)
        
        print(f"\nClaude prompt saved to {output_file}")
        print("You can now copy this content to the Claude application.")
        print("Paste it into your conversation at https://claude.ai")
        
    except Exception as e:
        print(f"Error processing PCAP file: {e}")
        
        print("\nTrying a simpler approach might help. Try:")
        print(f"  python {os.path.join(script_dir, 'simple_pcap_analysis.py')} {pcap_path}")
        
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
