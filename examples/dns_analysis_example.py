"""
Example script demonstrating DNS analysis with Wireshark MCP.

This example shows how to:
1. Load and analyze a pcap file with DNS traffic
2. Extract DNS protocol-specific information
3. Generate insights about DNS traffic patterns
4. Format the results for Claude AI
5. Optionally send the formatted data to Claude (commented out)

Usage:
    python dns_analysis_example.py path/to/capture.pcap
"""

import sys
import json
from pathlib import Path

from wireshark_mcp import WiresharkMCP, Protocol
from wireshark_mcp.formatter import ClaudeFormatter

def main():
    """Run the DNS analysis example."""
    # Check for pcap file argument
    if len(sys.argv) < 2:
        print("Usage: python dns_analysis_example.py path/to/capture.pcap")
        return 1
    
    pcap_path = sys.argv[1]
    if not Path(pcap_path).exists():
        print(f"Error: File not found - {pcap_path}")
        return 1
    
    # Print banner
    print("=" * 80)
    print("Wireshark MCP - DNS Analysis Example")
    print("=" * 80)
    print(f"Analyzing: {pcap_path}")
    print()
    
    # Initialize Wireshark MCP with the pcap file
    try:
        mcp = WiresharkMCP(pcap_path)
        print("✓ Successfully loaded pcap file")
    except Exception as e:
        print(f"Error initializing Wireshark MCP: {e}")
        return 1
    
    # Extract DNS protocol information
    try:
        print("Extracting DNS protocol data...")
        dns_context = mcp.extract_protocol(
            protocol=Protocol.DNS,
            include_headers=True,
            max_conversations=20
        )
        
        # Print some basic stats
        summary = dns_context.get('summary', {})
        print(f"Total queries: {summary.get('total_queries', 0)}")
        print(f"Total responses: {summary.get('total_responses', 0)}")
        print(f"Completed transactions: {summary.get('completed_transactions', 0)}")
        print(f"Unique domains: {summary.get('unique_domains', 0)}")
        print()
    except Exception as e:
        print(f"Error extracting DNS protocol data: {e}")
        return 1
    
    # Perform deeper DNS insights analysis
    try:
        print("Analyzing DNS patterns for insights...")
        dns_insights = mcp.protocol_insights(
            protocol=Protocol.DNS,
            extract_queries=True,
            analyze_response_codes=True,
            detect_tunneling=True
        )
        
        # Print insight counts
        query_insights = dns_insights.get('query_insights', [])
        response_insights = dns_insights.get('response_insights', [])
        tunneling_indicators = dns_insights.get('tunneling_indicators', [])
        
        print(f"Query insights: {len(query_insights)}")
        print(f"Response insights: {len(response_insights)}")
        print(f"Tunneling indicators: {len(tunneling_indicators)}")
        print()
    except Exception as e:
        print(f"Error analyzing DNS insights: {e}")
        dns_insights = None
    
    # Format for Claude
    try:
        print("Formatting results for Claude...")
        formatter = ClaudeFormatter()
        
        # Format protocol analysis
        protocol_analysis = formatter.format_protocol_analysis(
            dns_context,
            query="Analyze this DNS traffic and identify any unusual patterns or security concerns."
        )
        
        # Format protocol insights if available
        if dns_insights:
            protocol_insights = formatter.format_protocol_insights(
                dns_insights,
                query="What do these DNS patterns suggest about the network activity?"
            )
        
        # Save formatted output to files
        with open("dns_analysis_for_claude.md", "w") as f:
            f.write(protocol_analysis)
        print(f"✓ Saved protocol analysis to dns_analysis_for_claude.md")
        
        if dns_insights:
            with open("dns_insights_for_claude.md", "w") as f:
                f.write(protocol_insights)
            print(f"✓ Saved protocol insights to dns_insights_for_claude.md")
        
        print()
    except Exception as e:
        print(f"Error formatting for Claude: {e}")
        return 1
    
    # Optional: Send to Claude
    # This section is commented out as it requires API keys and authentication
    """
    try:
        from wireshark_mcp.ai import ClaudeClient
        
        print("Sending analysis to Claude...")
        claude = ClaudeClient(api_key="your_api_key")
        response = claude.analyze(protocol_analysis)
        
        # Save Claude's response
        with open("claude_dns_analysis.md", "w") as f:
            f.write(response.analysis)
        print(f"✓ Saved Claude's analysis to claude_dns_analysis.md")
    except Exception as e:
        print(f"Error communicating with Claude: {e}")
    """
    
    print("=" * 80)
    print("Analysis completed successfully!")
    print("=" * 80)
    return 0

if __name__ == "__main__":
    sys.exit(main())
