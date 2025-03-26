"""Command-line interface for Wireshark MCP."""

import argparse
import sys
import json
import os

from .core import WiresharkMCP
from .security_analyzer import SecurityAnalyzer
from .ai_connectors import ClaudeConnector
from .formatters import ClaudeFormatter

def main():
    """Main entry point for the Wireshark MCP CLI."""
    parser = argparse.ArgumentParser(
        description="Wireshark Model Context Protocol - Network Packet Analysis"
    )
    
    # Input file argument
    parser.add_argument(
        'pcap_file', 
        help='Path to the packet capture file'
    )
    
    # Analysis scope arguments
    parser.add_argument(
        '-m', '--max-packets', 
        type=int, 
        default=100, 
        help='Maximum number of packets to analyze (default: 100)'
    )
    
    parser.add_argument(
        '-p', '--protocols', 
        nargs='+', 
        help='Specific protocols to focus on (e.g., HTTP DNS TLS)'
    )
    
    # Analysis mode arguments
    parser.add_argument(
        '--security-scan', 
        action='store_true', 
        help='Perform detailed security analysis'
    )
    
    parser.add_argument(
        '--ai-analyze', 
        action='store_true', 
        help='Use AI to analyze network context'
    )
    
    # Output arguments
    parser.add_argument(
        '-o', '--output', 
        help='Output file path for analysis results'
    )
    
    # Claude-specific arguments
    parser.add_argument(
        '--claude-api-key', 
        help='Anthropic Claude API key for AI analysis',
        default=os.environ.get('CLAUDE_API_KEY')
    )
    
    parser.add_argument(
        '--query', 
        help='Custom query for AI analysis',
        default='Provide a comprehensive analysis of the network traffic, highlighting any potential security concerns or unusual patterns.'
    )
    
    # Parse arguments
    args = parser.parse_args()
    
    # Validate input file
    if not os.path.exists(args.pcap_file):
        print(f"Error: File {args.pcap_file} does not exist.", file=sys.stderr)
        sys.exit(1)
    
    # Initialize Wireshark MCP
    try:
        mcp = WiresharkMCP(args.pcap_file)
        
        # Generate context
        context = mcp.generate_context(
            max_packets=args.max_packets,
            focus_protocols=args.protocols
        )
        
        # Security analysis
        analysis_results = {}
        if args.security_scan:
            security_analyzer = SecurityAnalyzer(context['packets'])
            analysis_results['security'] = security_analyzer.analyze()
        
        # AI Analysis
        if args.ai_analyze:
            if not args.claude_api_key:
                print("Error: Claude API key is required for AI analysis.", file=sys.stderr)
                sys.exit(1)
            
            try:
                claude_connector = ClaudeConnector(args.claude_api_key)
                formatter = ClaudeFormatter()
                
                # Format context for Claude
                claude_prompt = formatter.format_context(
                    context, 
                    query=args.query
                )
                
                # Perform AI analysis
                ai_analysis = claude_connector.analyze_context(context, args.query)
                analysis_results['ai_analysis'] = ai_analysis
            
            except Exception as e:
                print(f"AI analysis failed: {e}", file=sys.stderr)
                analysis_results['ai_analysis'] = str(e)
        
        # Prepare final results
        final_results = {
            'context': context,
            **analysis_results
        }
        
        # Output results
        if args.output:
            # Write to file
            with open(args.output, 'w') as f:
                json.dump(final_results, f, indent=2)
            print(f"Analysis results written to {args.output}")
        else:
            # Print to console
            print(json.dumps(final_results, indent=2))
    
    except Exception as e:
        print(f"Analysis failed: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()