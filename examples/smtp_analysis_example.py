#!/usr/bin/env python3
"""
Example script demonstrating SMTP protocol analysis with Wireshark MCP.

This example shows how to:
1. Extract SMTP protocol data from a packet capture
2. Generate context for an AI system like Claude
3. Analyze SMTP security patterns
4. Generate domain-level insights from SMTP traffic

Usage:
    python smtp_analysis_example.py <path_to_pcap>

Requirements:
    - Wireshark/tshark installed
    - A packet capture containing SMTP traffic
"""

import os
import sys
import logging
import json
from typing import Dict, Any

from wireshark_mcp import WiresharkMCP, Protocol, Filter
from wireshark_mcp.formatters import ClaudeFormatter

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def analyze_smtp_traffic(pcap_path: str) -> None:
    """
    Analyze SMTP traffic in a packet capture.
    
    Args:
        pcap_path: Path to the packet capture file
    """
    logger.info(f"Analyzing SMTP traffic in {pcap_path}")
    
    # Initialize the Wireshark MCP
    try:
        mcp = WiresharkMCP(pcap_path)
    except (FileNotFoundError, ValueError) as e:
        logger.error(f"Error initializing Wireshark MCP: {e}")
        return
    
    # Extract SMTP protocol data
    try:
        smtp_context = mcp.extract_protocol(
            protocol=Protocol.SMTP,
            filter=Filter("smtp"),
            include_headers=True,
            include_body=False,
            max_conversations=10
        )
        
        logger.info("SMTP protocol data extracted successfully.")
        
        # Display summary information
        summary = smtp_context.get('summary', {})
        logger.info(f"SMTP Summary: {json.dumps(summary, indent=2)}")
        
        # Extract security insights
        security_insights = smtp_context.get('security_insights', {})
        if security_insights:
            logger.info("Security Insights:")
            suspicious_patterns = security_insights.get('suspicious_patterns', [])
            for pattern in suspicious_patterns:
                pattern_type = pattern.get('type', 'unknown')
                description = pattern.get('description', 'No description')
                logger.info(f"  - {pattern_type}: {description}")
            
            # Check for plaintext authentication
            if security_insights.get('plaintext_auth', False):
                logger.warning("⚠️ Plaintext authentication detected!")
            
            # Check for missing TLS
            missing_tls = security_insights.get('missing_tls', 0)
            if missing_tls > 0:
                logger.warning(f"⚠️ {missing_tls} sessions without TLS encryption")
        
        # Generate deeper insights
        logger.info("Generating deeper SMTP insights...")
        deeper_insights = mcp.protocol_insights(
            protocol=Protocol.SMTP,
            extract_queries=True,
            analyze_response_codes=True,
            detect_tunneling=True
        )
        
        # Display domain analysis
        domain_analysis = deeper_insights.get('domain_analysis', {})
        if domain_analysis:
            top_sender_domains = domain_analysis.get('top_sender_domains', {})
            top_recipient_domains = domain_analysis.get('top_recipient_domains', {})
            
            logger.info("Top Sender Domains:")
            for domain, count in top_sender_domains.items():
                logger.info(f"  - {domain}: {count}")
            
            logger.info("Top Recipient Domains:")
            for domain, count in top_recipient_domains.items():
                logger.info(f"  - {domain}: {count}")
        
        # Format for Claude
        format_for_claude(smtp_context, deeper_insights)
        
    except Exception as e:
        logger.error(f"Error analyzing SMTP traffic: {e}", exc_info=True)

def format_for_claude(smtp_context: Dict[str, Any], insights: Dict[str, Any]) -> None:
    """
    Format SMTP data for Claude analysis.
    
    Args:
        smtp_context: SMTP protocol context
        insights: Additional SMTP insights
    """
    logger.info("Formatting SMTP data for Claude...")
    
    # Initialize the Claude formatter
    formatter = ClaudeFormatter()
    
    # Format the basic context
    claude_prompt = formatter.format_context(
        smtp_context,
        query="Analyze this SMTP traffic and identify any security concerns or unusual patterns."
    )
    
    # Save Claude prompt to file
    output_path = "smtp_claude_prompt.md"
    with open(output_path, "w") as f:
        f.write(claude_prompt)
    
    logger.info(f"Claude prompt saved to {output_path}")
    
    # Format domain insights for a different query
    domain_analysis = insights.get('domain_analysis', {})
    response_analysis = insights.get('response_analysis', {})
    
    # Create a specialized context for domain and response analysis
    domain_context = {
        'summary': {
            'analyzed_domains': len(domain_analysis.get('top_sender_domains', {})) + 
                                len(domain_analysis.get('top_recipient_domains', {})),
            'top_sender_domains': domain_analysis.get('top_sender_domains', {}),
            'top_recipient_domains': domain_analysis.get('top_recipient_domains', {})
        },
        'protocol': 'SMTP',
        'response_categories': response_analysis.get('response_categories', {}),
        'top_error_messages': response_analysis.get('top_error_messages', {})
    }
    
    domain_prompt = formatter.format_context(
        domain_context,
        query="Analyze the email domain patterns and SMTP response codes. Do you notice any anomalies or concerns?"
    )
    
    # Save domain analysis prompt to file
    domain_output_path = "smtp_domain_analysis_prompt.md"
    with open(domain_output_path, "w") as f:
        f.write(domain_prompt)
    
    logger.info(f"Domain analysis prompt saved to {domain_output_path}")

def main():
    """Main entry point."""
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <path_to_pcap>")
        sys.exit(1)
    
    pcap_path = sys.argv[1]
    if not os.path.exists(pcap_path):
        print(f"Error: File not found - {pcap_path}")
        sys.exit(1)
    
    analyze_smtp_traffic(pcap_path)

if __name__ == "__main__":
    main()
