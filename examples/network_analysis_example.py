"""Example script demonstrating Wireshark MCP usage."""

import os
from wireshark_mcp import WiresharkMCP
from wireshark_mcp.security_analyzer import SecurityAnalyzer
from wireshark_mcp.flow_analyzer import FlowAnalyzer
from wireshark_mcp.formatters import ClaudeFormatter

def analyze_network_capture(pcap_path):
    """Perform comprehensive network analysis."""
    # Initialize Wireshark MCP
    mcp = WiresharkMCP(pcap_path)
    
    # Generate context
    context = mcp.generate_context(
        max_packets=500,
        focus_protocols=['HTTP', 'DNS', 'TLS']
    )
    
    # Security Analysis
    security_analyzer = SecurityAnalyzer(context['packets'])
    security_results = security_analyzer.analyze(
        detect_scanning=True,
        detect_malware_patterns=True,
        highlight_unusual_ports=True,
        check_encryption=True
    )
    
    # Flow Analysis
    flow_analyzer = FlowAnalyzer(context['packets'])
    flow_analysis = flow_analyzer.analyze_flows()
    anomalous_flows = flow_analyzer.detect_anomalous_flows()
    
    # Prepare final report
    analysis_report = {
        'context': context,
        'security': security_results,
        'flows': {
            'summary': flow_analysis,
            'anomalies': anomalous_flows
        }
    }
    
    return analysis_report

def main():
    # Example usage
    pcap_path = os.path.join(os.path.dirname(__file__), 'sample_capture.pcap')
    
    try:
        report = analyze_network_capture(pcap_path)
        
        # Optional: Format for Claude
        formatter = ClaudeFormatter()
        claude_prompt = formatter.format_context(
            report['context'], 
            query="Provide a comprehensive analysis of the network traffic, highlighting security concerns and unusual patterns."
        )
        
        print("Analysis Report:")
        print("Security Threats:", report['security']['potential_threats'])
        print("Anomalous Flows:", report['flows']['anomalies'])
        
    except Exception as e:
        print(f"Analysis failed: {e}")

if __name__ == '__main__':
    main()