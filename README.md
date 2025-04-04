# Wireshark MCP (Model Context Protocol)

A specialized protocol for extracting, structuring, and transmitting network packet data from Wireshark to AI systems like Claude in a context-optimized format.

## What is Wireshark MCP?

Wireshark MCP provides a standardized approach for translating complex network packet captures into structured contexts that AI models can effectively process and analyze. This bridges the gap between low-level network data and high-level AI understanding.

The protocol:
1. **Extracts** relevant packet data from Wireshark captures
2. **Structures** this information in AI-friendly formats
3. **Summarizes** large packet collections into digestible contexts
4. **Translates** protocol-specific details into natural language
5. **Contextualizes** network flows for more meaningful analysis

## Key Features

- **Packet Summarization**: Convert large pcap files into token-optimized summaries
- **Protocol Intelligence**: Enhanced context for common protocols (HTTP, DNS, TLS, SMTP, etc.)
- **Flow Tracking**: Group related packets into conversation flows
- **Anomaly Highlighting**: Emphasize unusual or suspicious patterns
- **Query Templates**: Pre-built prompts for common network analysis tasks
- **Visualization Generation**: Create text-based representations of network patterns
- **Multi-level Abstraction**: View data from raw bytes to high-level behaviors
- **Web Interface**: Browser-based UI for easier analysis and visualization

## Project Status

This project is under active development. Currently implemented features:

- Core packet extraction using tshark
- Protocol analyzers for HTTP, DNS, TLS, and SMTP 
- Claude-specific formatting for optimal AI analysis
- Security analysis for common threats
- Basic flow tracking and analysis
- Web interface for easier usage

Coming soon:
- Additional protocol analyzers (DHCP, ICMP, etc.)
- Advanced visualization options
- Expanded threat detection capabilities
- Enhanced AI integration options

## Documentation

- [Installation & Configuration Guide](docs/installation.md) - Step-by-step installation instructions
- [Claude Integration Guide](docs/claude_integration.md) - Detailed guide for connecting with Claude AI
- [Web Interface README](web_interface/README.md) - Information on using the web interface

## Installation

```bash
pip install wireshark-mcp
```

For full functionality:
1. Ensure Wireshark is installed on your system
2. Install tshark (Wireshark command-line interface)
3. Configure your API access for the AI model (Claude)

See the [Installation Guide](docs/installation.md) for detailed instructions.

## Basic Usage

```python
from wireshark_mcp import WiresharkMCP, Protocol
from wireshark_mcp.formatters import ClaudeFormatter

# Initialize with a pcap file
mcp = WiresharkMCP("capture.pcap")

# Generate a basic packet summary
context = mcp.generate_context(
    max_packets=100,
    focus_protocols=[Protocol.HTTP, Protocol.DNS],
    include_statistics=True
)

# Format it for Claude
formatter = ClaudeFormatter()
claude_prompt = formatter.format_context(
    context, 
    query="What unusual patterns do you see in this HTTP traffic?"
)

# Send to Claude (using your preferred method)
# claude_response = send_to_claude(claude_prompt)
```

## Advanced Usage

### Flow Analysis

```python
# Extract conversation flows
flows = mcp.extract_flows(
    client_ip="192.168.1.5",
    include_details=True,
    max_flows=5
)

# Generate Claude context for flow analysis
flow_prompt = formatter.format_flows(
    flows,
    query="Analyze the TLS handshake in these flows and identify any issues"
)
```

### Security Analysis

```python
# Focus on security-relevant patterns
security_context = mcp.security_analysis(
    detect_scanning=True,
    detect_malware_patterns=True,
    highlight_unusual_ports=True,
    check_encryption=True
)

security_prompt = formatter.format_security_context(
    security_context,
    query="Evaluate the security implications of these network patterns"
)
```

### Protocol Insights

```python
# Deep dive into DNS traffic
dns_insights = mcp.protocol_insights(
    protocol=Protocol.DNS,
    extract_queries=True,
    analyze_response_codes=True,
    detect_tunneling=True
)

dns_prompt = formatter.format_protocol_insights(
    dns_insights,
    query="What do these DNS patterns suggest about the network activity?"
)
```

### SMTP Analysis Example

```python
# Analyze SMTP traffic for email patterns and security issues
smtp_context = mcp.extract_protocol(
    protocol=Protocol.SMTP,
    filter=Filter("smtp"),
    include_headers=True,
    include_body=False
)

# Get deeper insights
smtp_insights = mcp.protocol_insights(
    protocol=Protocol.SMTP,
    extract_queries=True,
    analyze_response_codes=True,
    detect_tunneling=True
)

# Generate Claude prompt for SMTP analysis
smtp_prompt = formatter.format_context(
    smtp_context,
    query="Analyze this SMTP traffic for security issues and unusual email patterns"
)
```

### Claude API Integration

See the [Claude Integration Guide](docs/claude_integration.md) for detailed instructions on connecting to Claude's API. Here's a simplified example:

```python
from wireshark_mcp import WiresharkMCP, Protocol, Filter
from wireshark_mcp.formatters import ClaudeFormatter
from your_claude_client import ClaudeClient  # Your implementation

# Extract HTTP traffic
mcp = WiresharkMCP("web_traffic.pcap")
http_context = mcp.extract_protocol(
    protocol=Protocol.HTTP,
    filter=Filter("ip.addr == 192.168.1.5"),
    include_headers=True,
    include_body=False,
    max_conversations=10
)

# Format for Claude with specific query
formatter = ClaudeFormatter()
prompt = formatter.format_protocol_analysis(
    http_context,
    query="Review these HTTP requests and identify any potential security vulnerabilities"
)

# Send to Claude
claude = ClaudeClient(api_key="your_api_key")
response = claude.analyze(prompt)
print(response.analysis)
```

## Web Interface

Wireshark MCP includes a web-based user interface for easier analysis:

```bash
cd web_interface
pip install -r requirements.txt
python app.py
```

This starts a web server at http://localhost:5000 that allows you to:

- Upload PCAP/PCAPNG files
- Analyze protocol data with a point-and-click interface
- Generate Claude-optimized prompts
- View security insights and anomalies

See the [web interface README](web_interface/README.md) for more details.

## Architecture

The Wireshark MCP system consists of several components:

1. **Packet Extractors**: Interface with Wireshark/tshark to extract packet data
2. **Context Generators**: Process packet data into optimized contexts
3. **Protocol Analyzers**: Protocol-specific understanding and analysis
4. **Formatters**: Structure data for specific AI systems (Claude)
5. **Query Templates**: Pre-built analysis queries for common tasks
6. **AI Connectors**: Optional interfaces to AI systems
7. **Web Interface**: Browser-based UI for easier analysis

## For Developers

### Extending Protocol Support

```python
from wireshark_mcp.protocols import BaseProtocolAnalyzer

class CustomProtocolAnalyzer(BaseProtocolAnalyzer):
    protocol_name = "MY_PROTOCOL"
    
    def extract_features(self, packets):
        # Custom extraction logic
        return features
    
    def generate_context(self, features, detail_level=2):
        # Convert to AI-friendly context
        return context

# Register your custom analyzer
wireshark_mcp.register_protocol_analyzer(CustomProtocolAnalyzer())
```

### Building Custom Formatters

You can create formatters for AI systems other than Claude by extending the BaseFormatter class:

```python
from wireshark_mcp.formatters import BaseFormatter

class CustomAIFormatter(BaseFormatter):
    def format_context(self, context, query=None):
        # Format the context for your specific AI system
        # ...
        return formatted_context

# Use your custom formatter
formatter = CustomAIFormatter()
ai_prompt = formatter.format_context(context, query="Analyze this traffic")
```

## Examples

See the `examples/` directory for more detailed usage examples:

- Basic packet analysis with Claude
- DNS traffic analysis and anomaly detection
- SMTP email flow and security analysis
- Security analysis for threat hunting
- Customizing protocol analysis for specific needs

## Requirements

- Python 3.8+
- Wireshark/tshark installed on the system
- `pyshark`, `scapy`, `pydantic`, and `rich` packages
- Optional: API access to Claude or other AI systems
- For web interface: Flask and dependencies

## Contributing

Contributions are welcome! Areas where help is especially appreciated:

- Additional protocol analyzers
- Performance optimizations
- Documentation and examples
- Testing with diverse packet captures
- Web interface enhancements

See [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to contribute.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
