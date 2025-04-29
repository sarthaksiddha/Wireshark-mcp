# Wireshark MCP (Model Context Protocol)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

A specialized protocol for extracting, structuring, and transmitting network packet data from Wireshark to AI systems like Claude in a context-optimized format.

## What is Wireshark MCP?

Wireshark MCP provides a standardized approach for translating complex network packet captures into structured contexts that AI models can effectively process and analyze. This bridges the gap between low-level network data and high-level AI understanding.

<p align="center">
  <img src="https://raw.githubusercontent.com/sarthaksiddha/Wireshark-mcp/main/docs/images/wireshark-mcp-flow.png" alt="Wireshark MCP Flow" width="600"/>
</p>

The protocol:
1. **Extracts** relevant packet data from Wireshark captures
2. **Structures** this information in AI-friendly formats
3. **Summarizes** large packet collections into digestible contexts
4. **Translates** protocol-specific details into natural language
5. **Contextualizes** network flows for more meaningful analysis

## Quick Start

For the fastest way to analyze a PCAP file:

```bash
# Clone the repository
git clone https://github.com/sarthaksiddha/Wireshark-mcp.git
cd Wireshark-mcp

# Run the simple analysis script
python scripts/simple_pcap_analysis.py path/to/your/capture.pcap
```

This will generate a Claude-ready markdown file that you can copy and paste into your conversation with Claude.

## Key Features

- **Packet Summarization**: Convert large pcap files into token-optimized summaries
- **Protocol Intelligence**: Enhanced context for common protocols (HTTP, DNS, TLS, SMTP, etc.)
- **Flow Tracking**: Group related packets into conversation flows
- **Anomaly Highlighting**: Emphasize unusual or suspicious patterns
- **Query Templates**: Pre-built prompts for common network analysis tasks
- **Visualization Generation**: Create text-based representations of network patterns
- **Multi-level Abstraction**: View data from raw bytes to high-level behaviors
- **Web Interface**: Browser-based UI for easier analysis and visualization
- **Agent-to-Agent (A2A) Integration**: Expose packet analysis as an A2A-compatible agent
- **Secure Communication**: Robust message signatures for secure agent-to-agent communication
- **Cross-Platform**: Works on Windows, macOS, and Linux

## Installation Guides

For detailed installation instructions specific to your operating system:

- [Windows Installation Guide](docs/windows_installation.md)
- [macOS Installation Guide](docs/macos_installation.md)
- [Linux Installation Guide](docs/linux_installation.md)
- [General Installation & Configuration Guide](docs/installation.md)

## Documentation

- [Claude Integration Guide](docs/claude_integration.md) - Detailed guide for connecting with Claude AI
- [A2A Module Documentation](docs/a2a_module.md) - Guide for using the Agent-to-Agent integration
- [A2A Security Guide](docs/agent_to_agent_integration.md) - Security considerations for A2A integration
- [Message Security Signatures](docs/security_signature.md) - Guide for secure message signing and verification
- [Web Interface README](web_interface/README.md) - Information on using the web interface
- [Utility Scripts](scripts/README.md) - Helpful scripts for PCAP analysis

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

# Save to file for use with Claude
with open("claude_prompt.md", "w") as f:
    f.write(claude_prompt)
```

## Using with Claude

There are two main ways to use Wireshark MCP with Claude:

### 1. Simple Script Approach (Recommended)

For quick analysis without complex setup:

```bash
python scripts/simple_pcap_analysis.py path/to/your/capture.pcap
```

This generates a markdown file you can copy and paste into Claude at [claude.ai](https://claude.ai).

### 2. API Integration

For programmatic integration with Claude's API:

```python
from claude_client import ClaudeClient  # Your implementation
from wireshark_mcp import WiresharkMCP
from wireshark_mcp.formatters import ClaudeFormatter

# Process the PCAP file
mcp = WiresharkMCP("capture.pcap")
context = mcp.generate_context()

# Format for Claude
formatter = ClaudeFormatter()
prompt = formatter.format_context(context, query="Analyze this network traffic")

# Send to Claude API
client = ClaudeClient(api_key="your_api_key")
response = client.analyze(prompt)
```

See the [Claude Integration Guide](docs/claude_integration.md) for detailed API instructions.

## Web Interface

For a graphical approach, use the included web interface:

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

<p align="center">
  <img src="https://raw.githubusercontent.com/sarthaksiddha/Wireshark-mcp/main/docs/images/web-interface.png" alt="Web Interface" width="600"/>
</p>

## A2A Integration

For Agent-to-Agent (A2A) protocol integration, use the A2A module:

```bash
# Start the A2A server
python -m wireshark_mcp.a2a.cli server --pcap-file path/to/capture.pcap

# In another terminal, get the agent card
python -m wireshark_mcp.a2a.cli agent-card

# Analyze a PCAP file using the A2A CLI
python -m wireshark_mcp.a2a.cli analyze path/to/capture.pcap --output analysis.json
```

The A2A module enables other AI agents to discover and communicate with Wireshark MCP using Google's A2A protocol. This allows for seamless integration with agent ecosystems and multi-agent workflows.

See the [A2A Module Documentation](docs/a2a_module.md) for detailed usage instructions and the [A2A Security Guide](docs/agent_to_agent_integration.md) for security considerations.

## Secure Agent Communication

For secure agent-to-agent communication, use the message signature features:

```python
from wireshark_mcp.security import AgentSecurityWrapper, SecurityMonitor

# Create secured agents
security_monitor = SecurityMonitor()
secured_agent = AgentSecurityWrapper(agent, security_monitor)

# Generate secure message signatures
message = "Important security alert: Potential data exfiltration detected"
signature_data = secured_agent.generate_message_signature(message)

# Verify messages from other agents
if secured_agent.verify_message_signature(received_message, signature_data):
    # Process verified message
    process_message(received_message)
else:
    # Handle tampered message
    handle_security_incident(received_message)
```

See the [Message Security Signatures](docs/security_signature.md) guide for detailed instructions on implementing secure message signing and verification.

## Advanced Use Cases

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

### Creating A2A-Compatible Agents

```python
from wireshark_mcp.core import WiresharkMCP
from wireshark_mcp.a2a.agent import WiresharkA2AAgent
from wireshark_mcp.a2a.integration import WiresharkA2AIntegration

# Create a specialized agent
wireshark_mcp = WiresharkMCP(pcap_path="capture.pcap")
agent = WiresharkA2AAgent(
    name="DNS Analysis Agent",
    description="Specialized agent for DNS traffic analysis"
)
integration = WiresharkA2AIntegration(wireshark_mcp, agent)

# Now you can expose this agent through an A2A server
```

## Project Roadmap

### Near-Term Enhancements
- Additional protocol analyzers (DHCP, ICMP, etc.)
- Advanced visualization options
- Expanded threat detection capabilities
- Enhanced A2A integration capabilities
- Multi-agent analysis workflows

### Future Vision
- Real-time packet capture and analysis
- ML-based anomaly detection
- Integration with additional AI systems
- Collaborative analysis features
- Cloud-based analysis capabilities
- Custom protocol definition language

## Contributing

Contributions are welcome! Areas where help is especially appreciated:

- Additional protocol analyzers
- Performance optimizations
- Documentation and examples
- Testing with diverse packet captures
- Web interface enhancements
- A2A integration improvements

See [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to contribute.

## Open for Collaboration

This project welcomes collaboration from network security professionals, AI researchers, and developers. If you're interested in contributing or have ideas for improving Wireshark MCP, please open an issue or reach out to the maintainers. Together, we can build better tools for network analysis through AI.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
