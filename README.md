# Wireshark MCP (Model Context Protocol)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

A Model Context Protocol (MCP) server for integrating Wireshark network analysis capabilities with AI systems like Claude. This implementation provides direct integration with Claude without requiring manual copy/paste of prompts.

## What is Wireshark MCP?

Wireshark MCP provides a standardized way for AI assistants to access and analyze network packet data through Wireshark. It bridges the gap between low-level network data and high-level AI understanding by implementing the Model Context Protocol.

<p align="center">
  <img src="https://raw.githubusercontent.com/sarthaksiddha/Wireshark-mcp/main/docs/images/wireshark-mcp-flow.png" alt="Wireshark MCP Flow" width="600"/>
</p>

The server provides tools for:

1. Capturing live network traffic
2. Analyzing existing pcap files
3. Extracting protocol-specific information
4. Summarizing network flows

## Quick Start

### Installation

```bash
# Clone the repository 
git clone https://github.com/sarthaksiddha/Wireshark-mcp.git 
cd Wireshark-mcp

# Install dependencies
pip install -e .
```

### Running the MCP Server

```bash
# Run with stdio transport (for Claude Desktop)
python mcp_server.py --stdio

# Run with SSE transport (for other MCP clients)
python mcp_server.py --host 127.0.0.1 --port 5000
```

### Configuring Claude Desktop

To configure Claude Desktop to use the Wireshark MCP server:

1. Open Claude Desktop
2. Go to Settings > Developer > Edit Config
3. Add the following configuration:

```json
{
  "mcpServers": {
    "wireshark": {
      "command": "python",
      "args": [
        "/path/to/wireshark-mcp/mcp_server.py",
        "--stdio"
      ]
    }
  }
}
```

Replace `/path/to/wireshark-mcp` with the actual path to your repository.

## Available Tools

The Wireshark MCP server provides the following tools:

- `capture_live_traffic`: Capture live network traffic using tshark
- `analyze_pcap`: Analyze an existing pcap file
- `get_protocol_list`: Get a list of supported protocols

## Example Usage in Claude

Once configured, you can use the Wireshark MCP server in Claude with queries like:

- "Capture 30 seconds of network traffic on my system and show me what's happening"
- "Analyze my network.pcap file and tell me if there are any suspicious activities"
- "What protocols can I focus on when analyzing network traffic?"

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
- **Advanced Security Framework**: Comprehensive security controls for data protection and communication
- **IP Address Protection**: Multiple strategies for anonymizing sensitive network addresses
- **Secure Communication**: Robust message signatures for secure agent-to-agent communication
- **Cross-Platform**: Works on Windows, macOS, and Linux

## Documentation

- [Claude Integration Guide](docs/claude_integration.md) - Detailed guide for connecting with Claude AI
- [A2A Module Documentation](docs/a2a_module.md) - Guide for using the Agent-to-Agent integration
- [A2A Security Guide](docs/agent_to_agent_integration.md) - Security considerations for A2A integration
- [IP Protection Guide](docs/ip_protection.md) - Detailed guide on IP address anonymization and obfuscation
- [Security Manager Guide](docs/security_manager.md) - Comprehensive guide to the unified security framework
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

There are three main ways to use Wireshark MCP with Claude:

### 1. Direct MCP Integration (NEW)

For seamless integration with Claude Desktop:

```bash
# Run the MCP server with stdio transport
python mcp_server.py --stdio
```

Then configure Claude Desktop as described in the "Configuring Claude Desktop" section above. This method provides direct integration without any copy/paste needed.

### 2. Simple Script Approach

For quick analysis without complex setup (requires copy/paste):

```bash
python scripts/simple_pcap_analysis.py path/to/your/capture.pcap
```

This generates a markdown file you can copy and paste into Claude at [claude.ai](https://claude.ai).

### 3. API Integration

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

## Requirements

- Python 3.8+
- Wireshark/tshark installed and in your PATH
- fastmcp Python package

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
