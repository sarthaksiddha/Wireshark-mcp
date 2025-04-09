# Wireshark MCP (Model Context Protocol)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

A specialized protocol for extracting, structuring, and transmitting network packet data from Wireshark to AI systems like Claude in a context-optimized format.

## What is Wireshark MCP?

Wireshark MCP provides a standardized approach for translating complex network packet captures into structured contexts that AI models can effectively process and analyze. This bridges the gap between low-level network data and high-level AI understanding.

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
- **Cross-Platform**: Works on Windows, macOS, and Linux

## Installation Guides

For detailed installation instructions specific to your operating system:

- [Windows Installation Guide](docs/windows_installation.md)
- [macOS Installation Guide](docs/macos_installation.md)
- [Linux Installation Guide](docs/linux_installation.md)
- [General Installation & Configuration Guide](docs/installation.md)

## Documentation

- [Claude Integration Guide](docs/claude_integration.md) - Detailed guide for connecting with Claude AI
- [Web Interface Explanation](docs/web_interface_explained.md) - Understanding when to use the web interface vs. scripts
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

## Analysis Methods

### Simple Script (Recommended Method)

The simplest way to analyze PCAP files and generate Claude prompts:

```bash
python scripts/simple_pcap_analysis.py path/to/your/capture.pcap
```

This creates a markdown file you can directly copy into Claude at [claude.ai](https://claude.ai).

### Web Interface (Optional)

If you prefer a graphical approach, we also provide a web interface:

```bash
cd web_interface
pip install -r requirements.txt
python app.py
```

This starts a web server at http://localhost:5000 with features like:
- Upload PCAP/PCAPNG files through your browser
- Point-and-click protocol selection and analysis
- Generate Claude-optimized prompts
- View security insights and anomalies

See [Why Use the Web Interface?](docs/web_interface_explained.md) for details on when to use each approach.

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

## Project Roadmap

### Near-Term Enhancements
- Additional protocol analyzers (DHCP, ICMP, etc.)
- Advanced visualization options
- Expanded threat detection capabilities
- Enhanced AI integration options

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

See [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to contribute.

## Open for Collaboration

This project welcomes collaboration from network security professionals, AI researchers, and developers. If you're interested in contributing or have ideas for improving Wireshark MCP, please open an issue or reach out to the maintainers. Together, we can build better tools for network analysis through AI.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
