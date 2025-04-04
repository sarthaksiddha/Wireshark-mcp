# Installation & Configuration Guide

This guide covers the installation of Wireshark MCP and its configuration for use with Claude AI.

## Prerequisites

Before you begin, ensure you have the following:

1. **Python 3.8+** installed on your system
2. **Wireshark** installed on your system (including tshark)
3. A Claude API key (optional, if using the API directly)

## Installing Wireshark

If you don't already have Wireshark installed:

### Windows
1. Download the installer from [Wireshark's official website](https://www.wireshark.org/download.html)
2. Run the installer and follow the prompts
3. Make sure to check the option to install tshark (command-line tools) during installation

### macOS
1. Install using Homebrew:
   ```bash
   brew install wireshark
   ```
2. Or download the installer from [Wireshark's official website](https://www.wireshark.org/download.html)

### Linux
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install wireshark tshark

# Fedora
sudo dnf install wireshark

# Arch Linux
sudo pacman -S wireshark-qt
```

Verify tshark is installed and accessible:
```bash
tshark --version
```

## Installing Wireshark MCP

### Method 1: Using pip (recommended)

```bash
pip install wireshark-mcp
```

### Method 2: From source

```bash
git clone https://github.com/sarthaksiddha/Wireshark-mcp.git
cd Wireshark-mcp
pip install -e .
```

## Verifying Installation

Run a simple test to verify the installation:

```python
from wireshark_mcp import WiresharkMCP

# This should not raise any import errors
print("Wireshark MCP installed successfully!")
```

## Setting Up Claude Integration

There are two ways to integrate with Claude: via API or manually.

### Option 1: Claude API Integration

1. **Create a configuration file**

   Create a file named `claude_config.py`:

   ```python
   # claude_config.py
   CLAUDE_API_KEY = "your_anthropic_api_key"  # Replace with your actual API key
   CLAUDE_API_URL = "https://api.anthropic.com/v1/messages"
   CLAUDE_MODEL = "claude-3-opus-20240229"  # Or your preferred model version
   ```

2. **Create a Claude client class**

   ```python
   # claude_client.py
   import requests
   import json
   from claude_config import CLAUDE_API_KEY, CLAUDE_API_URL, CLAUDE_MODEL

   class ClaudeClient:
       def __init__(self, api_key=None, api_url=None, model=None):
           self.api_key = api_key or CLAUDE_API_KEY
           self.api_url = api_url or CLAUDE_API_URL
           self.model = model or CLAUDE_MODEL
           
       def analyze(self, prompt):
           headers = {
               "Content-Type": "application/json",
               "x-api-key": self.api_key,
               "anthropic-version": "2023-06-01"
           }
           
           data = {
               "model": self.model,
               "messages": [{"role": "user", "content": prompt}],
               "max_tokens": 4000
           }
           
           response = requests.post(self.api_url, headers=headers, json=data)
           
           if response.status_code != 200:
               raise Exception(f"API error: {response.status_code} - {response.text}")
               
           return response.json()
   ```

3. **Using the client with Wireshark MCP**

   ```python
   from wireshark_mcp import WiresharkMCP, Protocol
   from wireshark_mcp.formatters import ClaudeFormatter
   from claude_client import ClaudeClient
   
   # Initialize MCP with a packet capture
   mcp = WiresharkMCP("path/to/your/capture.pcap")
   
   # Extract protocol data (e.g., HTTP)
   context = mcp.extract_protocol(
       protocol=Protocol.HTTP,
       include_headers=True,
       include_body=False
   )
   
   # Format for Claude
   formatter = ClaudeFormatter()
   prompt = formatter.format_context(
       context,
       query="Analyze this HTTP traffic for security vulnerabilities"
   )
   
   # Send to Claude API
   claude = ClaudeClient()
   response = claude.analyze(prompt)
   
   # Print Claude's analysis
   print(response["content"][0]["text"])
   ```

### Option 2: Manual Integration

If you don't have API access or prefer to use Claude's web interface:

1. **Generate and save a Claude-formatted prompt**

   ```python
   from wireshark_mcp import WiresharkMCP, Protocol
   from wireshark_mcp.formatters import ClaudeFormatter
   
   # Initialize MCP with a packet capture
   mcp = WiresharkMCP("path/to/your/capture.pcap")
   
   # Extract protocol data
   context = mcp.extract_protocol(protocol=Protocol.HTTP)
   
   # Format for Claude
   formatter = ClaudeFormatter()
   prompt = formatter.format_context(
       context,
       query="Analyze this HTTP traffic for security issues"
   )
   
   # Save to file
   with open("claude_prompt.md", "w") as f:
       f.write(prompt)
   
   print("Claude prompt saved to claude_prompt.md")
   ```

2. **Use with Claude Web Interface**

   - Copy the contents of `claude_prompt.md`
   - Paste into [Claude's web interface](https://claude.ai)
   - Submit and wait for Claude's analysis

## Web Interface Configuration

The Wireshark MCP web interface provides a user-friendly way to analyze packets and generate Claude prompts.

### Setting up the web interface

1. **Install dependencies**

   ```bash
   cd web_interface
   pip install -r requirements.txt
   ```

2. **Configure environment variables (optional)**

   Create a `.env` file in the `web_interface` directory:

   ```
   SECRET_KEY=your_secret_key_here
   CLAUDE_API_KEY=your_claude_api_key
   UPLOAD_FOLDER=/custom/path/for/uploads
   ```

3. **Start the web server**

   ```bash
   python app.py
   ```

4. **Access the web interface**

   Open a browser and navigate to http://localhost:5000

## Troubleshooting

### Common Issues

1. **tshark not found**
   
   Error: `tshark not found. Please install Wireshark/tshark or provide the path.`
   
   Solution:
   - Ensure Wireshark is installed with tshark
   - Add tshark to your PATH
   - Provide the explicit path to tshark:
     ```python
     mcp = WiresharkMCP("capture.pcap", tshark_path="/path/to/tshark")
     ```

2. **Permission issues with PCAP files**
   
   Error: `Permission denied` when opening PCAP files
   
   Solution:
   - Ensure your user has read permissions for the PCAP files
   - On Linux/macOS, you might need to run with sudo for some packet captures

3. **Empty analysis results**
   
   Issue: No data in the protocol analysis
   
   Solution:
   - Verify the PCAP file contains the protocol you're analyzing
   - Check with Wireshark GUI to confirm packets are present
   - Try using a filter:
     ```python
     context = mcp.extract_protocol(
         protocol=Protocol.HTTP,
         filter=Filter("http")
     )
     ```

4. **Claude API errors**
   
   Issue: Errors when connecting to Claude API
   
   Solution:
   - Verify your API key is correct
   - Check your internet connection
   - Ensure you're using the correct API endpoint
   - Verify you're within API rate limits

## Advanced Configuration

### Custom Protocol Analyzers

If you want to add support for a protocol that's not included by default:

```python
from wireshark_mcp.protocols import BaseProtocolAnalyzer

class MyCustomProtocolAnalyzer(BaseProtocolAnalyzer):
    protocol_name = "CUSTOM_PROTOCOL"
    
    def extract_features(self, packets, **kwargs):
        # Custom extraction logic
        features = {}
        # Process packets...
        return features
    
    def generate_context(self, features, detail_level=2, **kwargs):
        # Convert features to AI-friendly context
        context = {
            'summary': {},
            'protocol': self.protocol_name,
            'transactions': []
        }
        # Structure the data...
        return context

# Register your custom analyzer
from wireshark_mcp import register_protocol_analyzer
register_protocol_analyzer(MyCustomProtocolAnalyzer())
```

### Custom Formatters

To customize how data is formatted for Claude or other AI systems:

```python
from wireshark_mcp.formatters import BaseFormatter

class MyCustomFormatter(BaseFormatter):
    def format_context(self, context, query=None):
        # Custom formatting logic
        output = "# Custom Network Analysis\n\n"
        # Format the context...
        return output

# Use your custom formatter
formatter = MyCustomFormatter()
prompt = formatter.format_context(context, query="Analyze this traffic")
```

## Security Considerations

When using Wireshark MCP with Claude:

1. **Sensitive Data**: Be careful about sending packet captures that might contain:
   - Passwords or authentication tokens
   - Personal identifiable information
   - Proprietary or confidential information

2. **API Keys**: Keep your Claude API keys secure and don't commit them to public repositories

3. **Web Interface Security**: When deploying the web interface:
   - Use HTTPS in production
   - Implement proper authentication if exposed beyond localhost
   - Regularly clean up uploaded files
