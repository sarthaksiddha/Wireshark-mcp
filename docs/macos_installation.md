# macOS Installation & Troubleshooting Guide

This guide provides detailed instructions for installing and using Wireshark MCP on macOS systems, including handling common issues.

## Prerequisites

Before you begin, ensure you have the following:

1. **Python 3.8+** installed on your system
   - Install using [Homebrew](https://brew.sh/): `brew install python`
   - Or download from [python.org](https://www.python.org/downloads/macos/)

2. **Git** installed on your system (for cloning the repository)
   - Install using Homebrew: `brew install git`
   - Or download from [git-scm.com](https://git-scm.com/download/mac)

3. **Wireshark/TShark** installed on your system
   - Install using Homebrew: `brew install wireshark`
   - Or download from [wireshark.org](https://www.wireshark.org/download.html)

## Installation Methods

### Method 1: Standard Installation (via pip)

```bash
pip3 install wireshark-mcp
```

### Method 2: From Source (Recommended for Development)

```bash
# Clone the repository
git clone https://github.com/sarthaksiddha/Wireshark-mcp.git
cd Wireshark-mcp

# Create a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## Alternate Installation Method (If You Encounter Issues)

If you encounter module import errors with the standard installation methods, you can use this approach:

1. Clone the repository:
   ```bash
   git clone https://github.com/sarthaksiddha/Wireshark-mcp.git
   cd Wireshark-mcp
   ```

2. Create a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Install dependencies directly (without installing the package in development mode):
   ```bash
   pip install pyshark scapy pydantic rich requests Jinja2
   pip install -r web_interface/requirements.txt
   ```

4. Set PYTHONPATH to include the repository directory:
   ```bash
   export PYTHONPATH=$PYTHONPATH:$(pwd)
   ```

This approach avoids issues with the package structure while still allowing you to use all the functionality.

## Using Wireshark MCP with Claude

### Simple Analysis Script

For the most reliable method to analyze a PCAP file, especially if you encounter issues with other methods, use the `simple_pcap_analysis.py` script included in the `scripts` directory:

```bash
cd scripts
python simple_pcap_analysis.py /path/to/your/capture.pcap
```

This will:
1. Extract basic information from your PCAP file using TShark directly
2. Format it for Claude
3. Save the output to a markdown file that you can copy and paste into Claude

### Protocol-Specific Analysis

To focus on a specific protocol:

```bash
cd scripts
python analyze_pcap.py /path/to/your/capture.pcap HTTP
```

Replace HTTP with the protocol you want to analyze (HTTP, DNS, TLS, SMTP, etc.)

## Web Interface

To use the web interface:

1. Ensure you're in the repository directory and the virtual environment is activated:
   ```bash
   cd Wireshark-mcp
   source venv/bin/activate
   export PYTHONPATH=$PYTHONPATH:$(pwd)  # If needed
   ```

2. Start the web interface:
   ```bash
   cd web_interface
   python app.py
   ```

3. Open a web browser and navigate to http://localhost:5000

## Troubleshooting macOS-Specific Issues

### TShark Not Found or Not Working

If you get a "TShark not found" error:

1. Verify TShark is installed by running in Terminal:
   ```bash
   which tshark
   ```

2. If not found but Wireshark is installed, specify the path explicitly:
   ```python
   # In your Python code
   mcp = WiresharkMCP("capture.pcap", tshark_path="/usr/local/bin/tshark")
   ```

3. For Homebrew installations, TShark is usually located at:
   ```
   /usr/local/bin/tshark
   ```

4. Add the TShark directory to your PATH:
   ```bash
   echo 'export PATH="/usr/local/bin:$PATH"' >> ~/.zshrc  # For Zsh
   # OR
   echo 'export PATH="/usr/local/bin:$PATH"' >> ~/.bash_profile  # For Bash
   ```

### Permission Issues for Packet Capture

On macOS, capturing packets requires special permissions:

1. Wireshark needs administrator privileges for live packet capture
2. For analyzing existing PCAP files, ensure you have read permissions:
   ```bash
   chmod +r /path/to/your/capture.pcap
   ```

3. If you encounter "permission denied" errors, try:
   ```bash
   sudo python scripts/simple_pcap_analysis.py /path/to/your/capture.pcap
   ```

### Module Import Errors

If you see errors like `No module named 'wireshark_mcp.protocols'`:

1. Make sure you're using the correct installation method (see "Alternate Installation Method" above)
2. Verify PYTHONPATH includes the Wireshark-mcp directory
3. Make sure all dependencies are installed

### Package Structure Issues

If you encounter errors related to package installation (like multiple top-level packages):

1. Use the "Alternate Installation Method" above
2. Try the simple analysis script which doesn't rely on the package structure

## Getting More Help

If you encounter persistent issues:

1. Check the error message carefully for clues
2. Look at the [GitHub issues](https://github.com/sarthaksiddha/Wireshark-mcp/issues) to see if others have had similar problems
3. Create a new issue with detailed information about your environment and the error messages