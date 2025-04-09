# Wireshark MCP Utility Scripts

This directory contains utility scripts to help with PCAP analysis and Claude integration.

## Available Scripts

### `simple_pcap_analysis.py`

This script provides a simple, reliable method to extract information from PCAP files and format it for Claude. It uses TShark directly and doesn't rely on the entire Wireshark MCP package structure, making it ideal for quick analysis or when you encounter issues with the main package.

**Usage:**
```bash
python simple_pcap_analysis.py path/to/your/capture.pcap
```

### `analyze_pcap.py`

This script analyzes PCAP files and allows you to focus on specific protocols. It uses the Wireshark MCP modules but with improved import handling to avoid common issues.

**Usage:**
```bash
python analyze_pcap.py path/to/your/capture.pcap [protocol]
```

Where `[protocol]` is an optional parameter specifying the protocol to focus on (e.g., HTTP, DNS, TLS, SMTP).

## When to Use These Scripts

- Use `simple_pcap_analysis.py` when you want a quick, reliable analysis of a PCAP file without complex setup
- Use `analyze_pcap.py` when you want more detailed protocol-specific analysis but are encountering issues with the main package

## Output

Both scripts generate a markdown file formatted for Claude that you can copy and paste into your Claude conversation. The file will be saved in the current directory with a name based on your input PCAP file.
