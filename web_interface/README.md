# Wireshark MCP Web Interface

A web-based interface for the Wireshark MCP (Model Context Protocol) tool, allowing users to easily upload and analyze network packet captures and generate AI-friendly contexts for Claude.

## Features

- Upload and analyze PCAP/PCAPNG files
- Browse detected protocols
- Detailed protocol-specific analysis for HTTP, DNS, SMTP, and TLS
- Security insights and anomaly detection
- Generate optimized prompts for Claude AI
- REST API for programmatic access

## Requirements

- Python 3.8+
- Flask and dependencies (see requirements.txt)
- Wireshark/tshark installed on the system
- Wireshark MCP Python package

## Installation

1. Install the Wireshark MCP package:

```bash
pip install wireshark-mcp
```

2. Install the web interface dependencies:

```bash
cd web_interface
pip install -r requirements.txt
```

3. Make sure Wireshark/tshark is installed and accessible in your system path.

## Usage

### Starting the server

Run the Flask application:

```bash
cd web_interface
python app.py
```

This will start the web server on http://localhost:5000

### Using the web interface

1. Open your browser and navigate to http://localhost:5000
2. Upload a PCAP or PCAPNG file using the upload form
3. Once uploaded, you'll see a summary of the capture
4. Select a specific protocol to analyze in detail
5. View the protocol-specific analysis, including transactions, security insights, and more
6. Copy the generated Claude-optimized prompt to analyze with Claude AI

### API Endpoints

The web interface also provides a REST API for programmatic access:

- `GET /api/protocols/<filename>` - Get available protocols in a capture
- `GET /api/context/<filename>` - Get basic context for a capture
- `GET /api/protocol/<filename>/<protocol>` - Get protocol-specific analysis

## Deployment

For production deployment, it's recommended to use a proper WSGI server like Gunicorn:

```bash
pip install gunicorn
cd web_interface
gunicorn app:app
```

## Security Considerations

- The application stores uploaded files temporarily in a system temp directory
- Files older than 24 hours are automatically cleaned up
- Limit file sizes to prevent DOS attacks (currently set to 50MB)
- In production, consider running behind a reverse proxy like Nginx

## License

This project is licensed under the MIT License - see the LICENSE file in the main project directory for details.
