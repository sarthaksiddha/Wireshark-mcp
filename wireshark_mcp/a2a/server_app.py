"""
Flask server application for Wireshark MCP A2A.
This module implements a Flask server that exposes A2A protocol endpoints
for the Wireshark MCP.
"""

import json
import logging
import os
from typing import Dict, Any, Tuple, Optional

from flask import Flask, request, Response, jsonify, send_from_directory
from flask_cors import CORS

from .agent import WiresharkA2AAgent
from .server import WiresharkA2AServer
from .integration import WiresharkA2AIntegration
from ..core import WiresharkMCP  # Import from core instead of wireshark


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class WiresharkA2AApp:
    """
    Flask application wrapper for Wireshark MCP A2A.
    This class initializes and configures a Flask application that exposes
    A2A protocol endpoints for the Wireshark MCP.
    """
    
    def __init__(self, pcap_path: str = None, tshark_path: str = None, host: str = "localhost", port: int = 5000, debug: bool = False):
        """
        Initialize the Flask application.
        
        Args:
            pcap_path: Path to a PCAP file to analyze (optional)
            tshark_path: Path to the tshark executable (optional)
            host: The host to run the server on
            port: The port to run the server on
            debug: Whether to run the server in debug mode
        """
        self.pcap_path = pcap_path
        self.tshark_path = tshark_path
        self.host = host
        self.port = port
        self.debug = debug
        
        # Initialize Flask app
        self.app = Flask(__name__)
        CORS(self.app)  # Enable CORS for all routes
        
        # Initialize Wireshark MCP
        if pcap_path:
            self.wireshark_mcp = WiresharkMCP(pcap_path=pcap_path, tshark_path=tshark_path)
        else:
            # If no PCAP file is provided, we'll need to handle this case
            # For now, we'll just log a warning
            logger.warning("No PCAP file provided. Some functionality may be limited.")
            self.wireshark_mcp = None
        
        # Initialize A2A agent
        self.agent = WiresharkA2AAgent(
            name="Wireshark MCP Agent",
            description="An A2A agent for analyzing network traffic using Wireshark"
        )
        
        # Initialize A2A server
        self.server = WiresharkA2AServer(self.agent)
        
        # Initialize A2A integration if Wireshark MCP is available
        if self.wireshark_mcp:
            self.integration = WiresharkA2AIntegration(self.wireshark_mcp, self.agent)
        else:
            self.integration = None
        
        # Register routes
        self._register_routes()
    
    def _register_routes(self) -> None:
        """Register Flask routes for the A2A protocol."""
        
        # Well-known agent card endpoint
        @self.app.route("/.well-known/agent.json", methods=["GET"])
        def agent_card():
            """Return the agent card in JSON format."""
            return jsonify(self.agent.get_agent_card())
        
        # A2A protocol endpoint
        @self.app.route("/a2a", methods=["POST"])
        def a2a_endpoint():
            """Handle A2A protocol requests."""
            try:
                data = request.json
                if not data:
                    return jsonify({"error": "Invalid JSON"}), 400
                
                method = data.get("method")
                params = data.get("params", {})
                
                if not method:
                    return jsonify({"error": "Method not specified"}), 400
                
                response, status_code = self.server.handle_request(method, params)
                return jsonify(response), status_code
            
            except Exception as e:
                logger.exception("Error handling A2A request")
                return jsonify({"error": str(e)}), 500
        
        # SSE endpoint for streaming
        @self.app.route("/a2a/stream", methods=["POST"])
        def a2a_stream():
            """
            Handle streaming A2A protocol requests.
            
            Note: This is a placeholder implementation and would need to be
            implemented properly using SSE (Server-Sent Events) in a real application.
            """
            return jsonify({"error": "Streaming not implemented"}), 501
        
        # Health check endpoint
        @self.app.route("/health", methods=["GET"])
        def health_check():
            """Return the health status of the server."""
            return jsonify({"status": "ok"}), 200
        
        # Documentation endpoint
        @self.app.route("/", methods=["GET"])
        def documentation():
            """Return a simple HTML page with documentation."""
            return """
            <html>
                <head>
                    <title>Wireshark MCP A2A Server</title>
                    <style>
                        body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
                        h1 { color: #333; }
                        h2 { color: #555; margin-top: 20px; }
                        pre { background-color: #f5f5f5; padding: 10px; border-radius: 5px; }
                    </style>
                </head>
                <body>
                    <h1>Wireshark MCP A2A Server</h1>
                    <p>This server implements the A2A protocol for the Wireshark MCP.</p>
                    
                    <h2>Agent Card</h2>
                    <p>The agent card is available at <a href="/.well-known/agent.json">/.well-known/agent.json</a></p>
                    
                    <h2>A2A Endpoint</h2>
                    <p>The A2A endpoint is available at <code>/a2a</code></p>
                    
                    <h2>Example Request</h2>
                    <pre>
POST /a2a HTTP/1.1
Content-Type: application/json

{
    "method": "tasks/send",
    "params": {
        "message": {
            "role": "user",
            "parts": [
                {
                    "type": "text",
                    "text": "Analyze network traffic from my PCAP file"
                }
            ]
        }
    }
}
                    </pre>
                </body>
            </html>
            """
    
    def run(self) -> None:
        """Run the Flask application."""
        self.app.run(host=self.host, port=self.port, debug=self.debug)


def create_app(pcap_path: str = None, tshark_path: str = None, host: str = "localhost", port: int = 5000, debug: bool = False) -> Flask:
    """
    Create and configure the Flask application.
    
    Args:
        pcap_path: Path to a PCAP file to analyze (optional)
        tshark_path: Path to the tshark executable (optional)
        host: The host to run the server on
        port: The port to run the server on
        debug: Whether to run the server in debug mode
        
    Returns:
        The configured Flask application
    """
    app_wrapper = WiresharkA2AApp(pcap_path=pcap_path, tshark_path=tshark_path, host=host, port=port, debug=debug)
    return app_wrapper.app


if __name__ == "__main__":
    # Create and run the app
    app_wrapper = WiresharkA2AApp(debug=True)
    app_wrapper.run()
