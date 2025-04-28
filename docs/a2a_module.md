# Wireshark MCP A2A Module Documentation

## Overview

The A2A (Agent-to-Agent) module for Wireshark MCP enables communication between Wireshark's packet analysis capabilities and other AI agents using Google's A2A protocol. This module allows Wireshark MCP to expose its network traffic analysis features through a standardized interface that other agents can discover and interact with.

## Key Components

The A2A module consists of several key components:

### 1. WiresharkA2AAgent

The `WiresharkA2AAgent` class represents a Wireshark agent that can communicate using the A2A protocol. It manages tasks, messages, and artifacts, and defines the skills that the agent can perform.

Key features:
- Maintains a collection of tasks
- Exposes network analysis capabilities as A2A skills
- Generates an agent card for discovery
- Manages the lifecycle of tasks and their states

### 2. WiresharkA2AServer

The `WiresharkA2AServer` class implements the server-side components of the A2A protocol. It handles incoming A2A protocol requests and delegates them to the appropriate handlers.

Key features:
- Processes A2A protocol methods (tasks/send, tasks/get, etc.)
- Manages task creation and updates
- Exposes the agent card for discovery
- Handles streaming and push notifications (when implemented)

### 3. WiresharkA2AIntegration

The `WiresharkA2AIntegration` class provides the integration between Wireshark's packet analysis capabilities and the A2A protocol structures. It translates between Wireshark MCP contexts and A2A-compatible formats.

Key features:
- Converts Wireshark packet analysis data to A2A artifacts
- Generates insights from packet captures
- Creates A2A artifacts from analysis results

### 4. Flask Server Application

The `WiresharkA2AApp` class provides a Flask web server that exposes the A2A protocol endpoints. It initializes all the necessary components and handles HTTP requests.

Key features:
- Exposes A2A protocol endpoints (/a2a)
- Serves the agent card at the well-known location (/.well-known/agent.json)
- Provides health check and documentation endpoints

### 5. Command-Line Interface

The `cli.py` module provides a command-line interface for interacting with the A2A functionality of Wireshark MCP.

Key features:
- Start the A2A server
- Get the agent card
- Analyze PCAP files
- List available skills

## Installation

To use the A2A module, ensure you have the required dependencies installed:

```bash
pip install -r requirements.txt
```

## Usage

### Starting the A2A Server

To start the A2A server, use the command-line interface:

```bash
python -m wireshark_mcp.a2a.cli server --pcap-file path/to/capture.pcap
```

This will start a Flask server that exposes the A2A protocol endpoints, allowing other agents to connect and use Wireshark's analysis capabilities.

### Using the A2A Agent Programmatically

You can use the A2A agent programmatically in your Python code:

```python
from wireshark_mcp.core import WiresharkMCP
from wireshark_mcp.a2a.agent import WiresharkA2AAgent, Message, Role, TextPart
from wireshark_mcp.a2a.server import WiresharkA2AServer
from wireshark_mcp.a2a.integration import WiresharkA2AIntegration

# Initialize components
wireshark_mcp = WiresharkMCP(pcap_path="capture.pcap")
agent = WiresharkA2AAgent(
    name="Wireshark MCP Agent",
    description="An A2A agent for analyzing network traffic using Wireshark"
)
server = WiresharkA2AServer(agent)
integration = WiresharkA2AIntegration(wireshark_mcp, agent)

# Create a task with a message
message = Message(
    role=Role.USER,
    parts=[TextPart(text="Analyze network traffic from capture.pcap")]
)
response, status_code = server.handle_tasks_send({
    "message": message.__dict__
})

task_id = response.get('task_id')

# Analyze a PCAP file
analysis_result = integration.analyze_packet_capture(
    file_path="capture.pcap",
    analysis_type="basic",
    max_packets=1000
)

# Create an artifact from the analysis result
artifact = integration.create_artifact_from_analysis(task_id, analysis_result)
```

### Using the CLI to Analyze PCAP Files

You can use the command-line interface to analyze PCAP files:

```bash
python -m wireshark_mcp.a2a.cli analyze path/to/capture.pcap --analysis-type basic --output results.json
```

### Listing Available Skills

To see what skills the A2A agent provides, use the CLI:

```bash
python -m wireshark_mcp.a2a.cli skills
```

## A2A Protocol Support

The A2A module implements the following A2A protocol methods:

- `agent/card`: Get the agent card
- `tasks/send`: Create a new task or add a message to an existing task
- `tasks/get`: Get the details of a task
- `tasks/cancel`: Cancel a task

Future versions will implement:
- `tasks/sendSubscribe`: Create a task with streaming updates
- `tasks/pushNotification/set`: Configure push notifications for task updates

## Integration with Other Agents

The A2A module allows other agents to discover and interact with Wireshark MCP. To connect to the Wireshark MCP A2A server from another agent:

1. Discover the agent by fetching the agent card from `/.well-known/agent.json`
2. Use the agent's endpoint (`/a2a`) to send A2A protocol requests
3. Create tasks to analyze network traffic
4. Retrieve the results as A2A artifacts

## Agent Capabilities

The Wireshark MCP A2A agent exposes the following skills:

- `analyze_packet_capture`: Analyze a packet capture file (PCAP) and provide insights
- `capture_live_traffic`: Capture live network traffic
- `detect_anomalies`: Detect anomalies in network traffic

## Examples

See the `examples/a2a_example.py` file for examples of how to use the A2A module. This example demonstrates:

1. Creating and processing a basic A2A task
2. Analyzing a PCAP file and generating artifacts
3. Displaying an agent card
4. Simulating communication between agents

To run the example:

```bash
python examples/a2a_example.py
```

## Security Considerations

When implementing A2A communication, it's important to consider security risks and mitigations. For detailed information on securing A2A integrations, see the [Agent-to-Agent (A2A) Integration Guide](agent_to_agent_integration.md).

Some key security aspects to consider:

1. **Message Integrity and Authentication**: Ensure messages between agents can't be tampered with or spoofed.
2. **Prompt Injection Protection**: Implement defenses against malicious inputs that might manipulate agent behavior.
3. **Information Leakage Prevention**: Prevent sensitive information from being inappropriately shared between agents.
4. **Permission-Based Access Controls**: Implement least-privilege access controls for agent operations.
5. **Input Validation and Sanitization**: Validate and sanitize all inputs between agents.

## Advanced Features

### Custom Analysis Pipelines

You can create custom analysis pipelines by chaining A2A agents together. For example:

```python
# Create a pipeline of specialized agents
network_agent = create_network_agent()
security_agent = create_security_agent()
visualization_agent = create_visualization_agent()

# Connect the agents
network_agent.add_peer(security_agent)
security_agent.add_peer(visualization_agent)

# Start the analysis pipeline
network_agent.start_analysis("capture.pcap")
```

### Real-Time Streaming

For long-running analysis tasks, you can use the streaming capabilities of the A2A protocol:

```python
# Create a streaming task
response = client.create_streaming_task(
    message="Analyze network traffic in real-time",
    callback=on_update
)

# Process streaming updates
def on_update(update):
    if update.type == "status":
        print(f"Task status: {update.status}")
    elif update.type == "artifact":
        process_artifact(update.artifact)
```

## Troubleshooting

Common issues and their solutions:

### Connection Issues

If you're having trouble connecting to the A2A server:

1. Ensure the server is running (`python -m wireshark_mcp.a2a.cli server`)
2. Check that the host and port are correct
3. Verify that there are no firewall rules blocking the connection

### PCAP Analysis Issues

If PCAP analysis is failing:

1. Ensure the PCAP file exists and is accessible
2. Check that tshark is installed and in your PATH
3. Try a different PCAP file to see if the issue is with the specific file

### Task Processing Issues

If tasks are not being processed correctly:

1. Check the task state to see if it's in an error state
2. Look for error messages in the task object
3. Enable debug logging for more detailed information

## Contributing

Contributions to the A2A module are welcome! Please ensure that your code passes all tests and follows the project's coding style.

To contribute:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for your changes
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
