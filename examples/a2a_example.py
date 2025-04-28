"""
Example usage of the Wireshark MCP A2A module.
This script demonstrates how to use the Wireshark MCP A2A module for
packet analysis and agent communication.
"""

import json
import logging
import os
import sys
from typing import Dict, Any

# Add the parent directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from wireshark_mcp.core import WiresharkMCP
from wireshark_mcp.a2a.agent import WiresharkA2AAgent, Message, Role, TextPart, TaskState
from wireshark_mcp.a2a.server import WiresharkA2AServer
from wireshark_mcp.a2a.integration import WiresharkA2AIntegration


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def example_1_basic_task():
    """Example 1: Creating and processing a basic task."""
    print("\n=== Example 1: Basic Task ===\n")
    
    # Initialize components
    pcap_path = input("Enter a path to a PCAP file (or press Enter to skip): ").strip()
    if pcap_path and os.path.exists(pcap_path):
        wireshark_mcp = WiresharkMCP(pcap_path=pcap_path)
    else:
        print("No valid PCAP file provided, some functionality will be limited.")
        wireshark_mcp = None
    
    agent = WiresharkA2AAgent(
        name="Wireshark MCP Agent",
        description="An A2A agent for analyzing network traffic using Wireshark"
    )
    server = WiresharkA2AServer(agent)
    
    # Create a task with a simple message
    message = Message(
        role=Role.USER,
        parts=[TextPart(text="Analyze network traffic")]
    )
    
    # Send the task to the server
    response, status_code = server.handle_tasks_send({
        "message": message.__dict__
    })
    
    print(f"Task created with ID: {response.get('task_id')}")
    print(f"Task state: {response.get('state')}")
    print(f"Response status code: {status_code}")
    
    # Get the task details
    task_id = response.get('task_id')
    task_response, _ = server.handle_tasks_get(task_id, {})
    
    print("\nTask details:")
    print(json.dumps(task_response, indent=2))


def example_2_pcap_analysis(pcap_path):
    """
    Example 2: Analyzing a PCAP file.
    
    Args:
        pcap_path: Path to the PCAP file
    """
    print("\n=== Example 2: PCAP Analysis ===\n")
    
    if not os.path.exists(pcap_path):
        print(f"Error: PCAP file not found: {pcap_path}")
        return
    
    # Initialize components
    wireshark_mcp = WiresharkMCP(pcap_path=pcap_path)
    agent = WiresharkA2AAgent(
        name="Wireshark MCP Agent",
        description="An A2A agent for analyzing network traffic using Wireshark"
    )
    server = WiresharkA2AServer(agent)
    integration = WiresharkA2AIntegration(wireshark_mcp, agent)
    
    # Create a task with a message to analyze the PCAP file
    message = Message(
        role=Role.USER,
        parts=[TextPart(text=f"Analyze PCAP file: {pcap_path}")]
    )
    
    # Send the task to the server
    response, status_code = server.handle_tasks_send({
        "message": message.__dict__
    })
    
    task_id = response.get('task_id')
    print(f"Task created with ID: {task_id}")
    
    # Analyze the PCAP file
    analysis_result = integration.analyze_packet_capture(
        file_path=pcap_path,
        analysis_type="basic",
        max_packets=1000
    )
    
    # Create an artifact from the analysis result
    artifact = integration.create_artifact_from_analysis(task_id, analysis_result)
    
    if artifact:
        print(f"Created artifact with ID: {artifact.artifact_id}")
    
    # Complete the task
    agent.update_task_state(task_id, TaskState.COMPLETED)
    
    # Get the task details
    task_response, _ = server.handle_tasks_get(task_id, {})
    
    print("\nTask details after analysis:")
    print(json.dumps(task_response, indent=2))


def example_3_agent_card():
    """Example 3: Displaying the agent card."""
    print("\n=== Example 3: Agent Card ===\n")
    
    # Initialize the agent
    agent = WiresharkA2AAgent(
        name="Wireshark MCP Agent",
        description="An A2A agent for analyzing network traffic using Wireshark"
    )
    
    # Get the agent card
    card = agent.get_agent_card()
    
    print("Agent Card:")
    print(json.dumps(card, indent=2))


def example_4_agent_communication():
    """Example 4: Simulating communication between agents."""
    print("\n=== Example 4: Agent Communication ===\n")
    
    # Initialize components for Agent 1 (Wireshark Agent)
    pcap_path = input("Enter a path to a PCAP file (or press Enter to skip): ").strip()
    if pcap_path and os.path.exists(pcap_path):
        wireshark_mcp = WiresharkMCP(pcap_path=pcap_path)
    else:
        print("No valid PCAP file provided, some functionality will be limited.")
        wireshark_mcp = None
    
    agent1 = WiresharkA2AAgent(
        name="Wireshark Agent",
        description="An A2A agent for analyzing network traffic using Wireshark"
    )
    server1 = WiresharkA2AServer(agent1)
    
    # Initialize components for Agent 2 (Security Analysis Agent)
    agent2 = WiresharkA2AAgent(
        name="Security Analysis Agent",
        description="An A2A agent for security analysis of network traffic"
    )
    server2 = WiresharkA2AServer(agent2)
    
    # Agent 2 sends a request to Agent 1
    message = Message(
        role=Role.USER,
        parts=[TextPart(text="Can you provide a summary of TCP traffic?")]
    )
    
    # Agent 1 processes the request
    response1, _ = server1.handle_tasks_send({
        "message": message.__dict__
    })
    
    task_id1 = response1.get('task_id')
    print(f"Agent 1 created task with ID: {task_id1}")
    
    # Agent 1 simulates processing and responds
    response_message = Message(
        role=Role.AGENT,
        parts=[TextPart(text="Here's a summary of TCP traffic: [TCP traffic summary]")]
    )
    agent1.add_message_to_task(task_id1, response_message)
    agent1.update_task_state(task_id1, TaskState.COMPLETED)
    
    # Agent 2 retrieves the response from Agent 1
    task_response1, _ = server1.handle_tasks_get(task_id1, {})
    
    # Agent 2 processes the response and creates its own task
    last_message = task_response1.get('messages', [])[-1]
    
    if last_message.get('role') == 'agent':
        agent2_message = Message(
            role=Role.USER,
            parts=[TextPart(text=f"Analyzing TCP traffic for security issues based on: {last_message.get('parts', [])[0].get('text', '')}")]
        )
        
        response2, _ = server2.handle_tasks_send({
            "message": agent2_message.__dict__
        })
        
        task_id2 = response2.get('task_id')
        print(f"Agent 2 created task with ID: {task_id2}")
        
        # Agent 2 simulates processing and responds
        security_message = Message(
            role=Role.AGENT,
            parts=[TextPart(text="Security analysis complete. Found 2 potential issues in TCP traffic.")]
        )
        agent2.add_message_to_task(task_id2, security_message)
        agent2.update_task_state(task_id2, TaskState.COMPLETED)
        
        # Get the final task details
        task_response2, _ = server2.handle_tasks_get(task_id2, {})
        
        print("\nAgent 2 task details after analysis:")
        print(json.dumps(task_response2, indent=2))


def main():
    """Main function to run the examples."""
    print("Wireshark MCP A2A Module Examples")
    print("=================================")
    
    # Example 1: Basic Task
    example_1_basic_task()
    
    # Example 2: PCAP Analysis
    pcap_path = input("\nEnter a path to a PCAP file for analysis (or press Enter to skip): ").strip()
    if pcap_path and os.path.exists(pcap_path):
        example_2_pcap_analysis(pcap_path)
    else:
        print("Skipping PCAP analysis example as no valid file was provided.")
    
    # Example 3: Agent Card
    example_3_agent_card()
    
    # Example 4: Agent Communication
    example_4_agent_communication()


if __name__ == "__main__":
    main()
