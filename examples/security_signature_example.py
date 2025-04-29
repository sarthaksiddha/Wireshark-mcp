#!/usr/bin/env python3
"""
Example demonstrating the use of message signatures in Wireshark MCP.

This example shows how to use the generate_message_signature method to create
secure signatures for agent-to-agent communication, and how to verify those
signatures to ensure message integrity and authenticity.
"""

import os
import sys
import json
import time
import logging
from typing import Dict, Any

# Add the parent directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the security module
from wireshark_mcp.security import (
    AgentSecurityWrapper,
    SecurityMonitor,
    DEFAULT_SECURITY_POLICIES
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def print_separator(title: str = None):
    """Print a separator line with an optional title."""
    print("\n" + "=" * 80)
    if title:
        print(f"{title.center(80)}")
        print("=" * 80)
    print()


def example_1_basic_signature():
    """Example 1: Basic message signature generation and verification."""
    print_separator("Example 1: Basic Message Signatures")
    
    # Create a mock agent and security wrapper
    class MockAgent:
        def __init__(self, name: str):
            self.name = name
    
    agent = MockAgent("Agent1")
    security_monitor = SecurityMonitor()
    security_wrapper = AgentSecurityWrapper(
        agent=agent,
        security_monitor=security_monitor,
        policies=DEFAULT_SECURITY_POLICIES
    )
    
    # Create a test message
    message = "Hello, this is a secure message from Agent1."
    
    # Generate a signature using the default settings (HMAC-SHA256 with timestamp)
    print("Generating signature with default settings (HMAC-SHA256 with timestamp)...")
    signature_data = security_wrapper.generate_message_signature(message)
    
    # Print the signature data
    print("\nSignature Data:")
    print(json.dumps(signature_data, indent=2))
    
    # Verify the signature
    print("\nVerifying signature...")
    is_valid = security_wrapper.verify_message_signature(message, signature_data)
    print(f"Signature valid: {is_valid}")
    
    # Try to verify a tampered message
    print("\nTrying to verify a tampered message...")
    tampered_message = message + " This part was added by an attacker."
    is_valid = security_wrapper.verify_message_signature(tampered_message, signature_data)
    print(f"Tampered message signature valid: {is_valid}")


def example_2_algorithm_options():
    """Example 2: Comparing different signature algorithms."""
    print_separator("Example 2: Comparing Different Signature Algorithms")
    
    # Create a mock agent and security wrapper
    class MockAgent:
        def __init__(self, name: str):
            self.name = name
    
    agent = MockAgent("Agent2")
    security_monitor = SecurityMonitor()
    security_wrapper = AgentSecurityWrapper(
        agent=agent,
        security_monitor=security_monitor,
        policies=DEFAULT_SECURITY_POLICIES
    )
    
    # Create a test message
    message = "This message will be signed with different algorithms."
    
    # Test different algorithms
    algorithms = ["sha256", "sha512", "hmac-sha256", "hmac-sha512"]
    
    for algorithm in algorithms:
        print(f"\nTesting algorithm: {algorithm}")
        
        # Generate a signature with the current algorithm
        signature_data = security_wrapper.generate_message_signature(
            message=message,
            algorithm=algorithm,
            include_timestamp=True
        )
        
        # Print the signature data
        print(f"Signature data size: {len(json.dumps(signature_data))} bytes")
        print(f"Signature value: {signature_data['signature'][:20]}... (truncated)")
        
        # Verify the signature
        is_valid = security_wrapper.verify_message_signature(message, signature_data)
        print(f"Signature valid: {is_valid}")


def example_3_agent_to_agent_communication():
    """Example 3: Simulating secure agent-to-agent communication."""
    print_separator("Example 3: Secure Agent-to-Agent Communication")
    
    # Create two mock agents and their security wrappers
    class MockAgent:
        def __init__(self, name: str):
            self.name = name
            self.received_messages = []
        
        def receive_message(self, message: str, sender: str, signature_data: Dict[str, Any] = None):
            self.received_messages.append({
                "message": message,
                "sender": sender,
                "signature_data": signature_data,
                "timestamp": time.time()
            })
            return f"Received message from {sender}: {message[:30]}..."
    
    # Create Agent A
    agent_a = MockAgent("AgentA")
    security_monitor_a = SecurityMonitor()
    security_wrapper_a = AgentSecurityWrapper(
        agent=agent_a,
        security_monitor=security_monitor_a,
        policies=DEFAULT_SECURITY_POLICIES
    )
    
    # Create Agent B
    agent_b = MockAgent("AgentB")
    security_monitor_b = SecurityMonitor()
    security_wrapper_b = AgentSecurityWrapper(
        agent=agent_b,
        security_monitor=security_monitor_b,
        policies=DEFAULT_SECURITY_POLICIES
    )
    
    # Generate a shared secret key for both agents
    shared_secret = "supersecretkey123"  # In a real system, use a secure key exchange
    
    print("Simulating secure communication between AgentA and AgentB")
    
    # AgentA sends a message to AgentB
    message_from_a = "Hello AgentB, here's some confidential data: XYZ-123."
    print(f"\nAgentA -> AgentB: {message_from_a}")
    
    # AgentA signs the message
    signature_data = security_wrapper_a.generate_message_signature(
        message=message_from_a,
        key=shared_secret,
        algorithm="hmac-sha256"
    )
    
    print("Message signed by AgentA:")
    print(json.dumps(signature_data, indent=2))
    
    # Simulate message transmission
    print("\nTransmitting message over the network...")
    
    # AgentB receives and verifies the message
    print("\nAgentB verifying the message signature...")
    
    # In a real implementation, AgentB would need to register the shared secret
    security_wrapper_b.secrets[signature_data["key_id"]] = shared_secret
    
    is_valid = security_wrapper_b.verify_message_signature(message_from_a, signature_data)
    print(f"Signature valid: {is_valid}")
    
    if is_valid:
        # Process the message only if the signature is valid
        agent_b.receive_message(message_from_a, "AgentA", signature_data)
        print(f"AgentB has processed the message from AgentA")
        print(f"AgentB received messages: {len(agent_b.received_messages)}")
    else:
        print("AgentB rejected the message due to invalid signature")


def example_4_message_expiration():
    """Example 4: Message expiration based on timestamp."""
    print_separator("Example 4: Message Expiration")
    
    # Create mock agents
    class MockAgent:
        def __init__(self, name: str):
            self.name = name
    
    agent = MockAgent("TimeAgent")
    security_monitor = SecurityMonitor()
    security_wrapper = AgentSecurityWrapper(
        agent=agent,
        security_monitor=security_monitor,
        policies=DEFAULT_SECURITY_POLICIES
    )
    
    # Create a test message
    message = "This message will expire after a short time."
    
    # Generate a signature with a custom timestamp (5 minutes in the past)
    current_time = int(time.time())
    past_time = current_time - (5 * 60)  # 5 minutes ago
    
    # Override the current time function for the test
    original_time = time.time
    try:
        # First, set the time to 5 minutes ago to create the signature
        time.time = lambda: past_time
        
        print("Generating signature with timestamp from 5 minutes ago...")
        signature_data = security_wrapper.generate_message_signature(message)
        print(f"Signature timestamp: {signature_data['timestamp']} ({time.ctime(signature_data['timestamp'])})")
        
        # Now, restore the current time to verify with current time
        time.time = original_time
        
        print(f"\nCurrent time: {current_time} ({time.ctime(current_time)})")
        print("Verifying signature with current time...")
        
        # The default expiration is 5 minutes, so this should fail
        is_valid = security_wrapper.verify_message_signature(message, signature_data)
        print(f"Signature valid: {is_valid} (Expected: False due to expiration)")
        
    finally:
        # Restore the original time function
        time.time = original_time


def main():
    """Main function to run the examples."""
    print("Wireshark MCP Security Signature Examples")
    print("=========================================")
    
    # Run the examples
    example_1_basic_signature()
    example_2_algorithm_options()
    example_3_agent_to_agent_communication()
    example_4_message_expiration()
    
    print("\nAll examples completed.")


if __name__ == "__main__":
    main()
