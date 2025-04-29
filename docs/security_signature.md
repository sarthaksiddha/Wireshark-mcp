# Message Signature Security

This document provides detailed information on how to use the message signature security features in Wireshark MCP for secure agent-to-agent communication.

## Overview

Wireshark MCP provides robust message signing and verification mechanisms to ensure the integrity and authenticity of communications between agents. This is particularly important in distributed systems where multiple AI agents or components need to communicate securely.

The `generate_message_signature` method and its companion `verify_message_signature` method provide cryptographic guarantees that:

1. Messages have not been tampered with (integrity)
2. Messages come from the expected source (authenticity)
3. Messages are not replays of previously sent messages (freshness)

## Key Features

- Multiple hashing algorithms (SHA-256, SHA-512, HMAC-SHA-256, HMAC-SHA-512)
- Timestamp-based message expiration to prevent replay attacks
- Flexible key management for HMAC-based signatures
- Detailed signature metadata for robust verification
- Comprehensive security logging

## Basic Usage

Here's how to implement message signing and verification in your agent-to-agent communication:

```python
from wireshark_mcp.security import AgentSecurityWrapper, SecurityMonitor

# Create security components
security_monitor = SecurityMonitor()
wrapper = AgentSecurityWrapper(agent=my_agent, security_monitor=security_monitor)

# Sender: Generate a signature for a message
message = "Critical security alert: Potential DNS tunneling detected at 15:42:30"
signature_data = wrapper.generate_message_signature(message)

# Send both the message and the signature_data to the recipient

# Receiver: Verify the received message
if wrapper.verify_message_signature(message, signature_data):
    # Message is authentic, process it
    process_verified_message(message)
else:
    # Message failed verification, handle accordingly
    handle_tampered_message(message)
```

## Advanced Usage

### Using Different Hash Algorithms

```python
# Generate signature with SHA-256 (no HMAC)
signature_data = wrapper.generate_message_signature(
    message=message,
    algorithm="sha256"
)

# Generate signature with SHA-512 (no HMAC)
signature_data = wrapper.generate_message_signature(
    message=message,
    algorithm="sha512"
)

# Generate signature with HMAC-SHA-256 (default)
signature_data = wrapper.generate_message_signature(
    message=message,
    algorithm="hmac-sha256"
)

# Generate signature with HMAC-SHA-512
signature_data = wrapper.generate_message_signature(
    message=message,
    algorithm="hmac-sha512"
)
```

### Using Shared Secret Keys

For HMAC-based algorithms, you can provide a shared secret key:

```python
# Generate signature with a custom shared secret
shared_secret = "supersecretkey123"  # Use a secure method to share this key
signature_data = wrapper.generate_message_signature(
    message=message,
    key=shared_secret,
    algorithm="hmac-sha256"
)

# Send the message and signature_data to the recipient

# On the recipient side, register the shared secret with the same key_id
recipient_wrapper.secrets[signature_data["key_id"]] = shared_secret

# Now verify with the shared secret
is_valid = recipient_wrapper.verify_message_signature(message, signature_data)
```

### Timestamp-Based Expiration

By default, messages include a timestamp and expire after 5 minutes:

```python
# Generate signature with timestamp (default)
signature_data = wrapper.generate_message_signature(
    message=message,
    include_timestamp=True  # This is the default
)

# The verification will fail if more than 5 minutes have passed
# This helps prevent replay attacks
```

If you don't want message expiration:

```python
# Generate signature without timestamp
signature_data = wrapper.generate_message_signature(
    message=message,
    include_timestamp=False
)
```

## Security Recommendations

1. **Use HMAC-based signatures** whenever possible, as they provide stronger security guarantees than plain hash-based signatures.

2. **Keep shared secrets secure** and rotate them periodically. Never hard-code secrets in your application.

3. **Always enable timestamps** to prevent replay attacks, unless you have a specific reason not to.

4. **Monitor signature verifications** to detect potential tampering attempts. The `SecurityMonitor` logs all verification successes and failures.

5. **Use stronger algorithms** (SHA-512 variants) for higher security requirements, especially when dealing with sensitive information.

## Full Example: Secure Agent-to-Agent Communication

```python
from wireshark_mcp.security import AgentSecurityWrapper, SecurityMonitor, DEFAULT_SECURITY_POLICIES

# Setup for Agent A
agent_a = YourAgentImplementation("AgentA")
security_monitor_a = SecurityMonitor()
wrapper_a = AgentSecurityWrapper(
    agent=agent_a,
    security_monitor=security_monitor_a,
    policies=DEFAULT_SECURITY_POLICIES
)

# Setup for Agent B
agent_b = YourAgentImplementation("AgentB")
security_monitor_b = SecurityMonitor()
wrapper_b = AgentSecurityWrapper(
    agent=agent_b,
    security_monitor=security_monitor_b,
    policies=DEFAULT_SECURITY_POLICIES
)

# Generate a shared secret key for both agents
shared_secret = "supersecretkey123"  # In production, use a secure key exchange mechanism

# Agent A sending a message to Agent B
message_from_a = "Important findings: Suspicious traffic pattern detected"
signature_data = wrapper_a.generate_message_signature(
    message=message_from_a,
    key=shared_secret,
    algorithm="hmac-sha256"
)

# Simulate sending message and signature data to Agent B
# In a real system, this would involve network transmission
# ...

# Agent B receiving and verifying the message
# First, register the shared secret with the key_id from the signature data
wrapper_b.secrets[signature_data["key_id"]] = shared_secret

# Now verify the message
is_valid = wrapper_b.verify_message_signature(message_from_a, signature_data)

if is_valid:
    print("Message verified successfully!")
    agent_b.process_message(message_from_a)
else:
    print("Message verification failed!")
    security_monitor_b.log_event(
        "MESSAGE_VERIFICATION_FAILED", 
        "Received message failed signature verification",
        "HIGH"
    )
```

## API Reference

### AgentSecurityWrapper

#### `generate_message_signature(message, key=None, algorithm="hmac-sha256", include_timestamp=True)`

Generates a cryptographic signature for a message.

**Parameters**:
- `message` (str): The message to sign
- `key` (str, optional): Secret key for HMAC. If None, a secure random key is generated
- `algorithm` (str): One of "sha256", "sha512", "hmac-sha256", or "hmac-sha512"
- `include_timestamp` (bool): Whether to include a timestamp in the signature

**Returns**:
- Dictionary containing the signature and metadata:
```python
{
    'signature': '<signature value>',
    'algorithm': '<algorithm used>',
    'timestamp': <unix timestamp> (if include_timestamp is True),
    'key_id': '<key identifier>' (for HMAC algorithms)
}
```

#### `verify_message_signature(message, signature_data)`

Verifies a message against its signature.

**Parameters**:
- `message` (str): The message to verify
- `signature_data` (dict): The signature data returned by `generate_message_signature`

**Returns**:
- `bool`: True if the signature is valid, False otherwise

## Integration with MCP Threat Matrix

The message signature system addresses several key concerns in the MCP (Model Context Protocol) threat matrix:

1. **Protocol Tampering**: Signatures detect any modifications to messages
2. **Authentication Bypass**: HMAC signatures provide strong authentication
3. **Message Replay**: Timestamps prevent replay attacks
4. **Man-in-the-Middle**: Signatures ensure end-to-end integrity

## Integration with MAESTRO Framework

This security feature aligns with multiple aspects of the MAESTRO security framework:

1. **M (Model Theft & Extraction)**: Verifies authenticity of communications between models
2. **A (Adversarial ML)**: Prevents tampering with model-to-model communications
3. **S (Social Engineering)**: Reduces the risk of one agent impersonating another
4. **T (Toxic Content Generation)**: Provides accountability for message content
5. **R (Rights Violation)**: Ensures proper attribution of messages

## Future Improvements

Future enhancements to the message signature system may include:

1. Additional signature algorithms (EdDSA, ECDSA)
2. Integration with key management systems
3. Automatic key rotation policies
4. Support for signature thresholds (multi-signature)
5. Integration with DID (Decentralized Identifier) systems
