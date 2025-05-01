# Security Manager

This document provides a comprehensive guide to using the SecurityManager in Wireshark MCP for unified network data protection and secure agent communication.

## Overview

The `SecurityManager` serves as a central integration point for all security features in Wireshark MCP. It combines IP address protection, content security evaluation, message signing/verification, and security event monitoring into a cohesive security framework.

This unified approach ensures consistent security policies across your network analysis workflows and simplifies the implementation of comprehensive security controls.

## Key Components

The SecurityManager integrates several security components:

1. **IP Protection**: Anonymization and obfuscation of sensitive IP addresses
2. **Content Security**: Evaluation of content against security policies
3. **Agent Security Wrappers**: Proxy-based security for agent interactions
4. **Security Monitoring**: Centralized logging and notification of security events
5. **Message Signatures**: Secure agent-to-agent communication

## Basic Usage

Here's how to use the SecurityManager for basic security features:

```python
from wireshark_mcp import WiresharkMCP, SecurityManager, IPProtectionManager

# Initialize MCP with a packet capture
mcp = WiresharkMCP("capture.pcap")

# Create the security manager
security_manager = SecurityManager()

# Configure IP protection (choose a protection mode)
security_manager.configure_ip_protection(IPProtectionManager.PSEUDONYMIZE)

# Add specific IP ranges to protect
security_manager.add_protected_ip_range("192.168.0.0/16")
security_manager.add_protected_ip_range("10.0.0.0/8")

# Extract raw data from the packet capture
raw_context = mcp.generate_context()

# Apply IP protection to all packets
protected_packets = security_manager.protect_packets(raw_context["packets"])
raw_context["packets"] = protected_packets

# Now use the protected context for analysis
```

## Advanced Usage

### Custom Security Policies

You can add custom security policies to the SecurityManager:

```python
from wireshark_mcp.security import SecurityPolicy, SecurityRisk

# Define a custom security policy
malware_policy = SecurityPolicy(
    name="Malware Detection Policy",
    description="Detects indicators of malware in content"
)

# Add rules to the policy
def detect_malware_iocs(content):
    # Check for common malware command and control patterns
    if "beacon" in content.lower() and "interval" in content.lower():
        return SecurityRisk(
            SecurityRisk.HIGH,
            "Potential command and control beacon detected",
            "Review network flow for unusual timing patterns"
        )
    return None

malware_policy.add_rule(detect_malware_iocs, "Detect C2 beaconing")

# Add the policy to the security manager
security_manager.add_security_policy(malware_policy)

# Now evaluate content against all policies including the custom one
risks = security_manager.evaluate_content_security("Analysis shows a regular beacon interval of 60 seconds to external IP.")

# Check for identified risks
for risk in risks:
    print(f"{risk.severity}: {risk.description}")
    print(f"Remediation: {risk.remediation}")
```

### Securing Agent Communication

The SecurityManager provides methods for securing agent-to-agent communication:

```python
from wireshark_mcp import SecurityManager

# Create security managers for two agents
security_manager_a = SecurityManager()
security_manager_b = SecurityManager()

# Agent A: Create and sign a message
message = "Critical security finding: DNS tunneling detected at 15:45:22"
signature_data = security_manager_a.sign_message(message, algorithm="hmac-sha256")

# Send message and signature_data to Agent B
# ...

# Agent B: Verify the message signature
if security_manager_b.verify_message(message, signature_data):
    # Process the verified message
    process_secure_message(message)
else:
    # Handle potential tampering
    report_security_incident("Message verification failed")

# For shared key verification:
key_id = signature_data.get("key_id")
if key_id:
    # Exchange the key securely between agents (out of band)
    security_manager_b.hmac_keys[key_id] = shared_secret
```

### Wrapping Agents with Security Controls

The SecurityManager can create secure wrappers around agents:

```python
from my_agent_lib import NetworkAnalysisAgent

# Create a security manager
security_manager = SecurityManager()

# Create an agent instance
network_agent = NetworkAnalysisAgent()

# Wrap the agent with security controls
secured_agent = security_manager.create_agent_wrapper(network_agent)

# Now use the secured agent
# It will automatically apply content security checks
# and protect sensitive information
input_message = "Please analyze traffic from 192.168.1.45 to 10.0.0.5"
secured_message, is_safe, risks = secured_agent.secure_input(input_message)

if is_safe:
    # Process the message
    response = secured_agent.agent.process(secured_message)
    
    # Also secure the output
    secured_response, output_safe, output_risks = secured_agent.secure_output(response)
    
    if output_safe:
        return secured_response
    else:
        return "Response contained sensitive information and was blocked"
else:
    return "Input contained potential security risks and was blocked"
```

### Security Event Monitoring

The SecurityManager tracks security events:

```python
# Get all security events
events = security_manager.get_security_events()

# Process or display events
for event in events:
    print(f"Event Type: {event['type']}")
    print(f"Description: {event['description']}")
    print(f"Severity: {event['severity']}")
    print(f"Metadata: {event['metadata']}")
    print("---")

# Clear events after processing if needed
security_manager.clear_security_events()
```

## Integration Examples

### Example 1: Secure Network Analysis Workflow

```python
from wireshark_mcp import WiresharkMCP, SecurityManager
from wireshark_mcp.formatters import ClaudeFormatter

# Initialize components
mcp = WiresharkMCP("sensitive_capture.pcap")
security_manager = SecurityManager()

# Configure security manager
security_manager.configure_ip_protection(IPProtectionManager.PSEUDONYMIZE)
security_manager.add_protected_ip_range("192.168.0.0/16")

# Create a secure analysis workflow
def secure_analyze_capture():
    # Extract raw network data
    raw_context = mcp.generate_context()
    
    # Apply IP protection
    protected_packets = security_manager.protect_packets(raw_context["packets"])
    raw_context["packets"] = protected_packets
    
    # Perform security analysis
    security_results = mcp.security_analysis()
    
    # Also protect IPs in security results
    for alert in security_results.get("alerts", []):
        if "source_ip" in alert:
            alert["source_ip"] = security_manager.ip_protection.protect_ip(
                alert["source_ip"])
    
    # Format context for Claude
    formatter = ClaudeFormatter()
    secure_prompt = formatter.format_context(
        context=protected_context,
        security_context=security_results,
        query="What unusual patterns do you see in this traffic?"
    )
    
    # Check for any content security risks before sharing
    risks = security_manager.evaluate_content_security(secure_prompt)
    has_critical_risks = any(risk.severity in ["HIGH", "CRITICAL"] for risk in risks)
    
    if has_critical_risks:
        return "Generated content contains security risks and cannot be shared"
    
    return secure_prompt

# Use the secure workflow
secure_analysis = secure_analyze_capture()

# Save to file or send to Claude
with open("secure_analysis.md", "w") as f:
    f.write(secure_analysis)
```

### Example 2: Multi-Agent Security Analysis

```python
from wireshark_mcp import SecurityManager
from wireshark_mcp.a2a.agent import WiresharkA2AAgent

# Create a security manager for agent communication
security_manager = SecurityManager()

# Create multiple specialized agents
agents = {
    "traffic_analyzer": WiresharkA2AAgent(name="Traffic Analyzer"),
    "malware_detector": WiresharkA2AAgent(name="Malware Detector"),
    "anomaly_finder": WiresharkA2AAgent(name="Anomaly Finder")
}

# Wrap all agents with security
secure_agents = {}
for name, agent in agents.items():
    secure_agents[name] = security_manager.create_agent_wrapper(agent)

# Create a secure multi-agent workflow
def secure_multi_agent_analysis(packet_data):
    results = {}
    
    # First agent: Traffic analysis
    traffic_message = f"Analyze traffic patterns in: {packet_data}"
    traffic_signature = security_manager.sign_message(traffic_message)
    
    # Send to traffic analyzer
    traffic_agent = secure_agents["traffic_analyzer"]
    if traffic_agent.verify_message_signature(traffic_message, traffic_signature):
        traffic_result = traffic_agent.agent.analyze(packet_data)
        results["traffic"] = traffic_result
        
        # Sign the result
        result_signature = security_manager.sign_message(traffic_result)
        
        # Pass to malware detector with signature
        malware_agent = secure_agents["malware_detector"]
        if malware_agent.verify_message_signature(traffic_result, result_signature):
            malware_result = malware_agent.agent.detect_malware(traffic_result)
            results["malware"] = malware_result
            
            # Similarly for anomaly finder
            # ...
    
    return results
```

## Security Best Practices

1. **Unified Protection**: Use the SecurityManager to ensure consistent protection across all aspects of your network analysis.

2. **Defense in Depth**: Combine multiple security features - IP protection, content security, and message signatures.

3. **Monitor Security Events**: Regularly review security events logged by the manager to detect potential issues.

4. **Appropriate Protection Levels**: Choose the right level of protection based on the sensitivity of your data and your analysis needs.

5. **Secret Management**: For HMAC-based signatures, implement proper secret management (not covered by SecurityManager).

6. **Validate Before Share**: Always run content through `evaluate_content_security()` before sharing with external systems.

## Technical Details

### Security Manager Architecture

The SecurityManager follows a modular design with these components:

- **IP Protection Module**: Handles all IP address anonymization tasks
- **Security Monitor**: Centralized event logging and notification system
- **Security Policies**: Rule-based content evaluation
- **Agent Security Wrappers**: Proxy pattern implementation for agent security
- **HMAC Key Storage**: Management of cryptographic keys for secure communication

### Default Security Policies

The SecurityManager comes with these default policies:

1. **Prompt Injection Policy**: Detects attempted prompt injections in content
2. **Data Leakage Policy**: Identifies personally identifiable information (PII)

### Integration with MAESTRO Framework

The SecurityManager aligns with the MAESTRO security framework:

1. **M (Model Theft & Extraction)**: Prevents model theft through agent security
2. **A (Adversarial ML)**: Detects adversarial input patterns
3. **E (Evasion)**: Identifies potential evasion techniques 
4. **S (Social Engineering)**: Prevents social engineering through message verification
5. **T (Toxic Content Generation)**: Blocks generation of sensitive information
6. **R (Rights Violation)**: Ensures proper anonymization of sensitive data
7. **O (Overreliance)**: Monitors security events for continuous validation

## Future Enhancements

Future versions of the SecurityManager may include:

1. Role-based access control for multi-user environments
2. Integration with external key management systems
3. Advanced anomaly detection for security events
4. Compliance reporting for privacy regulations
5. Support for additional cryptographic algorithms

## Additional Resources

- [IP Protection Guide](ip_protection.md) - Detailed guide on IP address protection features
- [Message Security Signatures](security_signature.md) - Guide for secure message signing and verification
- [A2A Security Guide](agent_to_agent_integration.md) - Security considerations for A2A integration