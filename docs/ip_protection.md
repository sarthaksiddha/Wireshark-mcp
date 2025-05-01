# IP Address Protection in Wireshark MCP

This document explains how to use the IP address protection features in Wireshark MCP to ensure network analysis can be performed while preserving privacy and confidentiality of sensitive network information.

## Overview

The `IPProtectionManager` provides a robust framework for anonymizing, obfuscating, or redacting IP addresses within packet captures. This is essential when:

- Working with packet captures containing sensitive network data
- Sharing network analysis with third parties
- Complying with privacy regulations like GDPR or HIPAA
- Creating public examples or demonstrations
- Analyzing network traffic in multi-tenant environments

## Key Features

- **Multiple Protection Strategies**: Choose from different levels of IP address obfuscation
- **Consistent Pseudonymization**: Replace real IPs with consistent alternatives for meaningful analysis
- **Configurable Network Preservation**: Keep network structure while hiding host identities
- **IPv4 and IPv6 Support**: Comprehensive protection for all IP versions
- **Protected Range Configuration**: Specify which networks require protection

## Protection Modes

The `IPProtectionManager` offers four protection modes, each with different levels of obfuscation:

1. **REDACT_FULL**: Completely replaces the IP address with a marker
   - Example: `192.168.1.45` → `[REDACTED]`
   - Best for: Maximum privacy when IP details are irrelevant

2. **REDACT_HOST**: Preserves network portion but redacts host identifiers
   - Example: `192.168.1.45` → `192.168.[x].[x]`
   - Best for: Maintaining network context while hiding specific hosts

3. **PSEUDONYMIZE**: Replaces IPs with consistent pseudonyms
   - Example: `192.168.1.45` → `10.0.0.12` (consistent throughout analysis)
   - Best for: Detailed analysis requiring host tracking without revealing true identities

4. **PARTIAL_MASK**: Masks only part of the IP address
   - Example: `192.168.1.45` → `192.168.x.45`
   - Best for: Lightweight obfuscation when full protection isn't required

## Basic Usage

Here's how to use IP protection in your Wireshark MCP analysis:

```python
from wireshark_mcp import WiresharkMCP, IPProtectionManager

# Initialize the MCP
mcp = WiresharkMCP("capture.pcap")

# Create an IP Protection Manager with default mode (PARTIAL_MASK)
ip_protector = IPProtectionManager()

# Extract context
raw_context = mcp.generate_context()

# Apply protection to all packets in the context
protected_packets = []
for packet in raw_context["packets"]:
    protected_packet = ip_protector.protect_packet(packet)
    protected_packets.append(protected_packet)

# Replace the raw packets with protected ones
raw_context["packets"] = protected_packets

# Now use the protected context for analysis or sharing
```

## Advanced Usage

### Using Different Protection Modes

```python
from wireshark_mcp import IPProtectionManager

# Create protectors with different modes
full_redactor = IPProtectionManager(IPProtectionManager.REDACT_FULL)
network_preserver = IPProtectionManager(IPProtectionManager.REDACT_HOST)
pseudonymizer = IPProtectionManager(IPProtectionManager.PSEUDONYMIZE)
partial_masker = IPProtectionManager(IPProtectionManager.PARTIAL_MASK)

# Apply different protection strategies to the same packet
fully_redacted = full_redactor.protect_packet(packet)
network_preserved = network_preserver.protect_packet(packet)
pseudonymized = pseudonymizer.protect_packet(packet)
partially_masked = partial_masker.protect_packet(packet)
```

### Specifying Protected IP Ranges

```python
# Create a protection manager
ip_protector = IPProtectionManager(IPProtectionManager.PSEUDONYMIZE)

# Configure specific ranges to protect
ip_protector.add_protected_range("192.168.0.0/16")  # Private network
ip_protector.add_protected_range("10.0.0.0/8")      # Another private range
ip_protector.add_protected_range("203.0.113.0/24")  # Example public range

# Now only IPs in these ranges (plus any private IPs) will be protected
protected_packet = ip_protector.protect_packet(packet)
```

### Tracking IP Pseudonyms

When using pseudonymization, you can track the mapping between original IPs and their pseudonyms:

```python
# Create a pseudonymizing protector
ip_protector = IPProtectionManager(IPProtectionManager.PSEUDONYMIZE)

# Protect packets
protected_packets = [ip_protector.protect_packet(p) for p in packets]

# Get the mapping of original IPs to pseudonyms
mapping = ip_protector.get_ip_mapping()
print("IP Mapping:")
for original_ip, pseudonym in mapping.items():
    print(f"  {original_ip} -> {pseudonym}")

# Reset the mapping if needed for a new analysis
ip_protector.reset_mapping()
```

## Integration with Security Manager

The `IPProtectionManager` is fully integrated with the `SecurityManager` for a unified security approach:

```python
from wireshark_mcp import WiresharkMCP, SecurityManager

# Initialize MCP and the security manager
mcp = WiresharkMCP("capture.pcap")
security_manager = SecurityManager()

# Configure IP protection
security_manager.configure_ip_protection(mode=IPProtectionManager.PSEUDONYMIZE)
security_manager.add_protected_ip_range("192.168.0.0/16")

# Extract and protect context
raw_context = mcp.generate_context()
protected_packets = security_manager.protect_packets(raw_context["packets"])
raw_context["packets"] = protected_packets

# Continue with protected analysis
```

## Practical Examples

### Example 1: Creating a Shareable Network Diagram

```python
from wireshark_mcp import WiresharkMCP, IPProtectionManager
from wireshark_mcp.formatters import NetworkDiagramFormatter

# Create MCP and extract flows
mcp = WiresharkMCP("sensitive_capture.pcap")
flows = mcp.extract_flows()

# Create a protector that preserves network structure but hides hosts
protector = IPProtectionManager(IPProtectionManager.REDACT_HOST)

# Protect the flow data
for flow in flows["flows"]:
    flow["src_ip"] = protector.protect_ip(flow["src_ip"])
    flow["dst_ip"] = protector.protect_ip(flow["dst_ip"])

# Generate a network diagram with protected IPs
diagram_formatter = NetworkDiagramFormatter()
shareable_diagram = diagram_formatter.format_flows(flows)

# Save to file
with open("shareable_network_diagram.md", "w") as f:
    f.write(shareable_diagram)
```

### Example 2: Analyzing Security Incidents Safely

```python
from wireshark_mcp import WiresharkMCP, SecurityManager
from wireshark_mcp.formatters import ClaudeFormatter

# Initialize components
mcp = WiresharkMCP("security_incident.pcap")
security_manager = SecurityManager()

# Use pseudonymization to maintain analysis capability while hiding real IPs
security_manager.configure_ip_protection(mode=IPProtectionManager.PSEUDONYMIZE)

# Perform security analysis
security_results = mcp.security_analysis()

# Protect all IP addresses in the results
for alert in security_results["alerts"]:
    if "source_ip" in alert:
        alert["source_ip"] = security_manager.ip_protection.protect_ip(alert["source_ip"])
    if "details" in alert and "ip" in alert["details"]:
        alert["details"]["ip"] = security_manager.ip_protection.protect_ip(alert["details"]["ip"])

# Format for Claude
formatter = ClaudeFormatter()
secure_prompt = formatter.format_security_context(
    security_results,
    query="Analyze these security alerts while respecting IP confidentiality"
)

# Save secure prompt
with open("secure_prompt.md", "w") as f:
    f.write(secure_prompt)
```

## Best Practices

1. **Choose the Right Protection Mode**: Select the least restrictive mode that meets your privacy requirements.

2. **Consistency is Key**: Use the same IPProtectionManager instance for all packets in a session to ensure consistent pseudonymization.

3. **Document Your Approach**: When sharing protected analysis, document which protection methods were used.

4. **Preserve Analysis Value**: Balance privacy needs with maintaining enough information for meaningful analysis.

5. **Guard the IP Mapping**: If using pseudonymization, the mapping between real and pseudonymized IPs should be protected as sensitive information.

## Technical Details

### Protection of IPv6 Addresses

The protection strategies work differently for IPv6 addresses:

- **REDACT_FULL**: Replaced with `[REDACTED_IPV6]`
- **REDACT_HOST**: Preserves the first 4 hextets, redacts the last 4
- **PSEUDONYMIZE**: Uses the `fd00::` prefix (ULA) with a unique suffix
- **PARTIAL_MASK**: Masks the middle 4 hextets with 'x'

### Automatic Detection of Private IPs

By default, all private IP ranges (as defined by RFC 1918 and RFC 4193) are automatically protected, even without explicitly adding them as protected ranges.

## Security Considerations

While IP address protection provides significant privacy benefits, users should be aware of certain limitations:

1. **Correlation Attacks**: If enough network context is preserved, it might still be possible to identify certain hosts based on their behavior patterns.

2. **Protection Scope**: This system protects IP addresses but not other potentially identifying information in packet payloads.

3. **Pseudonym Consistency**: The pseudonymization is consistent within a single analysis session but not across different runs unless the same IP protector instance is reused.

## Future Enhancements

Future versions of the IP protection system may include:

1. Advanced payload inspection to find and protect IPs in packet content
2. Configurable pseudonymization patterns
3. Persistent mapping files for consistent pseudonymization across sessions
4. Geographic preservation (maintaining approximate location relationships)
5. Integration with other anonymization techniques for comprehensive privacy

## Integration with MAESTRO Framework

This protection feature aligns with multiple aspects of the MAESTRO security framework:

1. **M (Model Theft & Extraction)**: Prevents leakage of sensitive network topology
2. **S (Social Engineering)**: Reduces the risk of network information being used for targeted attacks
3. **T (Toxic Content Generation)**: Prevents generation of analysis containing sensitive IP data
4. **R (Rights Violation)**: Helps maintain privacy and confidentiality of network data