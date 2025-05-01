# Wireshark MCP Documentation

Welcome to the Wireshark MCP documentation. This directory contains detailed guides on installation, configuration, security features, and usage of the Wireshark Model Context Protocol (MCP) system.

## Documentation Categories

### Installation & Setup
- [General Installation Guide](installation.md) - Comprehensive instructions for installing Wireshark MCP and its dependencies
- [Windows Installation Guide](windows_installation.md) - Windows-specific installation instructions
- [macOS Installation Guide](macos_installation.md) - macOS-specific installation instructions
- [Linux Installation Guide](linux_installation.md) - Linux-specific installation instructions

### Security Features
- [IP Protection Guide](ip_protection.md) - Detailed guide on IP address anonymization and obfuscation
- [Security Manager Guide](security_manager.md) - Comprehensive guide to the unified security framework
- [Message Security Signatures](security_signature.md) - Guide for secure message signing and verification

### Integration Guides
- [Claude Integration Guide](claude_integration.md) - Connect Wireshark MCP with Claude AI for network analysis
- [A2A Module Documentation](a2a_module.md) - Using the Agent-to-Agent integration
- [A2A Security Guide](agent_to_agent_integration.md) - Security considerations for A2A integration

## Quick Start

If you're new to Wireshark MCP, the recommended reading order is:

1. Start with the appropriate [Installation Guide](#installation--setup) for your platform.
2. Review the [Security Features](#security-features) documentation to understand how to protect sensitive data.
3. Follow the [Claude Integration Guide](claude_integration.md) to connect with Claude AI.

## Security Documentation Overview

Wireshark MCP includes comprehensive security features for protecting sensitive network data and ensuring secure communication between components:

1. **IP Protection**: The [IP Protection Guide](ip_protection.md) explains how to anonymize, pseudonymize, or redact sensitive IP addresses while preserving meaningful analysis capabilities.

2. **Security Manager**: The [Security Manager Guide](security_manager.md) covers the unified security framework that integrates IP protection, content security, and message signatures.

3. **Message Security**: The [Message Security Signatures](security_signature.md) documentation details how to implement secure message signing and verification for agent-to-agent communication.

4. **A2A Security**: The [A2A Security Guide](agent_to_agent_integration.md) provides security considerations specific to agent-to-agent integrations.

## Additional Resources

- See the main [README.md](../README.md) in the project root for a general overview.
- Check the [examples](../examples) directory for practical code samples.
- Explore the [web_interface](../web_interface) directory for the browser-based UI.

## Contributing to Documentation

We welcome contributions to improve this documentation. If you find errors, omissions, or have suggestions for improvements:

1. Fork the repository
2. Make your changes
3. Submit a pull request

## Getting Help

If you encounter issues or have questions that aren't addressed in the documentation:

1. Open an issue on the [GitHub repository](https://github.com/sarthaksiddha/Wireshark-mcp/issues)
2. Be specific about the problem you're facing
3. Include details about your environment and steps to reproduce the issue
