"""
AI module for Wireshark MCP.

This module provides interfaces to AI systems for analyzing network data.
"""

from .claude import ClaudeClient, ClaudeResponse

__all__ = ['ClaudeClient', 'ClaudeResponse']
