"""
Claude API client for Wireshark MCP.

This module provides a client for communicating with Claude AI,
sending network analysis prompts and processing responses.
"""

import json
import logging
import os
from dataclasses import dataclass
from typing import Dict, Any, Optional, List

# Try to import requests, but make it optional (with a fallback to a stub class)
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    logging.warning("requests package not found, Claude API communication disabled")
    
    # Stub class for environments without requests
    class requests:
        @staticmethod
        def post(*args, **kwargs):
            raise ImportError("requests package is required for Claude API communication")

logger = logging.getLogger(__name__)

# Base URL for Claude API
CLAUDE_API_URL = "https://api.anthropic.com/v1/messages"
DEFAULT_MODEL = "claude-3-7-sonnet-20250219"  # Latest model at time of implementation

@dataclass
class ClaudeResponse:
    """Response from Claude AI."""
    
    analysis: str
    """The analysis text from Claude."""
    
    raw_response: Dict[str, Any]
    """The raw API response as a dictionary."""
    
    token_usage: Dict[str, int]
    """Token usage statistics."""
    
    model: str
    """The model used for the analysis."""

class ClaudeClient:
    """
    Client for communicating with Claude AI.
    
    This client handles authentication, request formatting,
    and response processing for Claude API calls.
    """
    
    def __init__(self, 
                api_key: Optional[str] = None, 
                model: str = DEFAULT_MODEL,
                max_tokens: int = 4000):
        """
        Initialize the Claude client.
        
        Args:
            api_key: Claude API key (falls back to ANTHROPIC_API_KEY env var)
            model: Claude model to use
            max_tokens: Maximum tokens to generate in response
            
        Raises:
            ValueError: If no API key is provided or found in env vars
        """
        if not REQUESTS_AVAILABLE:
            logger.warning("requests library not installed, Claude API functionality disabled")
        
        # Get API key from args or environment
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError(
                "Claude API key is required (either pass directly or set ANTHROPIC_API_KEY env var)"
            )
        
        self.model = model
        self.max_tokens = max_tokens
        
    def analyze(self, prompt: str, system_prompt: Optional[str] = None) -> ClaudeResponse:
        """
        Send a prompt to Claude for analysis.
        
        Args:
            prompt: The prompt to send to Claude
            system_prompt: Optional system prompt to guide Claude's behavior
            
        Returns:
            ClaudeResponse object containing response and metadata
            
        Raises:
            Exception: If API request fails or response can't be parsed
        """
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests library not installed, Claude API functionality disabled")
        
        # Default system prompt for network analysis
        if system_prompt is None:
            system_prompt = (
                "You are a network security analyst expert in Wireshark packet captures. "
                "Analyze the following network data carefully, identifying patterns, anomalies, "
                "and potential security issues. Be thorough, organized, and concise in your analysis. "
                "Present your findings in a structured format with clear section headings. "
                "If you identify any suspicious activities, clearly explain what makes them concerning."
            )
        
        # Prepare API request
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01"
        }
        
        data = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "system": system_prompt
        }
        
        try:
            logger.info(f"Sending request to Claude ({self.model})")
            response = requests.post(CLAUDE_API_URL, headers=headers, json=data, timeout=120)
            response.raise_for_status()  # Raise exception for HTTP errors
            
            # Parse response
            result = response.json()
            
            # Extract the analysis text
            analysis = result.get("content", [{"text": "Error: No response content"}])[0].get("text", "")
            
            # Extract token usage
            token_usage = {
                "prompt_tokens": result.get("usage", {}).get("input_tokens", 0),
                "completion_tokens": result.get("usage", {}).get("output_tokens", 0),
            }
            
            return ClaudeResponse(
                analysis=analysis,
                raw_response=result,
                token_usage=token_usage,
                model=self.model
            )
            
        except Exception as e:
            logger.error(f"Error communicating with Claude API: {e}")
            raise
