# Wireshark MCP → Claude Integration Guide

This document provides a detailed guide on how to effectively connect Wireshark MCP with Claude for network traffic analysis.

## Introduction

Wireshark MCP is designed to transform complex packet captures into structured, AI-friendly contexts that Claude can analyze effectively. This guide explains both programmatic (API) and manual methods of integration, along with best practices for effective analysis.

## Prerequisites

- Wireshark MCP installed (see [installation guide](installation.md))
- One of the following:
  - Claude API access (Anthropic API key)
  - Access to Claude's web interface at [claude.ai](https://claude.ai)

## Integration Options

### Method 1: Using the Claude API (Programmatic)

#### Step 1: Set up configuration

Create a file named `claude_config.py`:

```python
# claude_config.py
CLAUDE_API_KEY = "your_anthropic_api_key"  # Replace with your actual API key
CLAUDE_API_URL = "https://api.anthropic.com/v1/messages"
CLAUDE_MODEL = "claude-3-opus-20240229"  # Adjust to your preferred model
```

#### Step 2: Create a Claude client class

```python
# claude_client.py
import requests
import json
import os
from claude_config import CLAUDE_API_KEY, CLAUDE_API_URL, CLAUDE_MODEL

class ClaudeClient:
    """Client for interacting with Claude API."""
    
    def __init__(self, api_key=None, api_url=None, model=None):
        """Initialize with API credentials."""
        self.api_key = api_key or CLAUDE_API_KEY or os.getenv("CLAUDE_API_KEY")
        self.api_url = api_url or CLAUDE_API_URL
        self.model = model or CLAUDE_MODEL
        
        # Verify API key exists
        if not self.api_key:
            raise ValueError("Claude API key not provided. Set in code or as CLAUDE_API_KEY environment variable.")
        
    def analyze(self, prompt, max_tokens=4000):
        """Send a prompt to Claude and get the analysis response."""
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01"
        }
        
        data = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens
        }
        
        response = requests.post(self.api_url, headers=headers, json=data)
        
        if response.status_code != 200:
            raise Exception(f"Claude API error: {response.status_code} - {response.text}")
        
        result = response.json()
        
        # Extract just the text content from Claude's response
        if "content" in result and len(result["content"]) > 0:
            return {
                "analysis": result["content"][0]["text"],
                "full_response": result
            }
        
        return result
    
    def analyze_network_capture(self, mcp_instance, protocol, query, include_headers=True, include_body=False):
        """Convenience method to analyze network capture with a specific protocol."""
        from wireshark_mcp.formatters import ClaudeFormatter
        
        # Extract protocol data
        context = mcp_instance.extract_protocol(
            protocol=protocol,
            include_headers=include_headers,
            include_body=include_body
        )
        
        # Format for Claude
        formatter = ClaudeFormatter()
        prompt = formatter.format_context(context, query=query)
        
        # Get analysis from Claude
        return self.analyze(prompt)
```

#### Step 3: Use the client for network analysis

```python
from wireshark_mcp import WiresharkMCP, Protocol
from claude_client import ClaudeClient

# Initialize MCP with a packet capture
mcp = WiresharkMCP("capture.pcap")

# Initialize Claude client
claude = ClaudeClient()

# Analyze HTTP traffic
http_analysis = claude.analyze_network_capture(
    mcp_instance=mcp,
    protocol=Protocol.HTTP,
    query="Analyze this HTTP traffic for security vulnerabilities and unusual patterns."
)

# Print the analysis
print(http_analysis["analysis"])

# Analyze SMTP traffic
smtp_analysis = claude.analyze_network_capture(
    mcp_instance=mcp,
    protocol=Protocol.SMTP,
    query="Identify any potentially malicious email patterns in this SMTP traffic."
)

print(smtp_analysis["analysis"])
```

### Method 2: Using Claude's Web Interface (Manual)

If you don't have API access or prefer to use Claude's web interface:

#### Step 1: Generate Claude-formatted prompt

```python
from wireshark_mcp import WiresharkMCP, Protocol
from wireshark_mcp.formatters import ClaudeFormatter

# Initialize MCP with a packet capture
mcp = WiresharkMCP("capture.pcap")

# Extract protocol data
protocol_context = mcp.extract_protocol(
    protocol=Protocol.HTTP,  # Or any other supported protocol
    include_headers=True,
    include_body=False
)

# Format for Claude
formatter = ClaudeFormatter()
prompt = formatter.format_context(
    protocol_context,
    query="Analyze this network traffic for security issues and unusual patterns."
)

# Save to file
with open("claude_prompt.md", "w") as f:
    f.write(prompt)

print("Claude prompt saved to claude_prompt.md")
```

#### Step 2: Use Claude's web interface

1. Open [Claude.ai](https://claude.ai) in your browser
2. Open the `claude_prompt.md` file
3. Copy the entire contents
4. Paste into Claude's message input
5. Send and wait for Claude's analysis

### Method 3: Using the Web Interface

The Wireshark MCP web interface provides a user-friendly way to upload capture files, analyze them, and generate Claude prompts.

1. Start the web interface:
   ```bash
   cd web_interface
   python app.py
   ```

2. Open http://localhost:5000 in your browser
3. Upload a packet capture file
4. Select the protocol to analyze
5. View the generated Claude prompt
6. Copy the prompt to Claude's web interface or use the API

## Optimizing Prompts for Claude

Wireshark MCP's `ClaudeFormatter` is designed to create prompts that work well with Claude, but you can enhance the results further:

### Best Practices for Claude Analysis

1. **Be specific in your queries**:
   - Instead of: "Analyze this traffic"
   - Better: "Analyze this HTTP traffic for indicators of SQL injection attacks and identify suspicious IP addresses"

2. **Guide the analysis with focused questions**:
   ```python
   query = """
   Please analyze this network traffic and answer the following:
   1. Are there any indicators of port scanning or reconnaissance?
   2. Do you see any unusual patterns in the DNS queries?
   3. Are there any connections to known malicious domains?
   4. What security recommendations would you make based on this traffic?
   """
   ```

3. **Adjust detail level based on needs**:
   ```python
   # Higher detail level for more comprehensive analysis
   context = mcp.extract_protocol(
       protocol=Protocol.HTTP,
       detail_level=3  # More detailed context
   )
   ```

4. **Combine different protocol analyses**:
   ```python
   # Extract multiple protocol contexts
   http_context = mcp.extract_protocol(Protocol.HTTP)
   dns_context = mcp.extract_protocol(Protocol.DNS)
   smtp_context = mcp.extract_protocol(Protocol.SMTP)
   
   # Custom formatting to combine them
   combined_prompt = f"""
   # Network Traffic Analysis
   
   ## HTTP Analysis
   {formatter.format_context(http_context)}
   
   ## DNS Analysis
   {formatter.format_context(dns_context)}
   
   ## SMTP Analysis
   {formatter.format_context(smtp_context)}
   
   Please analyze all these protocols together and identify any correlated suspicious activities.
   """
   ```

### Example Specialized Queries

**Security-focused analysis:**
```python
query = """
Analyze this network traffic from a security perspective:
1. Identify any potential threats or vulnerabilities
2. Flag suspicious connections or behaviors
3. Recommend mitigation steps for any issues found
"""
```

**Forensic analysis:**
```python
query = """
Perform a forensic analysis of this network traffic:
1. Create a timeline of key events
2. Identify the attacker's actions and techniques
3. Determine what data or systems might have been compromised
4. Explain the attack methodology used
"""
```

**Performance analysis:**
```python
query = """
Analyze this network traffic for performance issues:
1. Identify bottlenecks or latency problems
2. Determine if there are inefficient patterns or protocols
3. Suggest optimizations that could improve network performance
"""
```

## Using Claude with Security Analysis

Wireshark MCP has built-in security analysis features that work well with Claude:

```python
# Run security analysis
security_context = mcp.security_analysis(
    detect_scanning=True,
    detect_malware_patterns=True,
    highlight_unusual_ports=True,
    check_encryption=True
)

# Format for Claude
security_prompt = formatter.format_security_context(
    security_context,
    query="Provide a detailed security assessment of these findings."
)

# Send to Claude
response = claude.analyze(security_prompt)
```

## Troubleshooting

### Common Claude Integration Issues

1. **Token Limit Exceeded**
   
   Problem: Claude has a maximum token limit and some packet captures generate very large prompts
   
   Solution:
   - Reduce the number of packets analyzed:
     ```python
     context = mcp.extract_protocol(
         protocol=Protocol.HTTP,
         max_conversations=5  # Reduce from default 10
     )
     ```
   - Reduce the detail level:
     ```python
     context = mcp.extract_protocol(
         protocol=Protocol.HTTP,
         detail_level=1  # Less detailed
     )
     ```
   - Use the ClaudeFormatter's max_context_length parameter:
     ```python
     formatter = ClaudeFormatter(max_context_length=10000)
     ```

2. **Claude misinterpreting technical details**
   
   Problem: Claude sometimes misunderstands low-level protocol details
   
   Solution:
   - Be more specific in your queries
   - Use higher-level abstractions:
     ```python
     insights = mcp.protocol_insights(
         protocol=Protocol.DNS,
         extract_queries=True
     )
     ```
   - Add context in your query:
     ```python
     query = """
     In this HTTP traffic:
     - 401/403 status codes indicate authentication/authorization issues
     - 500 status codes indicate server errors
     - The X-XSS-Protection header relates to cross-site scripting defenses
     
     Analyze this traffic with these interpretations in mind.
     """
     ```

3. **Rate limits with Claude API**
   
   Problem: Hitting API rate limits
   
   Solution:
   - Add retry logic with exponential backoff:
     ```python
     import time
     import random
     
     def retry_with_backoff(func, max_retries=5):
         retries = 0
         while retries < max_retries:
             try:
                 return func()
             except Exception as e:
                 if "rate limit" not in str(e).lower():
                    raise
                    
                wait_time = (2 ** retries) + random.random()
                print(f"Rate limited. Waiting {wait_time:.2f} seconds...")
                time.sleep(wait_time)
                retries += 1
         
         raise Exception("Max retries exceeded")
     
     # Use with your Claude client
     response = retry_with_backoff(lambda: claude.analyze(prompt))
     ```

## Best Practices for Production Use

1. **Secure API key handling**:
   - Store API keys in environment variables
   - Use a secrets manager for production deployments
   - Never hardcode API keys in source code

2. **Implement caching**:
   - Cache Claude responses for identical or similar prompts
   - Implement a TTL (time-to-live) for cached responses

3. **Implement logging**:
   - Log prompt sizes, response times, and error rates
   - Set up alerts for anomalies

4. **Handle sensitive data**:
   - Implement data sanitization for sensitive packet contents
   - Use filters to exclude sensitive protocols or IP ranges

## Resources

- [Anthropic Claude Documentation](https://docs.anthropic.com/)
- [Wireshark MCP GitHub Repository](https://github.com/sarthaksiddha/Wireshark-mcp)
- [Wireshark Documentation](https://www.wireshark.org/docs/)
