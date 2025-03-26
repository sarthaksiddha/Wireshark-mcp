# Claude MCP (Model Context Protocol)

A flexible framework for managing interactions with Claude and other AI systems with advanced context handling.

## What is Model Context Protocol?

Model Context Protocol (MCP) is a standardized approach for:

1. **Context Management**: Efficiently handling context windows with large language models
2. **Prompt Engineering**: Structured templates and techniques for optimal AI interaction
3. **Session Continuity**: Maintaining coherent, long-running conversations with AI systems
4. **Memory Management**: Storing and retrieving relevant information across interactions
5. **Output Parsing**: Consistently extracting structured data from AI responses

This framework aims to provide an interface layer between applications and AI models like Claude, making it easier to build AI-enhanced applications with better context awareness.

## Features

- **Flexible Context Windows**: Smart management of token limits and context optimization
- **Memory Hierarchies**: Working, short-term, and long-term memory systems
- **Templating System**: Reusable prompt templates with variable substitution
- **Schema Validation**: Ensure AI outputs match expected formats
- **Conversation Threading**: Maintain parallel conversation branches
- **Context Compression**: Efficient summarization of previous exchanges
- **Plugin Support**: Extend functionality with custom handlers

## Getting Started

### Installation

```bash
pip install claude-mcp
```

### Basic Usage

```python
from claude_mcp import MCPSession, PromptTemplate
from claude_mcp.models import Claude

# Initialize a session with Claude
session = MCPSession(
    model=Claude(api_key="your_api_key"),
    memory_config={"working_memory": 10000, "long_term_memory": True}
)

# Define a prompt template
introduction_template = PromptTemplate(
    """
    <context>
    User is working on: {project}
    Previous conversation summary: {summary}
    </context>
    
    <instructions>
    You are assisting with {task_type} tasks.
    Focus on {focus_area}.
    </instructions>
    
    <message>{user_input}</message>
    """
)

# Start a conversation
response = session.send(
    introduction_template.format(
        project="Data analysis project",
        summary="Previously discussed dataset structure and cleaning approach",
        task_type="data science",
        focus_area="visualization techniques",
        user_input="I need help creating an effective dashboard for my sales data"
    )
)

print(response.content)

# Continue the conversation
follow_up = session.send("What libraries would you recommend for interactive charts?")
print(follow_up.content)
```

## Architecture

The Claude MCP system consists of several key components:

1. **MCPSession**: The main interface for managing conversations
2. **ContextManager**: Handles the organization and optimization of context windows
3. **MemorySystem**: Manages different types of memory storage and retrieval
4. **PromptEngine**: Processes templates and structures interactions
5. **ResponseProcessor**: Parses and validates AI outputs
6. **ModelConnector**: Interfaces with specific AI models (Claude, etc.)

## Advanced Features

### Context Compression

Automatically summarize and compress previous exchanges to maximize context window usage:

```python
# Enable automatic compression when context exceeds 80% of limit
session.context_manager.enable_compression(threshold=0.8)
```

### Structured Output

Specify and validate response formats:

```python
from claude_mcp.schemas import JSONSchema

# Define expected output format
product_schema = JSONSchema({
    "type": "object",
    "properties": {
        "name": {"type": "string"},
        "price": {"type": "number"},
        "features": {"type": "array", "items": {"type": "string"}}
    },
    "required": ["name", "price"]
})

# Request structured data
response = session.send(
    "Suggest a product for home office",
    output_schema=product_schema
)

# Access validated data
product = response.structured_data
print(f"Suggested product: {product['name']} (${product['price']})")
```

### Memory Persistence

Save and restore conversation state:

```python
# Save session state
session_data = session.save()

# Later, restore the session
new_session = MCPSession.load(session_data)
```

## Contributing

We welcome contributions to the Claude MCP project! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by best practices in prompt engineering and context management
- Built to enhance interactions with Anthropic's Claude and similar AI systems