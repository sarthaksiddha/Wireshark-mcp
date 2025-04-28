# A2A Protocol Implementation Guide

This guide provides implementation details for developers working with Google's Agent-to-Agent (A2A) protocol in the Wireshark MCP tool.

## Table of Contents

1. [Setup and Prerequisites](#setup-and-prerequisites)
2. [Protocol Integration](#protocol-integration)
3. [Packet Capture Configuration](#packet-capture-configuration)
4. [Packet Analysis](#packet-analysis)
5. [Custom Dissectors](#custom-dissectors)
6. [UI Integration](#ui-integration)
7. [Advanced Features](#advanced-features)
8. [Troubleshooting](#troubleshooting)

## Setup and Prerequisites

### Required Dependencies

- Node.js v16 or higher
- Wireshark v4.0 or higher
- Python 3.9 or higher

### Required Packages

```bash
# Install the required packages
npm install --save d3 boxicons
pip install -r requirements.txt
```

### Protocol References

Make sure to reference the official A2A protocol documentation:
- [Google A2A GitHub Repository](https://github.com/google/A2A)
- [A2A Protocol Specification](https://google.github.io/A2A/#/documentation)

## Protocol Integration

### Enabling A2A Protocol Support

The Wireshark MCP tool now has built-in support for A2A protocol. Here's how to enable it:

```javascript
// In your JavaScript code
const protocols = {
  MCP: 'mcp',
  A2A: 'a2a'
};

// Set the active protocol
localStorage.setItem('protocolType', protocols.A2A);
```

### Protocol Toggle

The protocol toggle in the UI provides an easy way to switch between MCP and A2A modes:

```html
<div class="protocol-toggle">
  <span>MCP</span>
  <label class="switch">
    <input type="checkbox" id="protocol-toggle">
    <span class="slider round"></span>
  </label>
  <span>A2A</span>
</div>
```

```javascript
document.getElementById('protocol-toggle').addEventListener('change', function() {
  const newProtocol = this.checked ? PROTOCOL_TYPES.A2A : PROTOCOL_TYPES.MCP;
  localStorage.setItem('protocolType', newProtocol);
  updateProtocolUIState(newProtocol);
});
```

## Packet Capture Configuration

### Configuring tcpdump for A2A

When capturing A2A traffic with tcpdump, use the following filter:

```bash
sudo tcpdump -i any -s 0 -w a2a_capture.pcap '(tcp port 80 or tcp port 443) and (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354)'
```

This will capture HTTP POST requests, which are typically used in A2A communications.

### Wireshark Display Filter

To isolate A2A traffic in Wireshark:

```
http.request.method == "POST" and http.request.uri contains "/a2a"
```

## Packet Analysis

### A2A JSON-RPC Structure

A2A uses JSON-RPC 2.0 for its requests and responses. Here's the basic structure:

1. **Request**:
```json
{
  "jsonrpc": "2.0",
  "id": "request-123",
  "method": "tasks/send",
  "params": {
    // Method-specific parameters
  }
}
```

2. **Response**:
```json
{
  "jsonrpc": "2.0",
  "id": "request-123",
  "result": {
    // Method-specific response
  }
}
```

3. **Error Response**:
```json
{
  "jsonrpc": "2.0",
  "id": "request-123",
  "error": {
    "code": -32001,
    "message": "Task not found",
    "data": null
  }
}
```

### A2A Task States

A2A tasks can be in the following states:

1. `submitted`: Task has been submitted but not started
2. `working`: Task is being processed by the agent
3. `input-required`: Task requires additional input from the client
4. `completed`: Task has been successfully completed
5. `failed`: Task has failed
6. `canceled`: Task has been canceled by the client

### Parsing A2A Messages

Here's an example of how to parse A2A messages in JavaScript:

```javascript
function parseA2APacket(packet) {
  try {
    const jsonData = JSON.parse(packet.data);
    
    // Check if this is an A2A packet
    if (jsonData.jsonrpc === '2.0' && 
        (jsonData.method?.startsWith('tasks/') || 
         jsonData.result?.id || 
         jsonData.error?.code)) {
      
      // Extract relevant information
      const packetInfo = {
        id: jsonData.id,
        protocolType: PROTOCOL_TYPES.A2A,
        method: jsonData.method,
        taskId: jsonData.params?.id || jsonData.result?.id,
        state: jsonData.result?.status?.state,
        timestamp: new Date().toISOString(),
        source: packet.source,
        destination: packet.destination,
        length: packet.length,
        details: {}
      };
      
      // Add details based on method
      if (jsonData.method === 'tasks/send') {
        packetInfo.message = jsonData.params.message;
      } else if (jsonData.result?.status?.message) {
        packetInfo.message = jsonData.result.status.message;
      }
      
      return packetInfo;
    }
    
    return null; // Not an A2A packet
  } catch (e) {
    console.error('Error parsing A2A packet:', e);
    return null;
  }
}
```

## Custom Dissectors

### Creating an A2A Dissector

To create a custom Wireshark dissector for A2A:

1. Create a file named `a2a_dissector.lua` with the following content:

```lua
-- A2A Protocol Dissector
a2a_proto = Proto("a2a", "Agent-to-Agent Protocol")

-- Fields
local f_jsonrpc = ProtoField.string("a2a.jsonrpc", "JSON-RPC Version")
local f_id = ProtoField.string("a2a.id", "Request ID")
local f_method = ProtoField.string("a2a.method", "Method")
local f_task_id = ProtoField.string("a2a.task_id", "Task ID")
local f_task_state = ProtoField.string("a2a.task_state", "Task State")

a2a_proto.fields = {f_jsonrpc, f_id, f_method, f_task_id, f_task_state}

-- Dissector function
function a2a_proto.dissector(buffer, pinfo, tree)
    -- Check if this looks like JSON
    if buffer:len() < 2 or buffer(0,1):string() ~= "{" then
        return 0
    end
    
    -- Try to parse as JSON
    local json_str = buffer:string()
    local success, json = pcall(json.decode, json_str)
    
    if not success or not json.jsonrpc or json.jsonrpc ~= "2.0" then
        return 0
    end
    
    -- Looks like A2A, mark the protocol
    pinfo.cols.protocol = "A2A"
    
    -- Create subtree
    local subtree = tree:add(a2a_proto, buffer(), "Agent-to-Agent Protocol")
    
    -- Add fields
    subtree:add(f_jsonrpc, json.jsonrpc)
    
    if json.id then
        subtree:add(f_id, json.id)
    end
    
    if json.method then
        subtree:add(f_method, json.method)
        pinfo.cols.info = "A2A: " .. json.method
    end
    
    -- Extract task ID
    local task_id = nil
    if json.params and json.params.id then
        task_id = json.params.id
    elseif json.result and json.result.id then
        task_id = json.result.id
    end
    
    if task_id then
        subtree:add(f_task_id, task_id)
    end
    
    -- Extract task state
    if json.result and json.result.status and json.result.status.state then
        subtree:add(f_task_state, json.result.status.state)
    end
    
    return buffer:len()
end

-- Register dissector for HTTP
local http_dissector_table = DissectorTable.get("http.content_type")
http_dissector_table:add("application/json", a2a_proto)
```

2. Place this file in your Wireshark plugins directory and restart Wireshark.

## UI Integration

### Adding A2A Elements to the UI

Use the following CSS classes to style A2A elements:

```css
/* A2A specific styles */
.a2a-packet {
  border-left: 3px solid #10B981; /* Emerald-500 */
}

.badge-a2a {
  background-color: #10B981;
  color: white;
  padding: 0.25rem 0.5rem;
  border-radius: 0.25rem;
  font-size: 0.75rem;
  font-weight: 600;
}

.state-working {
  color: #FBBF24; /* Amber-400 */
}

.state-completed {
  color: #10B981; /* Emerald-500 */
}

.state-failed {
  color: #EF4444; /* Red-500 */
}

.state-input-required {
  color: #3B82F6; /* Blue-500 */
}

.state-submitted {
  color: #A3A3A3; /* Gray-400 */
}

.state-canceled {
  color: #6B7280; /* Gray-500 */
}

/* Message styling */
.message-content {
  margin: 10px 0;
  border: 1px solid #E5E7EB;
  border-radius: 0.5rem;
  padding: 1rem;
}

.user-message {
  color: #3B82F6;
  font-weight: 600;
}

.agent-message {
  color: #10B981;
  font-weight: 600;
}

.message-text {
  margin: 0.5rem 0;
  white-space: pre-wrap;
}

.message-data pre {
  background-color: #F3F4F6;
  padding: 0.5rem;
  border-radius: 0.25rem;
  overflow-x: auto;
}

/* Task flow visualization */
.task-flow {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin: 1rem 0;
  position: relative;
}

.task-flow::before {
  content: '';
  position: absolute;
  top: 50%;
  left: 0;
  right: 0;
  height: 2px;
  background-color: #E5E7EB;
  z-index: 0;
}

.task-state-node {
  width: 20px;
  height: 20px;
  border-radius: 50%;
  background-color: #F3F4F6;
  border: 2px solid #E5E7EB;
  position: relative;
  z-index: 1;
}

.task-state-node.active {
  background-color: #10B981;
  border-color: #10B981;
}

.task-state-label {
  font-size: 0.75rem;
  white-space: nowrap;
  position: absolute;
  top: 100%;
  left: 50%;
  transform: translateX(-50%);
  margin-top: 0.25rem;
}
```

### Creating Task Flow Visualization

To visualize A2A task state transitions:

```javascript
function createTaskFlowVisualization(taskId, currentState) {
  // Define all possible states in order
  const states = ['submitted', 'working', 'input-required', 'completed', 'failed', 'canceled'];
  
  // Create container
  const container = document.createElement('div');
  container.className = 'task-flow';
  
  // Get current state index
  const currentStateIndex = states.indexOf(currentState);
  
  // Create nodes for each state
  states.forEach((state, index) => {
    const node = document.createElement('div');
    node.className = `task-state-node ${index <= currentStateIndex ? 'active' : ''}`;
    node.setAttribute('data-state', state);
    
    const label = document.createElement('div');
    label.className = 'task-state-label';
    label.textContent = state;
    
    node.appendChild(label);
    container.appendChild(node);
  });
  
  return container;
}
```

### Dynamic Protocol Switching

Implement dynamic protocol switching to update UI elements when the protocol changes:

```javascript
function updateProtocolUIState(protocol) {
  // Update protocol toggle state
  document.getElementById('protocol-toggle').checked = protocol === PROTOCOL_TYPES.A2A;
  
  // Update visible packet list
  updatePacketList(protocol);
  
  // Update visualization
  updateVisualization(protocol);
  
  // Show/hide protocol-specific UI elements
  document.querySelectorAll('.mcp-specific').forEach(el => {
    el.classList.toggle('hidden', protocol !== PROTOCOL_TYPES.MCP);
  });
  
  document.querySelectorAll('.a2a-specific').forEach(el => {
    el.classList.toggle('hidden', protocol !== PROTOCOL_TYPES.A2A);
  });
}

// Listen for storage changes (for multi-tab support)
window.addEventListener('storage', (e) => {
  if (e.key === 'protocolType') {
    updateProtocolUIState(e.newValue);
  }
});
```

## Advanced Features

### Task Grouping

To implement task grouping for A2A packets:

```javascript
function groupPacketsByTask(packets) {
  const taskGroups = {};
  
  // Group packets by taskId
  packets.forEach(packet => {
    if (packet.protocolType === PROTOCOL_TYPES.A2A && packet.taskId) {
      if (!taskGroups[packet.taskId]) {
        taskGroups[packet.taskId] = [];
      }
      taskGroups[packet.taskId].push(packet);
    }
  });
  
  // Sort packets within each group by timestamp
  Object.values(taskGroups).forEach(group => {
    group.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
  });
  
  return taskGroups;
}
```

### Task State Timeline

Create a timeline visualization for task state changes:

```javascript
function createTaskStateTimeline(taskGroup) {
  const container = document.createElement('div');
  container.className = 'task-state-timeline';
  
  // Extract state changes
  const stateChanges = [];
  let currentState = null;
  
  taskGroup.forEach(packet => {
    if (packet.state && packet.state !== currentState) {
      stateChanges.push({
        state: packet.state,
        timestamp: packet.timestamp
      });
      currentState = packet.state;
    }
  });
  
  // Create timeline elements
  stateChanges.forEach((change, index) => {
    const timelineItem = document.createElement('div');
    timelineItem.className = 'timeline-item';
    
    const stateIndicator = document.createElement('div');
    stateIndicator.className = `state-indicator state-${change.state}`;
    
    const stateLabel = document.createElement('div');
    stateLabel.className = 'state-label';
    stateLabel.textContent = change.state;
    
    const timestamp = document.createElement('div');
    timestamp.className = 'timestamp';
    timestamp.textContent = new Date(change.timestamp).toLocaleTimeString();
    
    timelineItem.appendChild(stateIndicator);
    timelineItem.appendChild(stateLabel);
    timelineItem.appendChild(timestamp);
    
    // Add connector line (except for the last item)
    if (index < stateChanges.length - 1) {
      const connector = document.createElement('div');
      connector.className = 'timeline-connector';
      timelineItem.appendChild(connector);
    }
    
    container.appendChild(timelineItem);
  });
  
  return container;
}
```

### Message Diff Visualization

Implement message diff visualization to track changes between messages:

```javascript
function createMessageDiff(previousMessage, currentMessage) {
  const diffContainer = document.createElement('div');
  diffContainer.className = 'message-diff';
  
  // Only diff text parts for simplicity
  const getPrevText = () => {
    if (!previousMessage?.parts) return '';
    const textPart = previousMessage.parts.find(p => p.type === 'text');
    return textPart?.text || '';
  };
  
  const getCurrentText = () => {
    if (!currentMessage?.parts) return '';
    const textPart = currentMessage.parts.find(p => p.type === 'text');
    return textPart?.text || '';
  };
  
  const prevText = getPrevText();
  const currText = getCurrentText();
  
  // Use diff library (need to include one, e.g., diff-match-patch)
  const dmp = new diff_match_patch();
  const diffs = dmp.diff_main(prevText, currText);
  dmp.diff_cleanupSemantic(diffs);
  
  // Convert diffs to HTML
  const diffHtml = diffs.map(([op, text]) => {
    if (op === 1) {
      return `<span class="diff-add">${text}</span>`;
    } else if (op === -1) {
      return `<span class="diff-remove">${text}</span>`;
    } else {
      return `<span class="diff-same">${text}</span>`;
    }
  }).join('');
  
  diffContainer.innerHTML = diffHtml;
  return diffContainer;
}
```

### Agent Card Viewer

Create a viewer for A2A Agent Cards:

```javascript
function createAgentCardViewer(agentCard) {
  const container = document.createElement('div');
  container.className = 'agent-card-viewer';
  
  // Header
  const header = document.createElement('div');
  header.className = 'card-header';
  header.innerHTML = `
    <h3>${agentCard.name}</h3>
    <div class="card-provider">${agentCard.provider?.organization || 'Unknown provider'}</div>
    <div class="card-version">v${agentCard.version}</div>
  `;
  
  // Description
  const description = document.createElement('div');
  description.className = 'card-description';
  description.textContent = agentCard.description || 'No description provided';
  
  // Capabilities
  const capabilities = document.createElement('div');
  capabilities.className = 'card-capabilities';
  capabilities.innerHTML = `
    <h4>Capabilities</h4>
    <ul>
      <li>Streaming: ${agentCard.capabilities.streaming ? 'Yes' : 'No'}</li>
      <li>Push Notifications: ${agentCard.capabilities.pushNotifications ? 'Yes' : 'No'}</li>
      <li>State History: ${agentCard.capabilities.stateTransitionHistory ? 'Yes' : 'No'}</li>
    </ul>
  `;
  
  // Skills
  const skills = document.createElement('div');
  skills.className = 'card-skills';
  skills.innerHTML = `<h4>Skills (${agentCard.skills.length})</h4>`;
  
  const skillsList = document.createElement('ul');
  agentCard.skills.forEach(skill => {
    const skillItem = document.createElement('li');
    skillItem.className = 'skill-item';
    skillItem.innerHTML = `
      <div class="skill-name">${skill.name}</div>
      <div class="skill-id">${skill.id}</div>
      <div class="skill-description">${skill.description || 'No description'}</div>
    `;
    skillsList.appendChild(skillItem);
  });
  
  skills.appendChild(skillsList);
  
  // Assemble all sections
  container.appendChild(header);
  container.appendChild(description);
  container.appendChild(capabilities);
  container.appendChild(skills);
  
  return container;
}
```

## Troubleshooting

### Common A2A Issues

#### Issue: Cannot parse A2A packets

**Solution**: Ensure that the content is valid JSON-RPC 2.0 format. Use the browser's developer tools to inspect the raw network traffic:

```javascript
// Debug A2A packet
function debugA2APacket(rawData) {
  try {
    const parsedData = JSON.parse(rawData);
    console.log('A2A Packet Structure:', parsedData);
    
    // Check for required fields
    const missingFields = [];
    if (!parsedData.jsonrpc) missingFields.push('jsonrpc');
    if (!parsedData.id) missingFields.push('id');
    if (!parsedData.method && !parsedData.result && !parsedData.error) {
      missingFields.push('method/result/error');
    }
    
    if (missingFields.length > 0) {
      console.warn('Missing required JSON-RPC fields:', missingFields.join(', '));
    }
    
    // Check task-related fields
    if (parsedData.params?.id || parsedData.result?.id) {
      console.log('Task ID:', parsedData.params?.id || parsedData.result?.id);
    } else {
      console.warn('No task ID found in packet');
    }
    
    return parsedData;
  } catch (e) {
    console.error('Failed to parse A2A packet:', e);
    console.log('Raw data:', rawData);
    return null;
  }
}
```

#### Issue: A2A tasks not appearing in the timeline

**Solution**: Check that task IDs are being correctly extracted and that state changes are being tracked:

```javascript
function validateTaskStates(packetData) {
  const taskMap = {};
  
  // Group by task ID
  packetData.forEach(packet => {
    if (packet.protocolType === PROTOCOL_TYPES.A2A && packet.taskId) {
      if (!taskMap[packet.taskId]) {
        taskMap[packet.taskId] = {
          states: [],
          timestamps: [],
          complete: false
        };
      }
      
      if (packet.state && !taskMap[packet.taskId].states.includes(packet.state)) {
        taskMap[packet.taskId].states.push(packet.state);
        taskMap[packet.taskId].timestamps.push(packet.timestamp);
        
        // Mark as complete if in terminal state
        if (['completed', 'failed', 'canceled'].includes(packet.state)) {
          taskMap[packet.taskId].complete = true;
        }
      }
    }
  });
  
  // Validate each task
  Object.entries(taskMap).forEach(([taskId, info]) => {
    console.log(`Task ${taskId}:`);
    console.log('  States:', info.states.join(' → '));
    console.log('  Complete:', info.complete);
    
    // Check for invalid state transitions
    let invalid = false;
    for (let i = 1; i < info.states.length; i++) {
      const prevState = info.states[i-1];
      const currState = info.states[i];
      
      if ((prevState === 'completed' || prevState === 'failed' || prevState === 'canceled')
          && currState !== prevState) {
        console.warn(`  Invalid state transition: ${prevState} → ${currState}`);
        invalid = true;
      }
    }
    
    if (!invalid) {
      console.log('  All state transitions valid');
    }
  });
  
  return taskMap;
}
```

#### Issue: Protocol toggle not working

**Solution**: Check that event listeners are properly registered and localStorage is being updated:

```javascript
function debugProtocolToggle() {
  const toggle = document.getElementById('protocol-toggle');
  if (!toggle) {
    console.error('Protocol toggle element not found');
    return;
  }
  
  console.log('Current protocol:', localStorage.getItem('protocolType') || 'Not set (defaults to MCP)');
  console.log('Toggle checked state:', toggle.checked);
  
  // Test toggle functionality
  toggle.addEventListener('click', function() {
    console.log('Toggle clicked, new checked state:', this.checked);
    const newProtocol = this.checked ? PROTOCOL_TYPES.A2A : PROTOCOL_TYPES.MCP;
    console.log('Setting protocol to:', newProtocol);
    localStorage.setItem('protocolType', newProtocol);
  });
  
  console.log('Debug event listener added to protocol toggle');
}
```

### Advanced Debugging

For more complex issues, use the built-in debug mode:

```javascript
// Enable debug mode
localStorage.setItem('debugMode', 'true');

// In your code
function isDebugMode() {
  return localStorage.getItem('debugMode') === 'true';
}

// Use throughout the code
if (isDebugMode()) {
  console.log('Debug info:', someData);
}
```

## A2A and MCP Integration

### Converting Between Protocols

To create a bridge between A2A and MCP:

```javascript
function convertMCPToA2A(mcpContent) {
  // Extract tool uses from MCP
  const toolPattern = /<tool_use>[\s\S]*?<tool name="([^"]+)">([\s\S]*?)<\/tool>[\s\S]*?<r>([\s\S]*?)<\/r>[\s\S]*?<\/tool_use>/g;
  const humanPattern = /<human>([\s\S]*?)<\/human>/g;
  
  // Create A2A message parts
  const parts = [];
  
  // Add human messages
  let humanMatch;
  while ((humanMatch = humanPattern.exec(mcpContent)) !== null) {
    parts.push({
      type: 'text',
      text: humanMatch[1].trim()
    });
  }
  
  // Add tool results as structured data
  let toolMatch;
  while ((toolMatch = toolPattern.exec(mcpContent)) !== null) {
    const toolName = toolMatch[1];
    const toolParams = toolMatch[2];
    const toolResult = toolMatch[3];
    
    parts.push({
      type: 'data',
      data: {
        tool: toolName,
        result: toolResult,
        params: toolParams
      }
    });
  }
  
  // Create A2A message
  const a2aMessage = {
    role: 'user',
    parts
  };
  
  return a2aMessage;
}

function convertA2AToMCP(a2aMessage) {
  let mcpContent = '';
  
  if (a2aMessage.role === 'user') {
    // Handle user messages
    a2aMessage.parts.forEach(part => {
      if (part.type === 'text') {
        mcpContent += `<human>${part.text}</human>\n`;
      } else if (part.type === 'data') {
        // Convert structured data to tool use if possible
        if (part.data.tool) {
          mcpContent += `<tool_use>\n`;
          mcpContent += `  <tool name="${part.data.tool}">${part.data.params || ''}</tool>\n`;
          mcpContent += `  <r>${part.data.result || ''}</r>\n`;
          mcpContent += `</tool_use>\n`;
        }
      }
    });
  } else if (a2aMessage.role === 'agent') {
    // Handle agent messages
    a2aMessage.parts.forEach(part => {
      if (part.type === 'text') {
        mcpContent += `<assistant>${part.text}</assistant>\n`;
      }
    });
  }
  
  return mcpContent;
}
```

### Protocol Detection

Automatically detect the protocol in use:

```javascript
function detectProtocol(content) {
  // Check for A2A JSON-RPC format
  try {
    const parsed = JSON.parse(content);
    if (parsed.jsonrpc === '2.0' && 
        (parsed.method?.startsWith('tasks/') || 
         parsed.result?.id ||
         parsed.error?.code)) {
      return PROTOCOL_TYPES.A2A;
    }
  } catch (e) {
    // Not valid JSON, might be MCP XML
  }
  
  // Check for MCP XML format
  if (content.includes('<context>') || 
      content.includes('<tool_use>') ||
      content.includes('<human>') ||
      content.includes('<assistant>')) {
    return PROTOCOL_TYPES.MCP;
  }
  
  // Unable to determine protocol
  return null;
}
```

With these implementations, you can successfully integrate A2A protocol support into the Wireshark MCP tool and provide comprehensive analysis capabilities for both protocols.
