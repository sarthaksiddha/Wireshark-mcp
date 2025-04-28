"""
Agent implementation for Wireshark MCP using the A2A protocol.
This module enables the Wireshark MCP to communicate with other agents
through the A2A protocol.
"""

import json
import uuid
from typing import Dict, List, Optional, Any, Union
from enum import Enum
from dataclasses import dataclass, field


class TaskState(str, Enum):
    """Task states according to A2A protocol."""
    SUBMITTED = "submitted"
    WORKING = "working"
    INPUT_REQUIRED = "input-required"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELED = "canceled"


class Role(str, Enum):
    """Message roles in A2A protocol."""
    USER = "user"
    AGENT = "agent"


@dataclass
class TextPart:
    """Text part representation in A2A protocol."""
    type: str = "text"
    text: str = ""


@dataclass
class DataPart:
    """Data part representation in A2A protocol."""
    type: str = "data"
    data: Dict[str, Any] = field(default_factory=dict)
    mime_type: str = "application/json"


@dataclass
class FilePart:
    """File part representation in A2A protocol."""
    type: str = "file"
    file_name: str = ""
    mime_type: str = ""
    bytes: Optional[str] = None
    uri: Optional[str] = None


PartType = Union[TextPart, DataPart, FilePart]


@dataclass
class Message:
    """Message representation in A2A protocol."""
    role: Role
    parts: List[PartType] = field(default_factory=list)


@dataclass
class Artifact:
    """Artifact representation in A2A protocol."""
    artifact_id: str
    parts: List[PartType] = field(default_factory=list)


@dataclass
class Task:
    """Task representation in A2A protocol."""
    task_id: str
    state: TaskState
    messages: List[Message] = field(default_factory=list)
    artifacts: List[Artifact] = field(default_factory=list)
    errors: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class WiresharkA2AAgent:
    """
    Wireshark A2A Agent implementation.
    This class represents a Wireshark agent that can communicate using the A2A protocol.
    """
    
    def __init__(self, name: str, description: str, version: str = "1.0.0"):
        """
        Initialize the Wireshark A2A Agent.
        
        Args:
            name: The name of the agent
            description: A description of the agent's capabilities
            version: The version of the agent
        """
        self.name = name
        self.description = description
        self.version = version
        self.tasks: Dict[str, Task] = {}
        self.skills = self._define_skills()
    
    def _define_skills(self) -> List[Dict[str, Any]]:
        """Define the skills that this agent can perform."""
        return [
            {
                "name": "analyze_packet_capture",
                "description": "Analyze a packet capture file (PCAP) and provide insights",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to the PCAP file"
                        },
                        "analysis_type": {
                            "type": "string",
                            "enum": ["basic", "security", "performance", "protocol"],
                            "description": "Type of analysis to perform"
                        },
                        "max_packets": {
                            "type": "integer",
                            "description": "Maximum number of packets to analyze"
                        }
                    },
                    "required": ["file_path"]
                }
            },
            {
                "name": "capture_live_traffic",
                "description": "Capture live network traffic",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "interface": {
                            "type": "string",
                            "description": "Network interface to capture traffic from"
                        },
                        "duration": {
                            "type": "integer",
                            "description": "Duration of capture in seconds"
                        },
                        "filter": {
                            "type": "string",
                            "description": "BPF filter expression"
                        }
                    },
                    "required": ["interface"]
                }
            },
            {
                "name": "detect_anomalies",
                "description": "Detect anomalies in network traffic",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to the PCAP file"
                        },
                        "sensitivity": {
                            "type": "string",
                            "enum": ["low", "medium", "high"],
                            "description": "Sensitivity of anomaly detection"
                        }
                    },
                    "required": ["file_path"]
                }
            }
        ]
    
    def get_agent_card(self) -> Dict[str, Any]:
        """
        Get the agent card for this Wireshark A2A Agent.
        
        Returns:
            Dict containing the agent card information
        """
        return {
            "schema_version": "1.0",
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "authentication": {
                "type": "none"
            },
            "endpoint": "/a2a",
            "features": {
                "streaming": True,
                "pushNotifications": False
            },
            "skills": self.skills
        }
    
    def create_task(self, initial_message: Message) -> Task:
        """
        Create a new task with the given initial message.
        
        Args:
            initial_message: The initial message from the user
            
        Returns:
            A new Task object
        """
        task_id = str(uuid.uuid4())
        task = Task(
            task_id=task_id,
            state=TaskState.SUBMITTED,
            messages=[initial_message]
        )
        self.tasks[task_id] = task
        return task
    
    def get_task(self, task_id: str) -> Optional[Task]:
        """
        Get a task by its ID.
        
        Args:
            task_id: The ID of the task to retrieve
            
        Returns:
            The Task object if found, None otherwise
        """
        return self.tasks.get(task_id)
    
    def update_task_state(self, task_id: str, state: TaskState) -> Optional[Task]:
        """
        Update the state of a task.
        
        Args:
            task_id: The ID of the task to update
            state: The new state for the task
            
        Returns:
            The updated Task object if found, None otherwise
        """
        task = self.get_task(task_id)
        if task:
            task.state = state
            return task
        return None
    
    def add_message_to_task(self, task_id: str, message: Message) -> Optional[Task]:
        """
        Add a message to an existing task.
        
        Args:
            task_id: The ID of the task to add the message to
            message: The message to add
            
        Returns:
            The updated Task object if found, None otherwise
        """
        task = self.get_task(task_id)
        if task:
            task.messages.append(message)
            return task
        return None
    
    def add_artifact_to_task(self, task_id: str, artifact: Artifact) -> Optional[Task]:
        """
        Add an artifact to an existing task.
        
        Args:
            task_id: The ID of the task to add the artifact to
            artifact: The artifact to add
            
        Returns:
            The updated Task object if found, None otherwise
        """
        task = self.get_task(task_id)
        if task:
            task.artifacts.append(artifact)
            return task
        return None
