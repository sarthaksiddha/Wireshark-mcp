"""
A2A Server implementation for Wireshark MCP.
This module implements the server-side components of the A2A protocol
for the Wireshark MCP.
"""

import json
import logging
from typing import Dict, Any, Optional, List, Callable, Tuple
from functools import wraps

from .agent import WiresharkA2AAgent, Task, TaskState, Message, Role, TextPart, Artifact


logger = logging.getLogger(__name__)


def requires_task(f: Callable) -> Callable:
    """Decorator to check if a task exists before executing a function."""
    @wraps(f)
    def wrapper(self, task_id: str, *args, **kwargs) -> Tuple[Any, int]:
        task = self.agent.get_task(task_id)
        if not task:
            return {"error": f"Task {task_id} not found"}, 404
        return f(self, task_id, *args, **kwargs)
    return wrapper


class WiresharkA2AServer:
    """
    A2A Server implementation for Wireshark MCP.
    This class handles A2A protocol requests and delegates them to the appropriate
    handlers.
    """
    
    def __init__(self, agent: WiresharkA2AAgent):
        """
        Initialize the A2A Server.
        
        Args:
            agent: The WiresharkA2AAgent instance to handle requests
        """
        self.agent = agent
        self.handlers = {
            "tasks/send": self.handle_tasks_send,
            "tasks/sendSubscribe": self.handle_tasks_send_subscribe,
            "tasks/get": self.handle_tasks_get,
            "tasks/cancel": self.handle_tasks_cancel,
            "tasks/pushNotification/set": self.handle_push_notification_set,
            "agent/card": self.handle_agent_card
        }
    
    def handle_request(self, method: str, params: Dict[str, Any]) -> Tuple[Any, int]:
        """
        Handle an incoming A2A protocol request.
        
        Args:
            method: The A2A method being called
            params: The parameters for the method
            
        Returns:
            A tuple containing the response and status code
        """
        handler = self.handlers.get(method)
        if not handler:
            return {"error": f"Unknown method: {method}"}, 400
        
        try:
            return handler(params)
        except Exception as e:
            logger.exception(f"Error handling {method} request")
            return {"error": str(e)}, 500
    
    def handle_agent_card(self, params: Dict[str, Any]) -> Tuple[Dict[str, Any], int]:
        """
        Handle a request for the agent card.
        
        Args:
            params: The parameters for the request
            
        Returns:
            The agent card and a 200 status code
        """
        return self.agent.get_agent_card(), 200
    
    def handle_tasks_send(self, params: Dict[str, Any]) -> Tuple[Dict[str, Any], int]:
        """
        Handle a tasks/send request.
        
        Args:
            params: The parameters for the request
            
        Returns:
            The task object and a status code
        """
        task_id = params.get("task_id")
        message = params.get("message", {})
        
        # Create a Message object from the message parameter
        role = message.get("role", "user")
        parts = message.get("parts", [])
        
        message_obj = Message(role=Role(role), parts=parts)
        
        if not task_id:
            # Create a new task if no task_id is provided
            task = self.agent.create_task(message_obj)
            # Process the task asynchronously (in a real implementation)
            self._process_task(task.task_id)
            return task.__dict__, 200
        
        # Add the message to an existing task
        task = self.agent.get_task(task_id)
        if not task:
            return {"error": f"Task {task_id} not found"}, 404
            
        self.agent.add_message_to_task(task_id, message_obj)
        self._process_task(task_id)
        
        return task.__dict__, 200
    
    def handle_tasks_send_subscribe(self, params: Dict[str, Any]) -> Tuple[Dict[str, Any], int]:
        """
        Handle a tasks/sendSubscribe request.
        
        Args:
            params: The parameters for the request
            
        Returns:
            A streaming response or error
        """
        # In a real implementation, this would set up Server-Sent Events (SSE)
        # For simplicity, we'll just return an error indicating streaming is not implemented
        return {"error": "Streaming not implemented in this example"}, 501
    
    @requires_task
    def handle_tasks_get(self, task_id: str, params: Dict[str, Any]) -> Tuple[Dict[str, Any], int]:
        """
        Handle a tasks/get request.
        
        Args:
            task_id: The ID of the task to retrieve
            params: The parameters for the request
            
        Returns:
            The task object and a status code
        """
        task = self.agent.get_task(task_id)
        return task.__dict__, 200
    
    @requires_task
    def handle_tasks_cancel(self, task_id: str, params: Dict[str, Any]) -> Tuple[Dict[str, Any], int]:
        """
        Handle a tasks/cancel request.
        
        Args:
            task_id: The ID of the task to cancel
            params: The parameters for the request
            
        Returns:
            The task object and a status code
        """
        task = self.agent.update_task_state(task_id, TaskState.CANCELED)
        return task.__dict__, 200
    
    def handle_push_notification_set(self, params: Dict[str, Any]) -> Tuple[Dict[str, Any], int]:
        """
        Handle a tasks/pushNotification/set request.
        
        Args:
            params: The parameters for the request
            
        Returns:
            A success response or error
        """
        # Not implemented in this example
        return {"error": "Push notifications not supported"}, 501
    
    def _process_task(self, task_id: str) -> None:
        """
        Process a task asynchronously.
        
        In a real implementation, this would be done in a separate thread or process.
        
        Args:
            task_id: The ID of the task to process
        """
        # Update the task state to working
        task = self.agent.update_task_state(task_id, TaskState.WORKING)
        if not task:
            return
        
        # Get the last message (which should be from the user)
        last_message = task.messages[-1] if task.messages else None
        if not last_message or last_message.role != Role.USER:
            self._complete_task_with_error(task_id, "No user message found")
            return
        
        # Extract the user's request from the message
        user_request = ""
        for part in last_message.parts:
            if getattr(part, "type", None) == "text":
                user_request += getattr(part, "text", "")
        
        if not user_request:
            self._complete_task_with_error(task_id, "No text content in user message")
            return
        
        # Here we would integrate with Wireshark MCP to process the request
        # For example, we might call the WiresharkMCP class to analyze packets
        # and generate insights based on the user's request
        
        # For this example, we'll simulate processing by adding a simple response
        response_message = Message(
            role=Role.AGENT,
            parts=[TextPart(text=f"Processed request: {user_request}")]
        )
        self.agent.add_message_to_task(task_id, response_message)
        
        # Add a sample artifact (in a real implementation, this might be a PCAP analysis)
        artifact = Artifact(
            artifact_id="sample_analysis",
            parts=[
                TextPart(text="Network Traffic Analysis"),
                DataPart(data={"packet_count": 100, "protocols": ["TCP", "HTTP", "DNS"]})
            ]
        )
        self.agent.add_artifact_to_task(task_id, artifact)
        
        # Complete the task
        self.agent.update_task_state(task_id, TaskState.COMPLETED)
    
    def _complete_task_with_error(self, task_id: str, error_message: str) -> None:
        """
        Complete a task with an error.
        
        Args:
            task_id: The ID of the task to complete
            error_message: The error message
        """
        task = self.agent.get_task(task_id)
        if not task:
            return
        
        task.errors.append({"message": error_message})
        self.agent.update_task_state(task_id, TaskState.FAILED)
