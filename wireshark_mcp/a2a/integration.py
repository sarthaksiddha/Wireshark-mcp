"""
Integration module for connecting Wireshark MCP with A2A.
This module provides the glue code to integrate Wireshark packet analysis
with the A2A protocol.
"""

import logging
from typing import Dict, Any, List, Optional

from .agent import WiresharkA2AAgent, Task, Message, Role, TextPart, DataPart, Artifact
from ..core import WiresharkMCP  # Import WiresharkMCP from core instead of wireshark


logger = logging.getLogger(__name__)


class WiresharkA2AIntegration:
    """
    Integration class for connecting Wireshark MCP with A2A.
    This class handles the conversion between Wireshark packet analysis data
    and A2A protocol structures.
    """
    
    def __init__(self, wireshark_mcp: WiresharkMCP, agent: WiresharkA2AAgent):
        """
        Initialize the integration.
        
        Args:
            wireshark_mcp: The WiresharkMCP instance to use for packet analysis
            agent: The WiresharkA2AAgent instance to handle A2A protocol
        """
        self.wireshark_mcp = wireshark_mcp
        self.agent = agent
    
    def analyze_packet_capture(self, file_path: str, analysis_type: str = "basic", 
                               max_packets: int = 1000) -> Dict[str, Any]:
        """
        Analyze a packet capture using Wireshark MCP and prepare results in A2A format.
        
        Args:
            file_path: Path to the PCAP file
            analysis_type: Type of analysis to perform (basic, security, performance, protocol)
            max_packets: Maximum number of packets to analyze
            
        Returns:
            Analysis results in a format suitable for A2A
        """
        try:
            # Use WiresharkMCP to analyze the packet capture
            # The generate_context method signature might be different based on the actual implementation
            # Adjust the parameters accordingly
            context = self.wireshark_mcp.generate_context(
                max_packets=max_packets,
                include_statistics=True
            )
            
            # Convert the Wireshark MCP context to A2A-compatible format
            result = self._convert_to_a2a_format(context, analysis_type)
            
            return result
        except Exception as e:
            logger.exception(f"Error analyzing packet capture: {file_path}")
            return {"error": str(e)}
    
    def _convert_to_a2a_format(self, context: Dict[str, Any], analysis_type: str) -> Dict[str, Any]:
        """
        Convert Wireshark MCP context to A2A-compatible format.
        
        Args:
            context: The Wireshark MCP context
            analysis_type: Type of analysis performed
            
        Returns:
            A2A-compatible format for the analysis results
        """
        # Extract relevant information from the context
        packet_summary = context.get("packets", [])
        statistics = context.get("statistics", {})
        
        # Create a data structure for A2A
        result = {
            "analysis_type": analysis_type,
            "packet_count": len(packet_summary),
            "statistics": statistics,
            "summary": packet_summary[:10],  # First 10 packets for summary
            "insights": self._generate_insights(context)
        }
        
        return result
    
    def _generate_insights(self, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate insights from the Wireshark MCP context.
        
        Args:
            context: The Wireshark MCP context
            
        Returns:
            A list of insights generated from the context
        """
        # In a real implementation, this would analyze the context and generate
        # meaningful insights based on packet patterns, protocol behavior, etc.
        
        # Extract data from the context if available
        statistics = context.get("statistics", {})
        summary = context.get("summary", {})
        protocol_data = context.get("protocol_data", {})
        
        # Build insights based on the available data
        insights = []
        
        # Add top talkers if available
        if "top_talkers" in statistics:
            insights.append({
                "type": "top_talkers",
                "description": "Most active IP addresses in the capture",
                "data": statistics["top_talkers"]
            })
        
        # Add protocol distribution if available in summary
        protocols = summary.get("protocols", {})
        if protocols:
            insights.append({
                "type": "protocol_distribution",
                "description": "Distribution of protocols in the capture",
                "data": protocols
            })
        
        # Add protocol-specific insights if available
        for protocol, proto_context in protocol_data.items():
            insights.append({
                "type": f"{protocol.lower()}_analysis",
                "description": f"Analysis of {protocol} traffic",
                "data": proto_context
            })
        
        # If no specific insights could be generated, add a generic one
        if not insights:
            insights.append({
                "type": "general",
                "description": "Basic packet analysis",
                "data": {"packet_count": len(context.get("packets", []))}
            })
        
        return insights
    
    def create_artifact_from_analysis(self, task_id: str, analysis_result: Dict[str, Any]) -> Optional[Artifact]:
        """
        Create an A2A artifact from the analysis result.
        
        Args:
            task_id: The ID of the task to add the artifact to
            analysis_result: The analysis result from analyze_packet_capture
            
        Returns:
            The created artifact, or None if there was an error
        """
        try:
            # Create a text summary
            summary_text = f"Analysis of packet capture\n"
            summary_text += f"Analysis type: {analysis_result.get('analysis_type', 'basic')}\n"
            summary_text += f"Packet count: {analysis_result.get('packet_count', 0)}\n"
            
            # Create the artifact
            artifact = Artifact(
                artifact_id=f"packet_analysis_{task_id}",
                parts=[
                    TextPart(text=summary_text),
                    DataPart(data=analysis_result)
                ]
            )
            
            # Add the artifact to the task
            self.agent.add_artifact_to_task(task_id, artifact)
            
            return artifact
        except Exception as e:
            logger.exception(f"Error creating artifact for task {task_id}")
            return None
