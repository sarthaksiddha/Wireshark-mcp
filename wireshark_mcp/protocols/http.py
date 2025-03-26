import subprocess
import json
import re
from typing import Dict, Any, List, Optional, Tuple
import tempfile
import os

from .base import BaseProtocolAnalyzer

class HTTPAnalyzer(BaseProtocolAnalyzer):
    """
    Analyzer for HTTP protocol traffic.
    Extracts and contextualizes HTTP requests and responses.
    """
    
    protocol_name = "HTTP"
    
    def analyze(self, capture_file: str, 
               include_headers: bool = True,
               include_body: bool = False,
               max_conversations: int = 20,
               max_body_size: int = 1024) -> Dict[str, Any]:
        """
        Analyze HTTP traffic in a capture file.
        
        Args:
            capture_file: Path to the capture file
            include_headers: Whether to include HTTP headers
            include_body: Whether to include HTTP bodies
            max_conversations: Maximum number of conversations to include
            max_body_size: Maximum size of body content to include (in bytes)
            
        Returns:
            HTTP analysis results
        """
        # Use tshark to extract HTTP packets
        cmd = [
            "tshark", "-r", capture_file,
            "-Y", "http",
            "-T", "json"
        ]
        
        try:
            process = subprocess.run(
                cmd, 
                capture_output=True,
                text=True,
                check=True
            )
            
            packets = json.loads(process.stdout)
        except subprocess.CalledProcessError as e:
            # Fall back to simplified analysis if tshark fails
            return {
                "protocol": "HTTP",
                "error": f"Failed to extract HTTP data: {str(e)}",
                "conversations": [],
                "statistics": {
                    "request_count": 0,
                    "response_count": 0
                }
            }
        except json.JSONDecodeError:
            return {
                "protocol": "HTTP",
                "error": "Failed to parse tshark output",
                "conversations": [],
                "statistics": {
                    "request_count": 0,
                    "response_count": 0
                }
            }
            
        # Process the packets to extract HTTP conversations
        features = self.extract_features(packets)
        
        # Limit the number of conversations
        if len(features["conversations"]) > max_conversations:
            features["conversations"] = features["conversations"][:max_conversations]
            features["truncated"] = True
        
        # Generate context
        return self.generate_context(
            features,
            detail_level=3 if include_body else (2 if include_headers else 1)
        )
    
    def extract_features(self, packets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Extract HTTP features from packets.
        
        Args:
            packets: List of packet dictionaries from tshark
            
        Returns:
            Extracted HTTP features
        """
        conversations = {}
        requests = []
        responses = []
        status_codes = {}
        methods = {}
        hosts = {}
        content_types = {}
        
        for packet in packets:
            # Extract the HTTP layer
            http_layer = None
            for layer_name, layer in packet.get("_source", {}).get("layers", {}).items():
                if layer_name.startswith("http"):
                    http_layer = layer
                    break
            
            if not http_layer:
                continue
                
            # Get stream index for conversation tracking
            tcp_stream = packet.get("_source", {}).get("layers", {}).get("tcp", {}).get("tcp.stream")
            if not tcp_stream:
                continue
                
            stream_key = f"stream_{tcp_stream}"
            
            # Initialize conversation if needed
            if stream_key not in conversations:
                conversations[stream_key] = {
                    "requests": [],
                    "responses": [],
                    "host": None,
                    "uri_path": None
                }
            
            # Process request
            if "http.request" in http_layer:
                request = {
                    "method": http_layer.get("http.request.method", ""),
                    "uri": http_layer.get("http.request.uri", ""),
                    "version": http_layer.get("http.request.version", "")
                }
                
                # Track host
                host = http_layer.get("http.host")
                if host:
                    conversations[stream_key]["host"] = host
                    hosts[host] = hosts.get(host, 0) + 1
                
                # Track URI path
                uri = http_layer.get("http.request.uri", "")
                if uri:
                    conversations[stream_key]["uri_path"] = uri
                
                # Track method
                method = http_layer.get("http.request.method", "")
                if method:
                    methods[method] = methods.get(method, 0) + 1
                
                # Extract headers
                headers = {}
                for key, value in http_layer.items():
                    if key.startswith("http.request.header"):
                        header_match = re.match(r"http\.request\.header\.([^:]+)", key)
                        if header_match:
                            header_name = header_match.group(1).lower()
                            headers[header_name] = value
                
                request["headers"] = headers
                
                # Add body if present
                if "http.file_data" in http_layer:
                    request["body"] = http_layer["http.file_data"]
                
                conversations[stream_key]["requests"].append(request)
                requests.append(request)
            
            # Process response
            elif "http.response" in http_layer:
                response = {
                    "status_code": http_layer.get("http.response.code", ""),
                    "phrase": http_layer.get("http.response.phrase", ""),
                    "version": http_layer.get("http.response.version", "")
                }
                
                # Track status code
                status_code = http_layer.get("http.response.code", "")
                if status_code:
                    status_codes[status_code] = status_codes.get(status_code, 0) + 1
                
                # Extract headers
                headers = {}
                for key, value in http_layer.items():
                    if key.startswith("http.response.header"):
                        header_match = re.match(r"http\.response\.header\.([^:]+)", key)
                        if header_match:
                            header_name = header_match.group(1).lower()
                            headers[header_name] = value
                            
                            # Track content types
                            if header_name == "content-type":
                                content_types[value] = content_types.get(value, 0) + 1
                
                response["headers"] = headers
                
                # Add body if present
                if "http.file_data" in http_layer:
                    response["body"] = http_layer["http.file_data"]
                
                conversations[stream_key]["responses"].append(response)
                responses.append(response)
        
        # Convert the conversation dictionary to a list
        conversation_list = []
        for stream_key, data in conversations.items():
            if data["requests"] or data["responses"]:
                conversation_list.append({
                    "stream": stream_key,
                    "host": data["host"],
                    "uri_path": data["uri_path"],
                    "requests": data["requests"],
                    "responses": data["responses"]
                })
        
        return {
            "conversations": conversation_list,
            "statistics": {
                "request_count": len(requests),
                "response_count": len(responses),
                "status_codes": status_codes,
                "methods": methods,
                "hosts": hosts,
                "content_types": content_types
            }
        }
    
    def generate_context(self, features: Dict[str, Any], detail_level: int = 2) -> Dict[str, Any]:
        """
        Generate a Claude-friendly context from HTTP features.
        
        Args:
            features: Extracted HTTP features
            detail_level: Level of detail to include (1-3)
            
        Returns:
            Context dictionary
        """
        context = {
            "protocol": "HTTP",
            "conversation_count": len(features["conversations"]),
            "statistics": features["statistics"],
            "conversations": []
        }
        
        # Add truncation notice if applicable
        if features.get("truncated", False):
            context["note"] = "Analysis truncated to the maximum number of conversations"
            
        # Process conversations based on detail level
        for convo in features["conversations"]:
            conversation = {
                "host": convo["host"],
                "path": convo["uri_path"],
                "request_count": len(convo["requests"]),
                "response_count": len(convo["responses"])
            }
            
            # Add detailed request/response info based on detail level
            if detail_level >= 2:
                conversation["requests"] = []
                conversation["responses"] = []
                
                # Process requests
                for req in convo["requests"]:
                    request = {
                        "method": req["method"],
                        "uri": req["uri"],
                        "version": req["version"]
                    }
                    
                    # Add headers at detail level 2+
                    if detail_level >= 2 and "headers" in req:
                        # Filter headers to include only the most relevant ones
                        important_headers = [
                            "host", "user-agent", "content-type", "content-length",
                            "cookie", "referer", "origin", "authorization"
                        ]
                        request["headers"] = {
                            k: v for k, v in req["headers"].items()
                            if k.lower() in important_headers
                        }
                    
                    # Add body at detail level 3
                    if detail_level >= 3 and "body" in req:
                        # Truncate body if too large
                        body = req.get("body", "")
                        if len(body) > 1024:
                            body = body[:1021] + "..."
                        request["body"] = body
                    
                    conversation["requests"].append(request)
                
                # Process responses
                for resp in convo["responses"]:
                    response = {
                        "status_code": resp["status_code"],
                        "phrase": resp["phrase"],
                        "version": resp["version"]
                    }
                    
                    # Add headers at detail level 2+
                    if detail_level >= 2 and "headers" in resp:
                        # Filter headers to include only the most relevant ones
                        important_headers = [
                            "content-type", "content-length", "server",
                            "cache-control", "set-cookie", "location"
                        ]
                        response["headers"] = {
                            k: v for k, v in resp["headers"].items()
                            if k.lower() in important_headers
                        }
                    
                    # Add body at detail level 3
                    if detail_level >= 3 and "body" in resp:
                        # Truncate body if too large
                        body = resp.get("body", "")
                        if len(body) > 1024:
                            body = body[:1021] + "..."
                        response["body"] = body
                    
                    conversation["responses"].append(response)
            
            context["conversations"].append(conversation)
        
        return context