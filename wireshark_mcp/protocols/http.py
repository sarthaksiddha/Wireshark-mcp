"""
HTTP protocol analyzer implementation.
"""

from typing import Dict, List, Any, Optional
from collections import defaultdict
import re
from urllib.parse import urlparse

from .base import BaseProtocolAnalyzer


class HTTPProtocolAnalyzer(BaseProtocolAnalyzer):
    """
    HTTP protocol analyzer for extracting and analyzing HTTP traffic.
    """
    
    protocol_name = "HTTP"
    
    # Common HTTP status code categories
    STATUS_CATEGORIES = {
        "1xx": "Informational",
        "2xx": "Success",
        "3xx": "Redirection",
        "4xx": "Client Error",
        "5xx": "Server Error"
    }
    
    # Security-sensitive HTTP headers
    SECURITY_HEADERS = [
        "content-security-policy",
        "x-xss-protection",
        "x-content-type-options",
        "strict-transport-security",
        "x-frame-options",
        "referrer-policy"
    ]
    
    def extract_features(self, 
                        packets: List[Dict[str, Any]], 
                        include_headers: bool = True,
                        include_body: bool = False,
                        **kwargs) -> Dict[str, Any]:
        """
        Extract HTTP-specific features from packet data.
        
        Args:
            packets: List of packet dictionaries
            include_headers: Whether to include HTTP headers
            include_body: Whether to include HTTP bodies
            **kwargs: Additional extraction parameters
            
        Returns:
            Dictionary of extracted HTTP features
        """
        # Filter to only HTTP packets
        http_packets = self._filter_packets(packets)
        
        # Group packets into HTTP conversations
        conversations = self._extract_conversations(http_packets)
        
        # Extract HTTP requests and responses
        http_data = {
            "conversations": {},
            "statistics": {
                "total_requests": 0,
                "total_responses": 0,
                "status_codes": defaultdict(int),
                "methods": defaultdict(int),
                "hosts": defaultdict(int),
                "content_types": defaultdict(int),
                "total_bytes": 0
            },
            "security_findings": []
        }
        
        # Process each conversation
        for conv_id, conv_packets in conversations.items():
            requests = []
            responses = []
            
            for packet in conv_packets:
                http = packet.get('http', {})
                
                # Determine if this is a request or response
                if 'request' in http:
                    requests.append(self._extract_http_request(packet, include_headers, include_body))
                    http_data["statistics"]["total_requests"] += 1
                    
                    # Update method statistics
                    method = http.get('request_method', '')
                    if method:
                        http_data["statistics"]["methods"][method] += 1
                    
                    # Update host statistics
                    host = None
                    for header in http.get('request_header', []):
                        if header.get('name', '').lower() == 'host':
                            host = header.get('value', '')
                            break
                    
                    if host:
                        http_data["statistics"]["hosts"][host] += 1
                        
                elif 'response' in http:
                    response = self._extract_http_response(packet, include_headers, include_body)
                    responses.append(response)
                    http_data["statistics"]["total_responses"] += 1
                    
                    # Update status code statistics
                    status_code = http.get('response_code', '')
                    if status_code:
                        http_data["statistics"]["status_codes"][status_code] += 1
                    
                    # Update content type statistics
                    content_type = None
                    for header in http.get('response_header', []):
                        if header.get('name', '').lower() == 'content-type':
                            content_type = header.get('value', '').split(';')[0].strip()
                            break
                    
                    if content_type:
                        http_data["statistics"]["content_types"][content_type] += 1
                    
                    # Check for missing security headers
                    self._check_security_headers(response, http_data["security_findings"])
                
                # Update byte count
                http_data["statistics"]["total_bytes"] += int(packet.get('length', 0))
            
            # Match requests with responses where possible
            matched_exchanges = self._match_requests_responses(requests, responses)
            
            http_data["conversations"][conv_id] = {
                "exchanges": matched_exchanges,
                "unmatched_requests": [req for req in requests if not req.get('_matched')],
                "unmatched_responses": [resp for resp in responses if not resp.get('_matched')]
            }
            
            # Remove temporary matching flags
            for req in requests:
                req.pop('_matched', None)
            for resp in responses:
                resp.pop('_matched', None)
        
        return http_data
    
    def generate_context(self, 
                        features: Dict[str, Any], 
                        detail_level: int = 2,
                        max_conversations: int = 10,
                        **kwargs) -> Dict[str, Any]:
        """
        Generate AI-friendly context from HTTP features.
        
        Args:
            features: Dictionary of extracted HTTP features
            detail_level: Level of detail (1-3, where 3 is most detailed)
            max_conversations: Maximum number of conversations to include
            **kwargs: Additional context parameters
            
        Returns:
            Dictionary with formatted HTTP context
        """
        conversations = features.get("conversations", {})
        statistics = features.get("statistics", {})
        security_findings = features.get("security_findings", [])
        
        # Prepare context
        context = {
            "protocol": "HTTP",
            "summary": {
                "total_requests": statistics.get("total_requests", 0),
                "total_responses": statistics.get("total_responses", 0),
                "total_conversations": len(conversations),
                "total_bytes_transferred": statistics.get("total_bytes", 0)
            },
            "top_statistics": {
                "status_codes": self._get_top_items(statistics.get("status_codes", {}), 10),
                "methods": self._get_top_items(statistics.get("methods", {}), 5),
                "hosts": self._get_top_items(statistics.get("hosts", {}), 5),
                "content_types": self._get_top_items(statistics.get("content_types", {}), 5)
            },
            "security": {
                "findings": security_findings[:10]  # Limit to top 10 findings
            },
            "conversations": {}
        }
        
        # Add HTTP status code descriptions
        status_descriptions = {}
        for status, count in statistics.get("status_codes", {}).items():
            category = self._get_status_category(status)
            status_descriptions[status] = f"{status} - {category}"
        
        context["status_code_descriptions"] = status_descriptions
        
        # Add conversation details based on detail level
        sorted_conversations = sorted(
            conversations.items(),
            key=lambda x: len(x[1]["exchanges"]),
            reverse=True
        )[:max_conversations]
        
        for conv_id, conv_data in sorted_conversations:
            exchanges = conv_data["exchanges"]
            context["conversations"][conv_id] = {
                "exchanges_count": len(exchanges),
                "exchanges": []
            }
            
            # Add exchange details based on detail level
            for exchange in exchanges:
                exchange_summary = {
                    "request": {
                        "method": exchange["request"].get("method", ""),
                        "uri": exchange["request"].get("uri", ""),
                        "version": exchange["request"].get("version", "")
                    },
                    "response": {
                        "status_code": exchange["response"].get("status_code", ""),
                        "status_phrase": exchange["response"].get("status_phrase", ""),
                        "content_length": exchange["response"].get("content_length", 0),
                        "content_type": exchange["response"].get("content_type", "")
                    }
                }
                
                # Add headers for higher detail levels
                if detail_level >= 2:
                    exchange_summary["request"]["headers"] = exchange["request"].get("headers", {})
                    exchange_summary["response"]["headers"] = exchange["response"].get("headers", {})
                
                # Add body preview for highest detail level
                if detail_level >= 3:
                    # Include a preview of the body (truncated)
                    req_body = exchange["request"].get("body", "")
                    resp_body = exchange["response"].get("body", "")
                    
                    exchange_summary["request"]["body_preview"] = req_body[:200] + "..." if len(req_body) > 200 else req_body
                    exchange_summary["response"]["body_preview"] = resp_body[:200] + "..." if len(resp_body) > 200 else resp_body
                
                context["conversations"][conv_id]["exchanges"].append(exchange_summary)
        
        return context
    
    def extract_insights(self, 
                        packets: List[Dict[str, Any]], 
                        extract_queries: bool = True,
                        analyze_response_codes: bool = True,
                        detect_tunneling: bool = False,
                        **kwargs) -> Dict[str, Any]:
        """
        Extract deeper HTTP-specific insights.
        
        Args:
            packets: List of packet dictionaries
            extract_queries: Whether to extract URL query patterns
            analyze_response_codes: Whether to analyze response code patterns
            detect_tunneling: Whether to look for HTTP tunneling
            **kwargs: Additional parameters
            
        Returns:
            Dictionary of HTTP insights
        """
        features = self.extract_features(packets)
        insights = {
            "protocol": "HTTP",
            "findings": [],
            "patterns": {}
        }
        
        # Extract URL and query patterns
        if extract_queries:
            query_patterns = self._analyze_query_patterns(features)
            insights["patterns"]["queries"] = query_patterns
        
        # Analyze response code patterns
        if analyze_response_codes:
            code_patterns = self._analyze_response_codes(features)
            insights["patterns"]["response_codes"] = code_patterns
        
        # Detect possible HTTP tunneling
        if detect_tunneling:
            tunneling = self._detect_tunneling(features)
            if tunneling:
                insights["tunneling"] = tunneling
        
        return insights
    
    def _extract_http_request(self, 
                            packet: Dict[str, Any], 
                            include_headers: bool = True,
                            include_body: bool = False) -> Dict[str, Any]:
        """Extract HTTP request details from a packet."""
        http = packet.get('http', {})
        request = {
            "method": http.get('request_method', ''),
            "uri": http.get('request_uri', ''),
            "version": http.get('request_version', ''),
            "timestamp": packet.get('timestamp', 0),
            "frame_number": packet.get('frame_number', '')
        }
        
        # Parse URI components if available
        uri = request["uri"]
        if uri:
            parsed_uri = urlparse(uri)
            request["uri_path"] = parsed_uri.path
            request["uri_query"] = parsed_uri.query
        
        # Extract headers if requested
        if include_headers:
            headers = {}
            for header in http.get('request_header', []):
                name = header.get('name', '').lower()
                value = header.get('value', '')
                headers[name] = value
            
            request["headers"] = headers
        
        # Extract body if requested
        if include_body and 'request_body' in http:
            request["body"] = http.get('request_body', '')
            request["body_length"] = len(request["body"])
        
        return request
    
    def _extract_http_response(self, 
                              packet: Dict[str, Any], 
                              include_headers: bool = True,
                              include_body: bool = False) -> Dict[str, Any]:
        """Extract HTTP response details from a packet."""
        http = packet.get('http', {})
        response = {
            "status_code": http.get('response_code', ''),
            "status_phrase": http.get('response_phrase', ''),
            "version": http.get('response_version', ''),
            "timestamp": packet.get('timestamp', 0),
            "frame_number": packet.get('frame_number', '')
        }
        
        # Extract headers if requested
        if include_headers:
            headers = {}
            for header in http.get('response_header', []):
                name = header.get('name', '').lower()
                value = header.get('value', '')
                headers[name] = value
            
            response["headers"] = headers
            
            # Extract common useful headers
            response["content_type"] = headers.get('content-type', '').split(';')[0].strip()
            
            try:
                response["content_length"] = int(headers.get('content-length', 0))
            except (ValueError, TypeError):
                response["content_length"] = 0
        
        # Extract body if requested
        if include_body and 'response_body' in http:
            response["body"] = http.get('response_body', '')
            response["body_length"] = len(response["body"])
        
        return response
    
    def _match_requests_responses(self, 
                               requests: List[Dict[str, Any]], 
                               responses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Match HTTP requests with their corresponding responses."""
        exchanges = []
        
        # Sort by timestamp
        sorted_requests = sorted(requests, key=lambda x: float(x.get('timestamp', 0)))
        sorted_responses = sorted(responses, key=lambda x: float(x.get('timestamp', 0)))
        
        # Match requests with responses
        for req in sorted_requests:
            req_time = float(req.get('timestamp', 0))
            
            # Find the first response that comes after this request
            for resp in sorted_responses:
                if resp.get('_matched'):
                    continue
                
                resp_time = float(resp.get('timestamp', 0))
                if resp_time > req_time:
                    # Match found
                    exchanges.append({
                        "request": req,
                        "response": resp,
                        "time_delta": resp_time - req_time
                    })
                    
                    # Mark as matched
                    req['_matched'] = True
                    resp['_matched'] = True
                    break
        
        return exchanges
    
    def _check_security_headers(self, 
                             response: Dict[str, Any], 
                             findings: List[str]) -> None:
        """Check HTTP response for missing security headers."""
        if 'headers' not in response:
            return
        
        headers = response.get('headers', {})
        for header in self.SECURITY_HEADERS:
            if header not in headers:
                findings.append(f"Missing security header: {header}")
    
    def _get_status_category(self, status_code: str) -> str:
        """Get the category for an HTTP status code."""
        try:
            category_key = status_code[0] + "xx"
            return self.STATUS_CATEGORIES.get(category_key, "Unknown")
        except (IndexError, TypeError):
            return "Unknown"
    
    def _get_top_items(self, 
                      items: Dict[str, int], 
                      limit: int = 10) -> Dict[str, int]:
        """Get the top N items from a dictionary by count."""
        return dict(sorted(items.items(), key=lambda x: x[1], reverse=True)[:limit])
    
    def _analyze_query_patterns(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze HTTP query patterns."""
        query_patterns = {
            "common_parameters": defaultdict(int),
            "parameter_types": defaultdict(set),
            "suspicious_patterns": []
        }
        
        # Extract all request URIs with queries
        for conv_id, conv_data in features.get("conversations", {}).items():
            for exchange in conv_data.get("exchanges", []):
                request = exchange.get("request", {})
                uri = request.get("uri", "")
                
                if "?" in uri:
                    parsed = urlparse(uri)
                    query = parsed.query
                    
                    if query:
                        # Extract parameters
                        params = query.split("&")
                        for param in params:
                            if "=" in param:
                                name, value = param.split("=", 1)
                                query_patterns["common_parameters"][name] += 1
                                
                                # Detect parameter types
                                param_type = self._detect_parameter_type(value)
                                query_patterns["parameter_types"][name].add(param_type)
                                
                                # Check for suspicious patterns
                                if self._is_suspicious_parameter(name, value):
                                    query_patterns["suspicious_patterns"].append({
                                        "parameter": name,
                                        "value_sample": value,
                                        "uri": uri
                                    })
        
        # Convert parameter types from sets to lists
        query_patterns["parameter_types"] = {
            k: list(v) for k, v in query_patterns["parameter_types"].items()
        }
        
        # Get top parameters
        query_patterns["top_parameters"] = dict(
            sorted(query_patterns["common_parameters"].items(), 
                  key=lambda x: x[1], 
                  reverse=True)[:10]
        )
        
        return query_patterns
    
    def _detect_parameter_type(self, value: str) -> str:
        """Detect the data type of a parameter value."""
        if not value:
            return "empty"
        
        # Check for numeric types
        if value.isdigit():
            return "integer"
        
        if re.match(r'^-?\d+(\.\d+)?$', value):
            return "number"
        
        # Check for dates
        if re.match(r'^\d{4}-\d{2}-\d{2}', value):
            return "date"
        
        # Check for UUIDs
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', value, re.I):
            return "uuid"
        
        # Check for email addresses
        if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
            return "email"
        
        # Check for URLs
        if re.match(r'^https?://', value):
            return "url"
        
        # Otherwise, assume it's a string
        return "string"
    
    def _is_suspicious_parameter(self, name: str, value: str) -> bool:
        """Check if a parameter name or value looks suspicious."""
        # Check for common injection patterns
        suspicious_patterns = [
            r"['\"].*--",            # SQL injection
            r"<script.*>",           # XSS
            r"/etc/passwd",          # Path traversal
            r"\.\.(/|\\)",           # Directory traversal
            r";.*\s*\w+\s*=",        # Command injection
            r"(exec|eval|system)\(", # Code injection
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, value, re.I):
                return True
        
        # Check for suspicious parameter names
        suspicious_names = [
            "passwd", "password", "pwd", 
            "token", "key", "secret",
            "command", "cmd", "exec",
            "query", "sql", "debug"
        ]
        
        name_lower = name.lower()
        for sus_name in suspicious_names:
            if sus_name in name_lower:
                return True
        
        return False
    
    def _analyze_response_codes(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze HTTP response code patterns."""
        status_codes = features.get("statistics", {}).get("status_codes", {})
        
        code_patterns = {
            "success_rate": 0,
            "error_rate": 0,
            "redirection_rate": 0,
            "top_codes": {},
            "unusual_codes": []
        }
        
        total_responses = features.get("statistics", {}).get("total_responses", 0)
        if total_responses > 0:
            success_count = sum(count for code, count in status_codes.items() 
                               if code.startswith('2'))
            error_count = sum(count for code, count in status_codes.items() 
                             if code.startswith('4') or code.startswith('5'))
            redirect_count = sum(count for code, count in status_codes.items() 
                                if code.startswith('3'))
            
            code_patterns["success_rate"] = success_count / total_responses
            code_patterns["error_rate"] = error_count / total_responses
            code_patterns["redirection_rate"] = redirect_count / total_responses
        
        # Get top status codes
        code_patterns["top_codes"] = dict(
            sorted(status_codes.items(), key=lambda x: x[1], reverse=True)[:5]
        )
        
        # Identify unusual status codes
        common_codes = {'200', '301', '302', '304', '400', '401', '403', '404', '500'}
        for code in status_codes:
            if code not in common_codes:
                code_patterns["unusual_codes"].append(code)
        
        return code_patterns
    
    def _detect_tunneling(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Detect potential HTTP tunneling."""
        tunneling_indicators = []
        
        # Look for indicators of HTTP tunneling
        for conv_id, conv_data in features.get("conversations", {}).items():
            for exchange in conv_data.get("exchanges", []):
                request = exchange.get("request", {})
                response = exchange.get("response", {})
                
                # Check for CONNECT method
                if request.get("method") == "CONNECT":
                    tunneling_indicators.append({
                        "type": "CONNECT method",
                        "uri": request.get("uri", ""),
                        "frame": request.get("frame_number")
                    })
                
                # Check for unusually large request or response bodies
                if request.get("body_length", 0) > 10000:
                    tunneling_indicators.append({
                        "type": "Large request body",
                        "size": request.get("body_length", 0),
                        "uri": request.get("uri", ""),
                        "frame": request.get("frame_number")
                    })
                
                # Check for unusual content types in large responses
                if response.get("body_length", 0) > 10000:
                    content_type = response.get("content_type", "")
                    if content_type and content_type not in ["text/html", "application/json", "text/javascript"]:
                        tunneling_indicators.append({
                            "type": "Unusual content type for large response",
                            "content_type": content_type,
                            "size": response.get("body_length", 0),
                            "frame": response.get("frame_number")
                        })
        
        if tunneling_indicators:
            return {
                "detected": True,
                "indicators": tunneling_indicators
            }
        
        return {"detected": False}
