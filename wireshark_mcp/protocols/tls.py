"""
TLS protocol analyzer for Wireshark MCP.

This module provides analysis capabilities for TLS/SSL traffic,
including handshake details, cipher suites, certificate information,
and security assessments.
"""

from typing import Dict, List, Any, Optional
import re
import json
from datetime import datetime

from .base import BaseProtocolAnalyzer


class TLSProtocolAnalyzer(BaseProtocolAnalyzer):
    """
    Protocol analyzer for TLS (Transport Layer Security) traffic.
    
    This analyzer extracts details about TLS handshakes, cipher suites,
    certificate information, and potential security issues from TLS traffic.
    """
    
    protocol_name = "TLS"
    
    # Common TLS/SSL record types
    RECORD_TYPES = {
        20: "Change Cipher Spec",
        21: "Alert",
        22: "Handshake",
        23: "Application Data"
    }
    
    # Handshake message types
    HANDSHAKE_TYPES = {
        1: "Client Hello",
        2: "Server Hello",
        4: "New Session Ticket",
        8: "Encrypted Extensions",
        11: "Certificate",
        12: "Server Key Exchange",
        13: "Certificate Request",
        14: "Server Hello Done",
        15: "Certificate Verify",
        16: "Client Key Exchange",
        20: "Finished"
    }
    
    # TLS versions
    TLS_VERSIONS = {
        "0x0300": "SSL 3.0",
        "0x0301": "TLS 1.0",
        "0x0302": "TLS 1.1",
        "0x0303": "TLS 1.2",
        "0x0304": "TLS 1.3"
    }
    
    # Weak cipher suites that should be flagged
    WEAK_CIPHERS = [
        "TLS_RSA_WITH_NULL_",
        "TLS_RSA_WITH_RC4_",
        "TLS_RSA_WITH_3DES_",
        "TLS_RSA_WITH_DES_",
        "TLS_RSA_EXPORT",
        "TLS_DHE_RSA_EXPORT",
        "TLS_DHE_DSS_EXPORT",
        "_MD5",
        "_SHA_"  # Original SHA-1
    ]
    
    def extract_features(self, 
                       packets: List[Dict[str, Any]], 
                       **kwargs) -> Dict[str, Any]:
        """
        Extract TLS-specific features from packet data.
        
        Args:
            packets: List of packet dictionaries
            **kwargs: Additional extraction parameters
            
        Returns:
            Dictionary of extracted TLS features
        """
        # Filter for TLS packets
        tls_packets = self._filter_packets(packets, "tls")
        
        # Group packets into TLS conversations
        conversations = self._extract_conversations(tls_packets)
        
        # Extract features for each conversation
        conv_features = []
        for conv_id, conv_packets in conversations.items():
            # Sort packets by time
            sorted_packets = sorted(conv_packets, key=lambda p: float(p.get('timestamp', 0)))
            
            # Extract basic conversation info
            src_ip, src_port, dst_ip, dst_port = self._parse_conversation_id(conv_id)
            
            # Extract handshake details
            handshake_info = self._extract_handshake_info(sorted_packets)
            
            # Extract certificate info if present
            certificate_info = self._extract_certificate_info(sorted_packets)
            
            # Extract application data metrics
            app_data_metrics = self._extract_app_data_metrics(sorted_packets)
            
            # Identify potential security issues
            security_issues = self._identify_security_issues(
                handshake_info, 
                certificate_info,
                sorted_packets
            )
            
            # Compile conversation features
            conv_feature = {
                "conversation_id": conv_id,
                "source_ip": src_ip,
                "source_port": src_port,
                "destination_ip": dst_ip,
                "destination_port": dst_port,
                "handshake": handshake_info,
                "certificates": certificate_info,
                "application_data": app_data_metrics,
                "security_issues": security_issues,
                "packets": sorted_packets[:10] if kwargs.get('include_packets', False) else []
            }
            
            conv_features.append(conv_feature)
        
        # Compile overall TLS statistics
        statistics = {
            "total_tls_packets": len(tls_packets),
            "total_conversations": len(conversations),
            "tls_versions": self._count_tls_versions(conv_features),
            "cipher_suites": self._count_cipher_suites(conv_features),
            "security_issues_count": sum(len(f["security_issues"]) for f in conv_features)
        }
        
        return {
            "conversations": conv_features,
            "statistics": statistics
        }
    
    def generate_context(self, 
                       features: Dict[str, Any], 
                       detail_level: int = 2,
                       max_conversations: int = 5,
                       **kwargs) -> Dict[str, Any]:
        """
        Generate AI-friendly context from the extracted TLS features.
        
        Args:
            features: Dictionary of extracted features
            detail_level: Level of detail (1-3, where 3 is most detailed)
            max_conversations: Maximum number of conversations to include
            **kwargs: Additional context parameters
            
        Returns:
            Dictionary with formatted context
        """
        conversations = features.get("conversations", [])[:max_conversations]
        statistics = features.get("statistics", {})
        
        # Generate context summary
        summary = self._generate_summary(conversations, statistics)
        
        # Generate findings based on security issues
        findings = self._generate_findings(conversations, statistics)
        
        # Generate formatted conversations
        formatted_convs = []
        for conv in conversations:
            formatted_conv = self._format_conversation(conv, detail_level)
            formatted_convs.append(formatted_conv)
        
        return {
            "protocol": self.protocol_name,
            "summary": summary,
            "statistics": statistics,
            "findings": findings,
            "conversations": formatted_convs
        }
    
    def extract_insights(self, 
                        packets: List[Dict[str, Any]], 
                        **kwargs) -> Dict[str, Any]:
        """
        Extract deeper insights from TLS traffic.
        
        Args:
            packets: List of packet dictionaries
            **kwargs: Insight extraction parameters
            
        Returns:
            Dictionary of TLS insights
        """
        features = self.extract_features(packets)
        conversations = features.get("conversations", [])
        
        # Focus on security assessment
        security_assessment = self._assess_security(conversations)
        
        # Analyze handshake patterns
        handshake_patterns = self._analyze_handshake_patterns(conversations)
        
        # Analyze certificate usage
        certificate_insights = self._analyze_certificates(conversations)
        
        return {
            "protocol": self.protocol_name,
            "security_assessment": security_assessment,
            "handshake_patterns": handshake_patterns,
            "certificate_insights": certificate_insights,
            "recommendations": self._generate_recommendations(security_assessment)
        }
    
    def _parse_conversation_id(self, conv_id: str) -> tuple:
        """Parse the conversation ID to extract IPs and ports."""
        parts = conv_id.split('-')
        if len(parts) < 2:
            return ("Unknown", "Unknown", "Unknown", "Unknown")
        
        src_parts = parts[0].split(':')
        dst_parts = parts[1].split(':')
        
        if len(src_parts) == 2 and len(dst_parts) == 2:
            return (src_parts[0], src_parts[1], dst_parts[0], dst_parts[1])
        else:
            return (parts[0], "", parts[1], "")
    
    def _extract_handshake_info(self, packets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract TLS handshake information from packets."""
        handshake_info = {
            "client_hello": None,
            "server_hello": None,
            "tls_version": None,
            "cipher_suite": None,
            "extensions": [],
            "key_exchange": None,
            "completion_time": None
        }
        
        client_hello_time = None
        handshake_complete_time = None
        
        for packet in packets:
            tls_layer = packet.get('tls', {})
            
            # Check for handshake record type
            record_type = tls_layer.get('record.content_type')
            if record_type == '22':  # Handshake
                handshake_type = tls_layer.get('handshake.type')
                
                # Process Client Hello
                if handshake_type == '1':
                    client_hello_time = float(packet.get('timestamp', 0))
                    handshake_info["client_hello"] = {
                        "timestamp": client_hello_time,
                        "version": self._get_tls_version(tls_layer.get('handshake.version')),
                        "random": tls_layer.get('handshake.random'),
                        "cipher_suites": self._extract_cipher_suites(tls_layer),
                        "extensions": self._extract_extensions(tls_layer)
                    }
                
                # Process Server Hello
                elif handshake_type == '2':
                    handshake_info["server_hello"] = {
                        "timestamp": float(packet.get('timestamp', 0)),
                        "version": self._get_tls_version(tls_layer.get('handshake.version')),
                        "random": tls_layer.get('handshake.random'),
                        "cipher_suite": tls_layer.get('handshake.ciphersuite'),
                        "extensions": self._extract_extensions(tls_layer)
                    }
                    
                    # Update selected version and cipher suite
                    handshake_info["tls_version"] = self._get_tls_version(tls_layer.get('handshake.version'))
                    handshake_info["cipher_suite"] = tls_layer.get('handshake.ciphersuite')
                
                # Process Finished message (end of handshake)
                elif handshake_type == '20':
                    handshake_complete_time = float(packet.get('timestamp', 0))
            
            # Track Key Exchange information
            if 'handshake.type' in tls_layer and tls_layer['handshake.type'] in ('12', '16'):
                handshake_info["key_exchange"] = {
                    "algorithm": tls_layer.get('handshake.sig_algorithm', 'Unknown'),
                    "curve": tls_layer.get('handshake.ecdh_curve', tls_layer.get('handshake.dh_p_len', 'Unknown'))
                }
        
        # Calculate handshake completion time if possible
        if client_hello_time and handshake_complete_time:
            handshake_info["completion_time"] = handshake_complete_time - client_hello_time
        
        return handshake_info
    
    def _extract_cipher_suites(self, tls_layer: Dict[str, Any]) -> List[str]:
        """Extract cipher suites from TLS layer."""
        cipher_suites = []
        for key, value in tls_layer.items():
            if key.startswith('handshake.ciphersuite.'):
                cipher_suites.append(value)
        return cipher_suites
    
    def _extract_extensions(self, tls_layer: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract TLS extensions from TLS layer."""
        extensions = []
        extension_types = {}
        
        # First pass to gather extension types
        for key, value in tls_layer.items():
            if key.startswith('handshake.extension.type') and key != 'handshake.extension.types':
                parts = key.split('.')
                if len(parts) >= 3:
                    index = parts[2]
                    extension_types[index] = value
        
        # Second pass to gather extension data
        for index, ext_type in extension_types.items():
            extension = {"type": ext_type}
            
            # Look for other fields related to this extension
            for key, value in tls_layer.items():
                if key.startswith(f'handshake.extension.{index}.'):
                    field_name = key.replace(f'handshake.extension.{index}.', '')
                    extension[field_name] = value
            
            extensions.append(extension)
        
        return extensions
        
    def _extract_certificate_info(self, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract certificate information from TLS packets."""
        certificates = []
        
        for packet in packets:
            tls_layer = packet.get('tls', {})
            
            # Check for certificate message
            if tls_layer.get('handshake.type') == '11':  # Certificate
                # Try to extract certificate details
                cert_info = {}
                
                for key, value in tls_layer.items():
                    if key.startswith('x509sat.'):
                        # X.509 Subject Alternative Name
                        field = key.replace('x509sat.', '')
                        cert_info[f"san_{field}"] = value
                    
                    elif key.startswith('x509af.'):
                        # X.509 field
                        field = key.replace('x509af.', '')
                        cert_info[field] = value
                    
                    elif key.startswith('x509ce.'):
                        # X.509 Certificate Extension
                        field = key.replace('x509ce.', '')
                        cert_info[f"ext_{field}"] = value
                
                # Key certificate fields to extract
                important_fields = [
                    'serialNumber', 'notBefore', 'notAfter', 
                    'san_dNSName', 'subjectCommonName', 'issuerCommonName'
                ]
                
                # If we have some certificate info, add it
                if any(field in cert_info for field in important_fields):
                    cert_info['timestamp'] = packet.get('timestamp')
                    certificates.append(cert_info)
        
        return certificates
    
    def _extract_app_data_metrics(self, packets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract metrics about TLS application data."""
        app_data_packets = [p for p in packets if p.get('tls', {}).get('record.content_type') == '23']
        
        total_bytes = sum(int(p.get('length', 0)) for p in app_data_packets)
        packet_count = len(app_data_packets)
        
        # Calculate time range if possible
        if packet_count > 1:
            start_time = min(float(p.get('timestamp', 0)) for p in app_data_packets)
            end_time = max(float(p.get('timestamp', 0)) for p in app_data_packets)
            duration = end_time - start_time
        else:
            duration = 0
            
        return {
            "packet_count": packet_count,
            "total_bytes": total_bytes,
            "duration": duration,
            "bytes_per_second": total_bytes / duration if duration > 0 else 0
        }
    
    def _identify_security_issues(self, 
                                handshake_info: Dict[str, Any],
                                certificate_info: List[Dict[str, Any]],
                                packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify potential security issues in the TLS connection."""
        issues = []
        
        # Check TLS version
        tls_version = handshake_info.get("tls_version")
        if tls_version in ("SSL 3.0", "TLS 1.0", "TLS 1.1"):
            issues.append({
                "severity": "high",
                "type": "outdated_protocol",
                "description": f"Outdated protocol version: {tls_version}",
                "recommendation": "Update to TLS 1.2 or preferably TLS 1.3"
            })
        
        # Check cipher suite
        cipher_suite = handshake_info.get("cipher_suite", "")
        if any(weak in cipher_suite for weak in self.WEAK_CIPHERS):
            issues.append({
                "severity": "high",
                "type": "weak_cipher",
                "description": f"Weak cipher suite: {cipher_suite}",
                "recommendation": "Update server configuration to use secure cipher suites"
            })
        
        # Check certificates
        for cert in certificate_info:
            # Check expiration
            if 'notAfter' in cert:
                try:
                    # Parse expiration and compare to current time
                    not_after = cert['notAfter']
                    # Check if it's in the past (would require datetime validation in practice)
                    if "utc" in not_after.lower() and "1970" in not_after:
                        issues.append({
                            "severity": "critical",
                            "type": "expired_certificate",
                            "description": f"Certificate expired: {not_after}",
                            "recommendation": "Renew the TLS certificate"
                        })
                except Exception:
                    pass
            
            # Check for weak signature algorithms
            if 'ext_signatureAlgorithm' in cert:
                sig_alg = cert['ext_signatureAlgorithm']
                if 'md5' in sig_alg.lower() or 'sha1' in sig_alg.lower():
                    issues.append({
                        "severity": "high",
                        "type": "weak_signature",
                        "description": f"Weak certificate signature algorithm: {sig_alg}",
                        "recommendation": "Use certificates with secure signature algorithms (SHA-256 or better)"
                    })
        
        # Check for alerts
        for packet in packets:
            tls_layer = packet.get('tls', {})
            if tls_layer.get('record.content_type') == '21':  # Alert
                alert_level = tls_layer.get('alert.level')
                alert_description = tls_layer.get('alert.description')
                
                if alert_level == '2':  # Fatal
                    issues.append({
                        "severity": "high",
                        "type": "tls_alert",
                        "description": f"Fatal TLS alert: {alert_description}",
                        "recommendation": "Investigate and resolve the cause of the TLS alert"
                    })
        
        return issues
    
    def _count_tls_versions(self, conversations: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count the occurrence of each TLS version."""
        version_counts = {}
        
        for conv in conversations:
            version = conv.get("handshake", {}).get("tls_version")
            if version:
                version_counts[version] = version_counts.get(version, 0) + 1
                
        return version_counts
    
    def _count_cipher_suites(self, conversations: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count the occurrence of each cipher suite."""
        cipher_counts = {}
        
        for conv in conversations:
            cipher = conv.get("handshake", {}).get("cipher_suite")
            if cipher:
                cipher_counts[cipher] = cipher_counts.get(cipher, 0) + 1
                
        return cipher_counts
    
    def _get_tls_version(self, version_hex: Optional[str]) -> str:
        """Convert TLS version hex to human-readable string."""
        if not version_hex:
            return "Unknown"
            
        return self.TLS_VERSIONS.get(version_hex, f"Unknown ({version_hex})")
    
    def _generate_summary(self, 
                        conversations: List[Dict[str, Any]], 
                        statistics: Dict[str, Any]) -> str:
        """Generate a summary of TLS analysis."""
        # Count security issues by severity
        high_issues = 0
        medium_issues = 0
        low_issues = 0
        
        for conv in conversations:
            for issue in conv.get("security_issues", []):
                severity = issue.get("severity", "")
                if severity == "high" or severity == "critical":
                    high_issues += 1
                elif severity == "medium":
                    medium_issues += 1
                else:
                    low_issues += 1
        
        # Create summary text
        summary = f"Analysis of {statistics.get('total_tls_packets', 0)} TLS packets "
        summary += f"across {statistics.get('total_conversations', 0)} conversations. "
        
        # Add version information
        versions = statistics.get("tls_versions", {})
        if versions:
            version_parts = []
            for version, count in versions.items():
                version_parts.append(f"{version} ({count})")
            summary += f"TLS versions used: {', '.join(version_parts)}. "
        
        # Add security overview
        if high_issues > 0:
            summary += f"Found {high_issues} high severity security issues. "
        else:
            summary += "No high severity security issues detected. "
            
        if medium_issues > 0 or low_issues > 0:
            summary += f"Also found {medium_issues} medium and {low_issues} low severity issues."
        
        return summary
