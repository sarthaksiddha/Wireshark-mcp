"""
Security Analyzer module for Wireshark MCP.

This module provides advanced security analysis for network packet captures,
detecting potential security issues, suspicious patterns, and anomalies.
"""

import ipaddress
import itertools
import logging
from typing import List, Dict, Any, Set, Tuple

logger = logging.getLogger(__name__)

class SecurityAnalyzer:
    """
    Performs security-focused analysis on network packet captures.
    
    Features include detection of:
    - Port scanning patterns
    - Known malware communication patterns
    - Unusual port usage
    - Unencrypted protocols
    - Suspicious behavioral patterns
    """
    
    def __init__(self, packets: List[Dict[str, Any]]):
        """
        Initialize the security analyzer with packet data.
        
        Args:
            packets: List of packet dictionaries
        """
        self.packets = packets
        self.ip_data = {}  # Store IP-related data
        self.connection_data = {}  # Store connection data
        self.port_data = {}  # Store port usage data
        
        # Known suspicious ports (example list, would be more comprehensive in production)
        self.suspicious_ports = {
            '4444': 'Metasploit default',
            '1080': 'SOCKS proxy',
            '6667': 'IRC (often used by botnets)',
            '6666': 'IRC alternate',
            '31337': 'Back Orifice',
            '12345': 'NetBus',
            '5900': 'VNC',
            '3389': 'RDP',
            '8080': 'Common alternate HTTP',
            '8443': 'Common alternate HTTPS',
            '6000': 'X11',
        }
        
        # Common well-known ports that are less suspicious
        self.common_ports = {
            '80': 'HTTP',
            '443': 'HTTPS',
            '22': 'SSH',
            '23': 'Telnet',
            '25': 'SMTP',
            '53': 'DNS',
            '110': 'POP3',
            '143': 'IMAP',
            '161': 'SNMP',
            '389': 'LDAP',
            '3306': 'MySQL',
            '5432': 'PostgreSQL',
            '27017': 'MongoDB',
        }
        
        # Initialize data structures from packets
        self._process_packets()
    
    def _process_packets(self):
        """Process packets to extract security-relevant information."""
        for packet in self.packets:
            # Process IP layer data
            if 'ip' in packet:
                src_ip = packet['ip'].get('src')
                dst_ip = packet['ip'].get('dst')
                
                if src_ip:
                    if src_ip not in self.ip_data:
                        self.ip_data[src_ip] = {
                            'sent_packets': 0,
                            'received_packets': 0,
                            'dst_ips': set(),
                            'dst_ports': {},  # port -> count
                            'protocols': set(),
                        }
                    
                    self.ip_data[src_ip]['sent_packets'] += 1
                    
                    if dst_ip:
                        self.ip_data[src_ip]['dst_ips'].add(dst_ip)
                
                if dst_ip:
                    if dst_ip not in self.ip_data:
                        self.ip_data[dst_ip] = {
                            'sent_packets': 0,
                            'received_packets': 0,
                            'dst_ips': set(),
                            'dst_ports': {},
                            'protocols': set(),
                        }
                    
                    self.ip_data[dst_ip]['received_packets'] += 1
            
            # Process TCP and UDP port data
            for proto in ['tcp', 'udp']:
                if proto in packet:
                    src_port = packet[proto].get('srcport')
                    dst_port = packet[proto].get('dstport')
                    
                    # Protocol detection
                    if 'ip' in packet and src_ip:
                        if proto == 'tcp':
                            self.ip_data[src_ip]['protocols'].add('TCP')
                        elif proto == 'udp':
                            self.ip_data[src_ip]['protocols'].add('UDP')
                    
                    # Track destination ports
                    if src_ip and dst_port:
                        if dst_port not in self.ip_data[src_ip]['dst_ports']:
                            self.ip_data[src_ip]['dst_ports'][dst_port] = 0
                        self.ip_data[src_ip]['dst_ports'][dst_port] += 1
                    
                    # Track general port usage
                    for port in [src_port, dst_port]:
                        if port:
                            if port not in self.port_data:
                                self.port_data[port] = {
                                    'count': 0,
                                    'protocol': proto.upper(),
                                    'ips': set(),
                                }
                            self.port_data[port]['count'] += 1
                            if 'ip' in packet and src_ip:
                                self.port_data[port]['ips'].add(src_ip)
                            if 'ip' in packet and dst_ip:
                                self.port_data[port]['ips'].add(dst_ip)
            
            # Process protocol information
            for layer in packet.get('layers', []):
                protocol = layer.get('protocol')
                if protocol and 'ip' in packet and src_ip:
                    self.ip_data[src_ip]['protocols'].add(protocol.upper())
            
            # Connection tracking (for flow analysis)
            if 'ip' in packet and 'tcp' in packet:
                src_ip = packet['ip'].get('src')
                dst_ip = packet['ip'].get('dst')
                src_port = packet['tcp'].get('srcport')
                dst_port = packet['tcp'].get('dstport')
                
                if src_ip and dst_ip and src_port and dst_port:
                    conn_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                    
                    if conn_key not in self.connection_data:
                        self.connection_data[conn_key] = {
                            'packets': 0,
                            'bytes': 0,
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'src_port': src_port,
                            'dst_port': dst_port,
                            'protocol': 'TCP',
                            'flags': set(),
                        }
                    
                    self.connection_data[conn_key]['packets'] += 1
                    
                    # Track packet length
                    if 'length' in packet:
                        self.connection_data[conn_key]['bytes'] += int(packet['length'])
                    
                    # Track TCP flags
                    if 'flags' in packet['tcp']:
                        for flag, value in packet['tcp']['flags'].items():
                            if int(value) == 1:
                                self.connection_data[conn_key]['flags'].add(flag)
    
    def analyze(self,
              detect_scanning: bool = True,
              detect_malware_patterns: bool = True,
              highlight_unusual_ports: bool = True,
              check_encryption: bool = True) -> Dict[str, Any]:
        """
        Perform security analysis on the packet capture.
        
        Args:
            detect_scanning: Whether to look for port scanning patterns
            detect_malware_patterns: Whether to check for known malware patterns
            highlight_unusual_ports: Whether to highlight unusual port usage
            check_encryption: Whether to analyze encryption usage
            
        Returns:
            Dictionary containing security analysis results
        """
        results = {
            'summary': {
                'total_packets': len(self.packets),
                'unique_ips': len(self.ip_data),
                'unique_ports': len(self.port_data),
                'connections': len(self.connection_data),
            },
            'alerts': [],
        }
        
        # Detect port scanning
        if detect_scanning:
            scanning_results = self._detect_scanning()
            results['port_scanning'] = scanning_results
            
            # Add alerts for significant findings
            for scanner in scanning_results.get('potential_scanners', []):
                results['alerts'].append({
                    'type': 'port_scan',
                    'severity': 'medium',
                    'source_ip': scanner['ip'],
                    'description': f"Potential port scan: {scanner['unique_ports']} ports across {scanner['unique_hosts']} hosts",
                    'details': scanner
                })
        
        # Check for malware patterns
        if detect_malware_patterns:
            malware_results = self._detect_malware_patterns()
            results['malware_indicators'] = malware_results
            
            # Add alerts for significant findings
            for indicator in malware_results.get('indicators', []):
                results['alerts'].append({
                    'type': 'malware_indicator',
                    'severity': 'high',
                    'source_ip': indicator['ip'],
                    'description': indicator['description'],
                    'details': indicator
                })
        
        # Highlight unusual ports
        if highlight_unusual_ports:
            port_results = self._highlight_unusual_ports()
            results['unusual_ports'] = port_results
            
            # Add alerts for significant findings
            for port_info in port_results.get('suspicious_ports', []):
                results['alerts'].append({
                    'type': 'suspicious_port',
                    'severity': 'low',
                    'port': port_info['port'],
                    'protocol': port_info['protocol'],
                    'description': f"Suspicious port {port_info['port']}/{port_info['protocol']} ({port_info['service_name']}) used by {len(port_info['ips'])} hosts",
                    'details': port_info
                })
        
        # Check encryption
        if check_encryption:
            encryption_results = self._check_encryption()
            results['encryption_analysis'] = encryption_results
            
            # Add alerts for significant findings
            for unencrypted in encryption_results.get('unencrypted_services', []):
                results['alerts'].append({
                    'type': 'unencrypted_traffic',
                    'severity': 'medium',
                    'port': unencrypted['port'],
                    'protocol': unencrypted['protocol'],
                    'description': f"Unencrypted {unencrypted['service']} traffic detected on port {unencrypted['port']}",
                    'details': unencrypted
                })
        
        # Sort alerts by severity
        severity_rank = {'high': 0, 'medium': 1, 'low': 2}
        results['alerts'] = sorted(
            results['alerts'], 
            key=lambda x: severity_rank.get(x['severity'], 100)
        )
        
        return results
    
    def _detect_scanning(self) -> Dict[str, Any]:
        """
        Detect potential port scanning activity.
        
        Returns:
            Dictionary with port scanning analysis
        """
        results = {
            'potential_scanners': [],
            'scan_targets': [],
        }
        
        # Method 1: IP that connects to many ports on a single host
        for src_ip, data in self.ip_data.items():
            # Group by destination IP
            ip_port_map = {}
            for dst_ip in data['dst_ips']:
                ip_port_map[dst_ip] = set()
            
            # Count ports per destination
            for conn_key, conn_data in self.connection_data.items():
                if conn_data['src_ip'] == src_ip:
                    dst_ip = conn_data['dst_ip']
                    if dst_ip in ip_port_map:
                        ip_port_map[dst_ip].add(conn_data['dst_port'])
            
            # Check for scanning behavior
            for dst_ip, ports in ip_port_map.items():
                if len(ports) >= 10:  # Arbitrary threshold
                    results['potential_scanners'].append({
                        'ip': src_ip,
                        'target': dst_ip,
                        'unique_ports': len(ports),
                        'ports': list(ports)[:20],  # Limit to 20 examples
                        'unique_hosts': 1,
                        'scan_type': 'vertical'
                    })
        
        # Method 2: IP that connects to the same port on many hosts
        for src_ip, data in self.ip_data.items():
            if len(data['dst_ips']) > 10:  # Arbitrary threshold
                # Count same port connections
                port_host_map = {}
                for conn_key, conn_data in self.connection_data.items():
                    if conn_data['src_ip'] == src_ip:
                        dst_port = conn_data['dst_port']
                        if dst_port not in port_host_map:
                            port_host_map[dst_port] = set()
                        port_host_map[dst_port].add(conn_data['dst_ip'])
                
                # Check for horizontal scanning
                for port, hosts in port_host_map.items():
                    if len(hosts) > 5:  # Arbitrary threshold
                        results['potential_scanners'].append({
                            'ip': src_ip,
                            'port': port,
                            'unique_hosts': len(hosts),
                            'hosts': list(hosts)[:20],  # Limit to 20 examples
                            'unique_ports': 1,
                            'scan_type': 'horizontal'
                        })
        
        # Method 3: Identify scan targets
        target_count = {}
        for scanner in results['potential_scanners']:
            if 'target' in scanner:
                target = scanner['target']
                if target not in target_count:
                    target_count[target] = 0
                target_count[target] += 1
        
        # Hosts targeted by multiple scanners
        for target, count in target_count.items():
            if count > 1:
                results['scan_targets'].append({
                    'ip': target,
                    'scanner_count': count
                })
        
        return results
    
    def _detect_malware_patterns(self) -> Dict[str, Any]:
        """
        Detect common malware communication patterns.
        
        Returns:
            Dictionary with malware indicator analysis
        """
        results = {
            'indicators': [],
        }
        
        # Pattern 1: Beaconing behavior (regular communication intervals)
        # Simplified version - in production would analyze temporal patterns
        
        # Pattern 2: Connection to known suspicious ports
        suspicious_connections = []
        for conn_key, conn_data in self.connection_data.items():
            dst_port = conn_data['dst_port']
            if dst_port in self.suspicious_ports:
                suspicious_connections.append({
                    'src_ip': conn_data['src_ip'],
                    'dst_ip': conn_data['dst_ip'],
                    'port': dst_port,
                    'service': self.suspicious_ports[dst_port],
                    'packets': conn_data['packets']
                })
        
        # Pattern 3: Unusual protocol behavior
        # e.g., DNS requests with abnormally high data volume or frequency
        unusual_protocols = []
        for ip, data in self.ip_data.items():
            protocol_count = {}
            for protocol in data['protocols']:
                if protocol not in protocol_count:
                    protocol_count[protocol] = 0
                protocol_count[protocol] += 1
            
            # Detect unusual protocol patterns (example: HTTP over non-standard port)
            # This is a simplified example
            
        # Combine detected patterns into indicators
        for conn in suspicious_connections:
            results['indicators'].append({
                'ip': conn['src_ip'],
                'type': 'suspicious_port',
                'description': f"Connection to suspicious service: {conn['service']} on port {conn['port']}",
                'details': conn
            })
        
        # Add other indicators based on analysis...
        
        return results
    
    def _highlight_unusual_ports(self) -> Dict[str, Any]:
        """
        Highlight unusual port usage.
        
        Returns:
            Dictionary with unusual port analysis
        """
        results = {
            'high_numbered_ports': [],
            'suspicious_ports': [],
            'uncommon_service_ports': [],
        }
        
        for port, data in self.port_data.items():
            port_num = int(port)
            
            # High-numbered ephemeral ports with server behavior
            if port_num > 10000 and data['count'] > 5:
                results['high_numbered_ports'].append({
                    'port': port,
                    'protocol': data['protocol'],
                    'packet_count': data['count'],
                    'ips': list(data['ips'])
                })
            
            # Known suspicious ports
            if port in self.suspicious_ports:
                results['suspicious_ports'].append({
                    'port': port,
                    'protocol': data['protocol'],
                    'packet_count': data['count'],
                    'ips': list(data['ips']),
                    'service_name': self.suspicious_ports[port]
                })
            
            # Standard services on non-standard ports
            # This is a simplified example - would be more sophisticated in production
            
        return results
    
    def _check_encryption(self) -> Dict[str, Any]:
        """
        Analyze encryption usage in the traffic.
        
        Returns:
            Dictionary with encryption analysis
        """
        results = {
            'encrypted_protocols': [],
            'unencrypted_services': [],
            'encryption_statistics': {
                'encrypted_packets': 0,
                'unencrypted_packets': 0,
                'encrypted_bytes': 0,
                'unencrypted_bytes': 0,
            }
        }
        
        # Known encrypted protocols
        encrypted_protocols = {'TLS', 'SSL', 'SSH', 'HTTPS', 'SMTPS', 'FTPS', 'SFTP', 'IMAPS', 'POP3S', 'LDAPS'}
        
        # Known unencrypted protocols that should be encrypted
        sensitive_unencrypted = {
            'HTTP': 80,
            'FTP': 21,
            'TELNET': 23,
            'SMTP': 25,
            'POP3': 110,
            'IMAP': 143,
            'SNMP': 161,
            'LDAP': 389,
        }
        
        # Count encrypted vs unencrypted
        encrypted_conn_count = 0
        unencrypted_conn_count = 0
        
        # Track services observed on standard ports
        observed_services = {}
        
        # Analyze connections
        for conn_key, conn_data in self.connection_data.items():
            is_encrypted = False
            for protocol in self.ip_data.get(conn_data['src_ip'], {}).get('protocols', set()):
                if protocol in encrypted_protocols:
                    is_encrypted = True
                    break
            
            # Classify connection
            if is_encrypted:
                encrypted_conn_count += 1
                results['encryption_statistics']['encrypted_packets'] += conn_data['packets']
                results['encryption_statistics']['encrypted_bytes'] += conn_data['bytes']
            else:
                unencrypted_conn_count += 1
                results['encryption_statistics']['unencrypted_packets'] += conn_data['packets']
                results['encryption_statistics']['unencrypted_bytes'] += conn_data['bytes']
                
                # Check if this is a sensitive unencrypted service
                dst_port = conn_data['dst_port']
                for service, port in sensitive_unencrypted.items():
                    if dst_port == str(port):
                        observed_services[service] = observed_services.get(service, 0) + 1
        
        # Add results for unencrypted sensitive services
        for service, count in observed_services.items():
            port = sensitive_unencrypted[service]
            results['unencrypted_services'].append({
                'service': service,
                'port': str(port),
                'protocol': 'TCP',  # Most services are TCP, could be more precise
                'connection_count': count
            })
        
        return results
