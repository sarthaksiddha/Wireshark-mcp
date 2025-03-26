"""Advanced network flow analysis module."""

import typing
from collections import defaultdict

class FlowAnalyzer:
    """Comprehensive network flow tracking and analysis."""
    
    def __init__(self, packets: typing.List[dict]):
        """Initialize flow analyzer with packet data.
        
        Args:
            packets (List[dict]): List of parsed network packets
        """
        self.packets = packets
        self.flows = defaultdict(list)
        self._extract_flows()
    
    def _extract_flows(self):
        """Extract and categorize network flows."""
        for packet in self.packets:
            try:
                src_ip = packet.get('_source', {}).get('layers', {}).get('ip.src')
                dst_ip = packet.get('_source', {}).get('layers', {}).get('ip.dst')
                src_port = packet.get('_source', {}).get('layers', {}).get('tcp.srcport')
                dst_port = packet.get('_source', {}).get('layers', {}).get('tcp.dstport')
                protocol = packet.get('_source', {}).get('layers', {}).get('frame.protocols', '')
                timestamp = packet.get('_source', {}).get('layers', {}).get('frame.time_epoch')
                
                if src_ip and dst_ip:
                    flow_key = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                    flow_info = {
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'protocol': protocol,
                        'timestamp': float(timestamp) if timestamp else None,
                        'packet_details': packet
                    }
                    self.flows[flow_key].append(flow_info)
            except Exception:
                continue
    
    def analyze_flows(self, 
                      min_packets_threshold: int = 5,
                      time_window: float = 60.0) -> dict:
        """Analyze network flows with various metrics.
        
        Args:
            min_packets_threshold (int): Minimum number of packets to consider a flow significant
            time_window (float): Time window for flow analysis in seconds
        
        Returns:
            dict: Detailed flow analysis results
        """
        flow_analysis = {
            'total_flows': len(self.flows),
            'significant_flows': [],
            'flow_statistics': {
                'protocols': defaultdict(int),
                'packet_counts': {}
            }
        }
        
        for flow_key, flow_packets in self.flows.items():
            if len(flow_packets) >= min_packets_threshold:
                # Analyze significant flows
                first_packet = flow_packets[0]
                last_packet = flow_packets[-1]
                
                flow_duration = (last_packet['timestamp'] - first_packet['timestamp']) \
                    if first_packet['timestamp'] and last_packet['timestamp'] else 0
                
                significant_flow = {
                    'flow_key': flow_key,
                    'src_ip': first_packet['src_ip'],
                    'dst_ip': first_packet['dst_ip'],
                    'src_port': first_packet['src_port'],
                    'dst_port': first_packet['dst_port'],
                    'protocol': first_packet['protocol'],
                    'packet_count': len(flow_packets),
                    'duration': flow_duration
                }
                
                flow_analysis['significant_flows'].append(significant_flow)
                
                # Update protocol statistics
                flow_analysis['flow_statistics']['protocols'][first_packet['protocol']] += 1
                flow_analysis['flow_statistics']['packet_counts'][flow_key] = len(flow_packets)
        
        return flow_analysis
    
    def detect_anomalous_flows(self, 
                                packet_threshold: int = 50,
                                time_threshold: float = 10.0) -> typing.List[dict]:
        """Detect potentially anomalous network flows.
        
        Args:
            packet_threshold (int): Maximum number of packets in a normal flow
            time_threshold (float): Maximum time for a normal flow in seconds
        
        Returns:
            List of anomalous flows
        """
        anomalous_flows = []
        
        for flow_key, flow_packets in self.flows.items():
            if len(flow_packets) > packet_threshold:
                # Too many packets in a single flow
                anomalous_flows.append({
                    'type': 'high_packet_count',
                    'flow_key': flow_key,
                    'packet_count': len(flow_packets)
                })
            
            # Check time between first and last packet
            if flow_packets and len(flow_packets) > 1:
                first_packet = flow_packets[0]
                last_packet = flow_packets[-1]
                
                flow_duration = (last_packet['timestamp'] - first_packet['timestamp']) \
                    if first_packet['timestamp'] and last_packet['timestamp'] else 0
                
                if flow_duration > time_threshold:
                    anomalous_flows.append({
                        'type': 'long_duration',
                        'flow_key': flow_key,
                        'duration': flow_duration
                    })
        
        return anomalous_flows