"""
DNS Protocol Analyzer for Wireshark MCP.
"""

from typing import List, Dict, Any, Optional, Set
import ipaddress
import logging

from .base import BaseProtocolAnalyzer
from ..protocols import Protocol

logger = logging.getLogger(__name__)

class DNSProtocolAnalyzer(BaseProtocolAnalyzer):
    """
    Analyzer for DNS protocol traffic.
    
    Extracts and processes DNS queries, responses, and related metadata
    to provide context about domain name resolution activities.
    """
    
    protocol_name = "DNS"
    
    def __init__(self):
        """Initialize the DNS Protocol Analyzer."""
        super().__init__()
        self.record_types = {
            1: "A",
            2: "NS",
            5: "CNAME",
            6: "SOA",
            12: "PTR",
            15: "MX",
            16: "TXT",
            28: "AAAA",
            33: "SRV",
            41: "OPT",
            43: "DS",
            46: "RRSIG",
            47: "NSEC",
            48: "DNSKEY",
            50: "NSEC3",
            51: "NSEC3PARAM",
            52: "TLSA"
        }
        
        self.response_codes = {
            0: "No Error",
            1: "Format Error",
            2: "Server Failure",
            3: "Name Error (NXDOMAIN)",
            4: "Not Implemented",
            5: "Refused",
            6: "YX Domain",
            7: "YX RR Set",
            8: "NX RR Set",
            9: "Not Auth",
            10: "Not Zone"
        }
    
    def extract_features(self, 
                        packets: List[Dict[str, Any]], 
                        include_headers: bool = True,
                        include_body: bool = False) -> Dict[str, Any]:
        """
        Extract DNS-specific features from packets.
        
        Args:
            packets: List of packet dictionaries
            include_headers: Whether to include DNS headers
            include_body: Whether to include response data
            
        Returns:
            Dictionary containing extracted DNS features
        """
        queries = []
        responses = []
        transactions = {}  # Track query-response pairs
        domains = set()
        ips = set()
        
        for packet in packets:
            if 'dns' not in packet:
                continue
                
            dns = packet.get('dns', {})
            
            # Extract basic DNS packet information
            try:
                dns_id = dns.get('id', '0')
                flags = dns.get('flags', {})
                is_response = int(flags.get('response', 0)) == 1
                
                # Get timestamp for sorting
                timestamp = float(packet.get('timestamp', 0))
                
                if is_response:
                    # Process response
                    resp_code = int(dns.get('response_code', 0))
                    resp_code_name = self.response_codes.get(resp_code, f"Unknown ({resp_code})")
                    
                    answers = []
                    if 'answers' in dns:
                        for answer in dns.get('answers', []):
                            record_type_num = int(answer.get('type', 0))
                            record_type = self.record_types.get(record_type_num, f"TYPE{record_type_num}")
                            name = answer.get('name', '')
                            ttl = answer.get('ttl', '')
                            data = answer.get('data', '')
                            
                            if name:
                                domains.add(name)
                            
                            # Capture IP addresses
                            if record_type in ["A", "AAAA"] and data:
                                try:
                                    ipaddress.ip_address(data)
                                    ips.add(data)
                                except ValueError:
                                    pass
                                    
                            answers.append({
                                'name': name,
                                'type': record_type,
                                'ttl': ttl,
                                'data': data if include_body else None
                            })
                    
                    response = {
                        'id': dns_id,
                        'timestamp': timestamp,
                        'response_code': resp_code,
                        'response_code_name': resp_code_name,
                        'answers': answers,
                        'authoritative': int(flags.get('authoritative', 0)) == 1,
                        'truncated': int(flags.get('truncated', 0)) == 1,
                        'recursion_desired': int(flags.get('recursion_desired', 0)) == 1,
                        'recursion_available': int(flags.get('recursion_available', 0)) == 1,
                    }
                    
                    if include_headers:
                        response['flags'] = flags
                        
                    responses.append(response)
                    
                    # Match with query if we've seen it
                    if dns_id in transactions:
                        transactions[dns_id]['response'] = response
                        
                else:
                    # Process query
                    questions = []
                    if 'questions' in dns:
                        for question in dns.get('questions', []):
                            name = question.get('name', '')
                            if name:
                                domains.add(name)
                                
                            record_type_num = int(question.get('type', 0))
                            record_type = self.record_types.get(record_type_num, f"TYPE{record_type_num}")
                            
                            questions.append({
                                'name': name,
                                'type': record_type
                            })
                    
                    query = {
                        'id': dns_id,
                        'timestamp': timestamp,
                        'questions': questions,
                        'recursion_desired': int(flags.get('recursion_desired', 0)) == 1
                    }
                    
                    if include_headers:
                        query['flags'] = flags
                        
                    queries.append(query)
                    
                    # Start tracking transaction
                    transactions[dns_id] = {
                        'query': query,
                        'response': None
                    }
                    
            except Exception as e:
                logger.warning(f"Error processing DNS packet: {e}")
                continue
        
        # Create completed transactions list
        completed_transactions = [
            trans for trans in transactions.values() 
            if trans['response'] is not None
        ]
        
        # Sort by timestamp
        completed_transactions.sort(key=lambda x: x['query']['timestamp'])
        queries.sort(key=lambda x: x['timestamp'])
        responses.sort(key=lambda x: x['timestamp'])
        
        return {
            'queries': queries,
            'responses': responses,
            'transactions': completed_transactions,
            'domains': list(domains),
            'ips': list(ips),
            'metadata': {
                'total_queries': len(queries),
                'total_responses': len(responses),
                'completed_transactions': len(completed_transactions),
                'unique_domains': len(domains),
                'unique_ips': len(ips)
            }
        }
    
    def generate_context(self, 
                        features: Dict[str, Any],
                        detail_level: int = 2,
                        max_conversations: int = 10) -> Dict[str, Any]:
        """
        Generate a context dictionary from DNS features.
        
        Args:
            features: Dictionary of extracted DNS features
            detail_level: Level of detail (1-3)
            max_conversations: Maximum number of conversations to include
            
        Returns:
            Dictionary containing DNS context for AI consumption
        """
        # Get basic stats
        metadata = features.get('metadata', {})
        domains = features.get('domains', [])
        ips = features.get('ips', [])
        
        # Get truncated list of transactions
        transactions = features.get('transactions', [])[:max_conversations]
        
        # Create domain frequency analysis
        domain_counts = {}
        for query in features.get('queries', []):
            for question in query.get('questions', []):
                name = question.get('name', '')
                if name:
                    domain_counts[name] = domain_counts.get(name, 0) + 1
                    
        # Sort domains by frequency
        top_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Group transactions by domain name
        domain_transactions = {}
        for trans in features.get('transactions', []):
            query = trans.get('query', {})
            for question in query.get('questions', []):
                name = question.get('name', '')
                if name:
                    if name not in domain_transactions:
                        domain_transactions[name] = []
                    domain_transactions[name].append(trans)
        
        # Create summaries of domain activity
        domain_summaries = {}
        for domain, trans_list in domain_transactions.items():
            # Get response codes
            response_codes = {}
            record_types = {}
            ips_returned = set()
            
            for trans in trans_list:
                response = trans.get('response', {})
                if response:
                    resp_code = response.get('response_code_name', 'Unknown')
                    response_codes[resp_code] = response_codes.get(resp_code, 0) + 1
                    
                    for answer in response.get('answers', []):
                        record_type = answer.get('type', 'Unknown')
                        record_types[record_type] = record_types.get(record_type, 0) + 1
                        
                        if record_type in ["A", "AAAA"]:
                            data = answer.get('data')
                            if data:
                                ips_returned.add(data)
            
            domain_summaries[domain] = {
                'query_count': len(trans_list),
                'response_codes': response_codes,
                'record_types': record_types,
                'ip_addresses': list(ips_returned)
            }
        
        # Generate insights
        insights = []
        
        # Check for NXDOMAINs
        nxdomain_domains = []
        for domain, summary in domain_summaries.items():
            if summary['response_codes'].get('Name Error (NXDOMAIN)', 0) > 0:
                nxdomain_domains.append(domain)
        
        if nxdomain_domains:
            insights.append({
                'type': 'nxdomain',
                'description': f"Found {len(nxdomain_domains)} domains with NXDOMAIN responses",
                'domains': nxdomain_domains[:5]  # Limit to 5 examples
            })
        
        # Check for high query rates
        high_query_domains = [domain for domain, count in top_domains if count > 5]
        if high_query_domains:
            insights.append({
                'type': 'high_query_rate',
                'description': f"Found {len(high_query_domains)} domains with high query rates",
                'domains': high_query_domains[:5]  # Limit to 5 examples
            })
            
        return {
            'summary': {
                'total_queries': metadata.get('total_queries', 0),
                'total_responses': metadata.get('total_responses', 0),
                'completed_transactions': metadata.get('completed_transactions', 0),
                'unique_domains': metadata.get('unique_domains', 0),
                'unique_ips': metadata.get('unique_ips', 0)
            },
            'top_domains': dict(top_domains),
            'domain_summaries': domain_summaries,
            'transactions': transactions,
            'insights': insights
        }
        
    def extract_insights(self,
                         packets: List[Dict[str, Any]],
                         extract_queries: bool = True,
                         analyze_response_codes: bool = True,
                         detect_tunneling: bool = False) -> Dict[str, Any]:
        """
        Extract deeper insights from DNS traffic.
        
        Args:
            packets: List of packet dictionaries
            extract_queries: Whether to analyze query patterns
            analyze_response_codes: Whether to analyze response code patterns
            detect_tunneling: Whether to look for potential DNS tunneling
            
        Returns:
            Dictionary of DNS insights
        """
        features = self.extract_features(packets)
        insights = []
        
        if extract_queries:
            # Analyze query patterns
            queries = features.get('queries', [])
            domains = features.get('domains', [])
            
            # Check for unusual query types
            unusual_types = set()
            query_types = {}
            
            for query in queries:
                for question in query.get('questions', []):
                    qtype = question.get('type', '')
                    query_types[qtype] = query_types.get(qtype, 0) + 1
                    
                    # Consider TXT, NULL as potentially unusual
                    if qtype in ["TXT", "NULL"]:
                        unusual_types.add(qtype)
            
            if unusual_types:
                insights.append({
                    'type': 'unusual_query_types',
                    'description': f"Found potentially unusual query types: {', '.join(unusual_types)}",
                    'query_types': {k: v for k, v in query_types.items() if k in unusual_types}
                })
                
            # Check for long domain names (potential exfiltration)
            long_domains = [d for d in domains if len(d) > 50]
            if long_domains:
                insights.append({
                    'type': 'long_domain_names',
                    'description': f"Found {len(long_domains)} unusually long domain names",
                    'examples': long_domains[:3]
                })
        
        if analyze_response_codes:
            # Analyze response code patterns
            responses = features.get('responses', [])
            
            # Analyze response codes
            response_codes = {}
            for response in responses:
                code_name = response.get('response_code_name', 'Unknown')
                response_codes[code_name] = response_codes.get(code_name, 0) + 1
                
            # Check for high error rates
            total_responses = len(responses)
            error_count = sum(response_codes.get(code, 0) for code in [
                'Format Error', 'Server Failure', 'Name Error (NXDOMAIN)',
                'Not Implemented', 'Refused'
            ])
            
            if total_responses > 0 and (error_count / total_responses) > 0.2:
                insights.append({
                    'type': 'high_error_rate',
                    'description': f"High DNS error rate: {error_count}/{total_responses} responses ({(error_count/total_responses)*100:.1f}%)",
                    'response_codes': response_codes
                })
        
        if detect_tunneling:
            # Check for potential DNS tunneling indicators
            
            # Feature 1: High volume of unique subdomains
            domain_parts = {}
            for domain in features.get('domains', []):
                parts = domain.split('.')
                if len(parts) >= 2:
                    root_domain = '.'.join(parts[-2:])
                    if root_domain not in domain_parts:
                        domain_parts[root_domain] = set()
                    
                    if len(parts) > 2:
                        subdomain = '.'.join(parts[:-2])
                        domain_parts[root_domain].add(subdomain)
            
            tunneling_candidates = []
            for root, subdomains in domain_parts.items():
                if len(subdomains) > 10:  # Arbitrary threshold
                    tunneling_candidates.append({
                        'domain': root,
                        'unique_subdomains': len(subdomains)
                    })
            
            if tunneling_candidates:
                insights.append({
                    'type': 'potential_tunneling',
                    'description': f"Found {len(tunneling_candidates)} domains with suspicious numbers of unique subdomains",
                    'candidates': tunneling_candidates
                })
                
            # Feature 2: Entropy analysis of domain names
            # (Simplified version - in production would use actual entropy calculation)
            high_entropy_domains = []
            for domain in features.get('domains', []):
                parts = domain.split('.')
                for part in parts:
                    if len(part) > 10 and any(c.isdigit() for c in part) and any(c.isalpha() for c in part):
                        high_entropy_domains.append(domain)
                        break
            
            if high_entropy_domains:
                insights.append({
                    'type': 'high_entropy_domains',
                    'description': f"Found {len(high_entropy_domains)} domains with high character entropy (potential encoding)",
                    'examples': high_entropy_domains[:5]
                })
        
        return {
            'query_insights': insights if extract_queries else [],
            'response_insights': insights if analyze_response_codes else [],
            'tunneling_indicators': insights if detect_tunneling else []
        }
