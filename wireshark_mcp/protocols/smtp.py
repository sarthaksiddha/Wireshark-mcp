"""
SMTP Protocol Analyzer for Wireshark MCP.

This module provides SMTP protocol analysis capabilities, extracting and structuring
SMTP mail transactions from network packet captures.
"""

import logging
import re
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime

from .base import BaseProtocolAnalyzer

logger = logging.getLogger(__name__)

# SMTP command regex patterns
SMTP_PATTERNS = {
    'ehlo': re.compile(r'EHLO\s+(.+)$', re.IGNORECASE),
    'helo': re.compile(r'HELO\s+(.+)$', re.IGNORECASE),
    'mail_from': re.compile(r'MAIL\s+FROM:\s*(?:<(.+)>|(.+))$', re.IGNORECASE),
    'rcpt_to': re.compile(r'RCPT\s+TO:\s*(?:<(.+)>|(.+))$', re.IGNORECASE),
    'data': re.compile(r'DATA$', re.IGNORECASE),
    'quit': re.compile(r'QUIT$', re.IGNORECASE),
    'rset': re.compile(r'RSET$', re.IGNORECASE),
    'starttls': re.compile(r'STARTTLS$', re.IGNORECASE),
    'auth': re.compile(r'AUTH\s+(.+)$', re.IGNORECASE),
}

# SMTP response code categories
SMTP_RESPONSE_CATEGORIES = {
    '2xx': 'Success',
    '3xx': 'Intermediate Success',
    '4xx': 'Temporary Failure',
    '5xx': 'Permanent Failure'
}

class SMTPProtocolAnalyzer(BaseProtocolAnalyzer):
    """
    Analyzer for SMTP protocol packets.
    
    Extracts and structures SMTP commands and responses, tracking email
    transactions and authentication attempts.
    """
    
    protocol_name = "SMTP"
    
    def __init__(self):
        super().__init__()
    
    def extract_features(self, 
                      packets: List[Dict[str, Any]], 
                      include_headers: bool = True,
                      include_body: bool = False) -> Dict[str, Any]:
        """
        Extract SMTP protocol features from packets.
        
        Args:
            packets: List of packets (from Wireshark/tshark)
            include_headers: Whether to include SMTP headers
            include_body: Whether to include email body content
            
        Returns:
            Dictionary containing extracted SMTP features
        """
        # Track SMTP sessions and transactions
        sessions = {}
        transactions = []
        current_transaction = None
        
        # Stats for summary
        total_commands = 0
        auth_attempts = 0
        success_responses = 0
        error_responses = 0
        
        # Process each packet
        for packet in packets:
            # Skip packets without SMTP data
            if 'smtp' not in packet:
                continue
            
            smtp_data = packet.get('smtp', {})
            
            # Get basic packet info
            timestamp = float(packet.get('timestamp', 0))
            ip_src = packet.get('ip', {}).get('src')
            ip_dst = packet.get('ip', {}).get('dst')
            
            # Extract SMTP commands and responses
            command = smtp_data.get('request', {}).get('command')
            request_parameter = smtp_data.get('request', {}).get('parameter')
            response_code = smtp_data.get('response', {}).get('code')
            response_parameter = smtp_data.get('response', {}).get('parameter')
            
            # Create session key based on src-dst IP pair
            if ip_src and ip_dst:
                session_key = f"{ip_src}-{ip_dst}"
                
                # Create or update session
                if session_key not in sessions:
                    sessions[session_key] = {
                        'client_ip': ip_src,
                        'server_ip': ip_dst,
                        'first_seen': timestamp,
                        'last_seen': timestamp,
                        'commands': [],
                        'responses': [],
                        'authenticated': False,
                        'uses_tls': False,
                        'transaction_count': 0
                    }
                else:
                    sessions[session_key]['last_seen'] = timestamp
            
            # Process SMTP command
            if command:
                total_commands += 1
                
                # If we have a valid session, add command to it
                if session_key in sessions:
                    sessions[session_key]['commands'].append({
                        'command': command,
                        'parameter': request_parameter,
                        'timestamp': timestamp
                    })
                
                # Handle specific commands
                if command.upper() == 'MAIL':
                    # Start new transaction
                    current_transaction = {
                        'timestamp': timestamp,
                        'session': session_key if session_key in sessions else None,
                        'mail_from': request_parameter,
                        'rcpt_to': [],
                        'has_data': False,
                        'completed': False,
                        'commands': [],
                        'responses': []
                    }
                    
                    # Add command to transaction
                    current_transaction['commands'].append({
                        'command': command,
                        'parameter': request_parameter,
                        'timestamp': timestamp
                    })
                
                elif command.upper() == 'RCPT' and current_transaction:
                    # Add recipient to current transaction
                    current_transaction['rcpt_to'].append(request_parameter)
                    
                    # Add command to transaction
                    current_transaction['commands'].append({
                        'command': command,
                        'parameter': request_parameter,
                        'timestamp': timestamp
                    })
                
                elif command.upper() == 'DATA' and current_transaction:
                    # Mark transaction as having data
                    current_transaction['has_data'] = True
                    
                    # Add command to transaction
                    current_transaction['commands'].append({
                        'command': command,
                        'parameter': request_parameter,
                        'timestamp': timestamp
                    })
                
                elif command.upper() == 'AUTH':
                    # Track authentication attempts
                    auth_attempts += 1
                    
                    # If we have a valid session, mark auth attempt
                    if session_key in sessions:
                        sessions[session_key]['auth_attempts'] = sessions[session_key].get('auth_attempts', 0) + 1
                
                elif command.upper() == 'STARTTLS':
                    # Mark session as using TLS
                    if session_key in sessions:
                        sessions[session_key]['uses_tls'] = True
            
            # Process SMTP response
            if response_code:
                # If we have a valid session, add response
                if session_key in sessions:
                    sessions[session_key]['responses'].append({
                        'code': response_code,
                        'parameter': response_parameter,
                        'timestamp': timestamp
                    })
                
                # Add response to current transaction if exists
                if current_transaction:
                    current_transaction['responses'].append({
                        'code': response_code,
                        'parameter': response_parameter,
                        'timestamp': timestamp
                    })
                
                # Track response code stats
                response_code_prefix = response_code[0] if response_code else '0'
                if response_code_prefix == '2':
                    success_responses += 1
                elif response_code_prefix in ['4', '5']:
                    error_responses += 1
                    
                # Check for completion of transaction
                if current_transaction and current_transaction['has_data']:
                    if response_code.startswith('2'):
                        # Success response after DATA = completed transaction
                        current_transaction['completed'] = True
                        transactions.append(current_transaction)
                        
                        # Update session transaction count
                        if session_key in sessions:
                            sessions[session_key]['transaction_count'] += 1
                        
                        # Reset current transaction
                        current_transaction = None
        
        # Create summary
        summary = {
            'total_sessions': len(sessions),
            'total_transactions': len(transactions),
            'completed_transactions': sum(1 for t in transactions if t['completed']),
            'total_commands': total_commands,
            'auth_attempts': auth_attempts,
            'success_responses': success_responses,
            'error_responses': error_responses,
            'tls_sessions': sum(1 for s in sessions.values() if s['uses_tls'])
        }
        
        # Prepare the final features dictionary
        features = {
            'summary': summary,
            'sessions': sessions,
            'transactions': transactions
        }
        
        return features
