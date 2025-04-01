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
    
    def generate_context(self, 
                        features: Dict[str, Any], 
                        detail_level: int = 2,
                        max_conversations: int = 10) -> Dict[str, Any]:
        """
        Generate AI-friendly context from SMTP features.
        
        Args:
            features: Dictionary containing extracted SMTP features
            detail_level: Level of detail to include (1-3)
            max_conversations: Maximum number of conversations to include
            
        Returns:
            Dictionary containing AI-friendly SMTP context
        """
        summary = features.get('summary', {})
        sessions = features.get('sessions', {})
        transactions = features.get('transactions', [])
        
        # Filter transactions to the most interesting ones
        filtered_transactions = self._select_interesting_transactions(
            transactions, max_transactions=max_conversations
        )
        
        # Structure the context by detail level
        context = {
            'summary': summary,
            'protocol': self.protocol_name,
            'transactions': []
        }
        
        # For security context, look for suspicious patterns
        context['security_insights'] = self._extract_security_insights(features)
        
        # Add transactions with appropriate detail level
        for transaction in filtered_transactions:
            context_transaction = self._format_transaction(transaction, detail_level)
            context['transactions'].append(context_transaction)
        
        # If detail level is high, add session information
        if detail_level >= 3:
            # Choose most active sessions
            active_sessions = sorted(
                sessions.values(),
                key=lambda s: s['transaction_count'],
                reverse=True
            )[:max_conversations]
            
            context['sessions'] = active_sessions
        
        return context
    
    def _select_interesting_transactions(self, 
                                     transactions: List[Dict[str, Any]], 
                                     max_transactions: int = 10) -> List[Dict[str, Any]]:
        """
        Select the most interesting SMTP transactions for analysis.
        
        This prioritizes completed transactions, large recipient lists,
        and error responses.
        """
        # First prioritize completed transactions
        completed = [t for t in transactions if t.get('completed', False)]
        
        # Then look for transactions with error responses
        error_transactions = []
        for transaction in transactions:
            for response in transaction.get('responses', []):
                code = response.get('code', '')
                if code and (code.startswith('4') or code.startswith('5')):
                    error_transactions.append(transaction)
                    break
        
        # Prioritize transactions with multiple recipients
        multi_recipient = [
            t for t in transactions 
            if len(t.get('rcpt_to', [])) > 1
        ]
        
        # Combine and ensure uniqueness
        interesting_transactions = []
        for t_list in [completed, error_transactions, multi_recipient, transactions]:
            for t in t_list:
                if t not in interesting_transactions:
                    interesting_transactions.append(t)
                    if len(interesting_transactions) >= max_transactions:
                        return interesting_transactions
        
        return interesting_transactions[:max_transactions]
    
    def _format_transaction(self, 
                         transaction: Dict[str, Any], 
                         detail_level: int) -> Dict[str, Any]:
        """Format a transaction for the context with appropriate detail level."""
        # Basic transaction info
        result = {
            'timestamp': transaction.get('timestamp'),
            'mail_from': transaction.get('mail_from'),
            'rcpt_to': transaction.get('rcpt_to'),
            'completed': transaction.get('completed', False)
        }
        
        # Add query/response structure for Claude formatter
        result['query'] = {
            'mail_from': transaction.get('mail_from'),
            'rcpt_to': transaction.get('rcpt_to'),
            'has_data': transaction.get('has_data', False)
        }
        
        # Add basic response info
        response_codes = [r.get('code') for r in transaction.get('responses', []) if r.get('code')]
        result['response'] = {
            'codes': response_codes,
            'successful': any(c.startswith('2') for c in response_codes) if response_codes else False
        }
        
        # Add detailed command/response sequence for higher detail levels
        if detail_level >= 2:
            # Add commands and responses with timestamps
            result['command_sequence'] = self._format_command_sequence(
                transaction.get('commands', []),
                transaction.get('responses', [])
            )
        
        return result
    
    def _format_command_sequence(self, 
                              commands: List[Dict[str, Any]], 
                              responses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Format the command/response sequence in chronological order."""
        # Combine commands and responses
        sequence = []
        
        for cmd in commands:
            sequence.append({
                'type': 'command',
                'timestamp': cmd.get('timestamp'),
                'command': cmd.get('command'),
                'parameter': cmd.get('parameter')
            })
        
        for resp in responses:
            sequence.append({
                'type': 'response',
                'timestamp': resp.get('timestamp'),
                'code': resp.get('code'),
                'message': resp.get('parameter')
            })
        
        # Sort by timestamp
        sequence.sort(key=lambda x: x.get('timestamp', 0))
        
        return sequence
    
    def _extract_security_insights(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Extract security insights from SMTP features."""
        transactions = features.get('transactions', [])
        sessions = features.get('sessions', {})
        
        insights = {
            'auth_failures': 0,
            'suspicious_patterns': [],
            'plaintext_auth': False,
            'missing_tls': 0
        }
        
        # Check for auth failures
        for session in sessions.values():
            if session.get('auth_attempts', 0) > 0 and not session.get('authenticated', False):
                insights['auth_failures'] += 1
            
            if not session.get('uses_tls', False):
                insights['missing_tls'] += 1
                
                # Check if authentication was attempted without TLS
                if session.get('auth_attempts', 0) > 0:
                    insights['plaintext_auth'] = True
                    insights['suspicious_patterns'].append({
                        'type': 'plaintext_auth',
                        'client_ip': session.get('client_ip'),
                        'server_ip': session.get('server_ip'),
                        'description': 'Authentication attempted over plaintext connection'
                    })
        
        # Check for suspicious patterns in transactions
        for transaction in transactions:
            mail_from = transaction.get('mail_from', '')
            rcpt_to = transaction.get('rcpt_to', [])
            
            # Check for high number of recipients (potential spam)
            if len(rcpt_to) > 10:
                insights['suspicious_patterns'].append({
                    'type': 'high_recipient_count',
                    'mail_from': mail_from,
                    'recipient_count': len(rcpt_to),
                    'description': f'Email sent to {len(rcpt_to)} recipients'
                })
            
            # Check for suspicious sender domains
            if mail_from and '@' in mail_from:
                domain = mail_from.split('@')[-1]
                suspicious_domains = ['temp', 'disposable', 'anonymous']
                if any(word in domain.lower() for word in suspicious_domains):
                    insights['suspicious_patterns'].append({
                        'type': 'suspicious_sender_domain',
                        'mail_from': mail_from,
                        'domain': domain,
                        'description': f'Email sent from potentially suspicious domain: {domain}'
                    })
        
        return insights
