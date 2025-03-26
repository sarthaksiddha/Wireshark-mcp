"""
Filter module for handling Wireshark display filters.
"""

import re
from typing import List, Optional, Union


class Filter:
    """
    Class for building and validating Wireshark display filters.
    
    This class helps create and manipulate display filters that can be
    used with tshark and Wireshark to filter packet data.
    """
    
    # Simple validator for filter syntax
    FILTER_REGEX = re.compile(r'^[\w\s\.\(\)!=<>"\[\]&|]+$')
    
    def __init__(self, filter_str: str = ""):
        """
        Initialize a filter with an optional filter string.
        
        Args:
            filter_str: Initial filter string
            
        Raises:
            ValueError: If the filter string has invalid syntax
        """
        self.filter_str = filter_str
        if filter_str and not self._validate(filter_str):
            raise ValueError(f"Invalid filter syntax: {filter_str}")
    
    def __str__(self) -> str:
        """Return the filter string."""
        return self.filter_str
    
    def __bool__(self) -> bool:
        """Return True if the filter is not empty."""
        return bool(self.filter_str)
    
    def _validate(self, filter_str: str) -> bool:
        """
        Validate the syntax of a display filter.
        
        This is a simple validator. For full validation, the filter
        would need to be checked against actual tshark/Wireshark filter syntax.
        
        Args:
            filter_str: Filter string to validate
            
        Returns:
            True if the filter appears valid, False otherwise
        """
        if not filter_str:
            return True
        
        # Basic syntax check
        if not self.FILTER_REGEX.match(filter_str):
            return False
        
        # Check for balanced parentheses
        if filter_str.count('(') != filter_str.count(')'):
            return False
        
        # Check for balanced quotes
        if filter_str.count('"') % 2 != 0:
            return False
        
        return True
    
    def add(self, condition: str, operator: str = "and") -> 'Filter':
        """
        Add a condition to the filter.
        
        Args:
            condition: Filter condition to add
            operator: Operator to use ('and' or 'or')
            
        Returns:
            Self for method chaining
            
        Raises:
            ValueError: If the condition has invalid syntax
        """
        if not self._validate(condition):
            raise ValueError(f"Invalid filter condition: {condition}")
        
        if not self.filter_str:
            self.filter_str = condition
        else:
            if operator.lower() not in ("and", "or"):
                raise ValueError(f"Invalid operator: {operator}")
            
            self.filter_str = f"({self.filter_str}) {operator.lower()} ({condition})"
        
        return self
    
    def or_add(self, condition: str) -> 'Filter':
        """
        Add a condition with 'or' operator.
        
        Args:
            condition: Filter condition to add
            
        Returns:
            Self for method chaining
        """
        return self.add(condition, operator="or")
    
    @classmethod
    def from_protocol(cls, protocol: str) -> 'Filter':
        """
        Create a filter for a specific protocol.
        
        Args:
            protocol: Protocol name
            
        Returns:
            Filter instance
        """
        return cls(f"{protocol.lower()}")
    
    @classmethod
    def from_ip(cls, ip: str, direction: Optional[str] = None) -> 'Filter':
        """
        Create a filter for an IP address.
        
        Args:
            ip: IP address
            direction: Optional direction ('src', 'dst', or None for both)
            
        Returns:
            Filter instance
        """
        if direction and direction.lower() not in ('src', 'dst'):
            raise ValueError("Direction must be 'src', 'dst', or None")
        
        if direction:
            return cls(f"ip.{direction.lower()} == {ip}")
        else:
            return cls(f"ip.addr == {ip}")
    
    @classmethod
    def from_port(cls, port: Union[int, str], protocol: Optional[str] = "tcp", direction: Optional[str] = None) -> 'Filter':
        """
        Create a filter for a port number.
        
        Args:
            port: Port number
            protocol: Protocol ('tcp' or 'udp')
            direction: Optional direction ('src', 'dst', or None for both)
            
        Returns:
            Filter instance
        """
        if protocol.lower() not in ('tcp', 'udp'):
            raise ValueError("Protocol must be 'tcp' or 'udp'")
        
        if direction and direction.lower() not in ('src', 'dst'):
            raise ValueError("Direction must be 'src', 'dst', or None")
        
        if direction:
            return cls(f"{protocol.lower()}.{direction.lower()}port == {port}")
        else:
            return cls(f"{protocol.lower()}.port == {port}")
    
    @classmethod
    def from_host(cls, host: str) -> 'Filter':
        """
        Create a filter for a host name.
        
        Args:
            host: Host name
            
        Returns:
            Filter instance
        """
        return cls(f"host {host}")
    
    @classmethod
    def combine(cls, filters: List[Union[str, 'Filter']], operator: str = "and") -> 'Filter':
        """
        Combine multiple filters with an operator.
        
        Args:
            filters: List of filters or filter strings
            operator: Operator to use ('and' or 'or')
            
        Returns:
            Combined filter
            
        Raises:
            ValueError: If no filters are provided
        """
        if not filters:
            raise ValueError("No filters provided")
        
        if operator.lower() not in ("and", "or"):
            raise ValueError(f"Invalid operator: {operator}")
        
        # Convert any strings to Filter objects
        filter_objs = [f if isinstance(f, Filter) else cls(f) for f in filters]
        
        # Combine the filters
        combined_str = " ".join([f"({str(f)})" for f in filter_objs if f])
        if combined_str:
            combined_str = combined_str.replace(") (", f") {operator.lower()} (")
        
        return cls(combined_str)
