from typing import Optional, List, Union

class Filter:
    """
    Represents a Wireshark/tshark display filter.
    Provides methods to construct and manipulate filter expressions.
    """
    
    def __init__(self, expression: str):
        """
        Initialize with a filter expression.
        
        Args:
            expression: Wireshark display filter expression
        """
        self.expression = expression
    
    def __str__(self) -> str:
        return self.expression
    
    def __repr__(self) -> str:
        return f"Filter({self.expression!r})"
    
    def __and__(self, other: 'Filter') -> 'Filter':
        """Combine two filters with AND operator"""
        return Filter(f"({self.expression}) and ({other.expression})")
    
    def __or__(self, other: 'Filter') -> 'Filter':
        """Combine two filters with OR operator"""
        return Filter(f"({self.expression}) or ({other.expression})")
    
    def __invert__(self) -> 'Filter':
        """Negate a filter"""
        return Filter(f"not ({self.expression})")
    
    @staticmethod
    def ip(address: str) -> 'Filter':
        """
        Create a filter for a specific IP address.
        
        Args:
            address: IP address to filter
            
        Returns:
            Filter object
        """
        return Filter(f"ip.addr == {address}")
    
    @staticmethod
    def port(port: Union[int, str], protocol: Optional[str] = None) -> 'Filter':
        """
        Create a filter for a specific port.
        
        Args:
            port: Port number or name
            protocol: Optional protocol (tcp/udp)
            
        Returns:
            Filter object
        """
        if protocol:
            return Filter(f"{protocol}.port == {port}")
        return Filter(f"tcp.port == {port} or udp.port == {port}")
    
    @staticmethod
    def protocol(name: str) -> 'Filter':
        """
        Create a filter for a specific protocol.
        
        Args:
            name: Protocol name
            
        Returns:
            Filter object
        """
        return Filter(name.lower())
    
    @staticmethod
    def host(name: str) -> 'Filter':
        """
        Create a filter for a specific host.
        
        Args:
            name: Hostname
            
        Returns:
            Filter object
        """
        return Filter(f"host {name}")
    
    @staticmethod
    def conversation(ip1: str, ip2: str) -> 'Filter':
        """
        Create a filter for a conversation between two IPs.
        
        Args:
            ip1: First IP address
            ip2: Second IP address
            
        Returns:
            Filter object
        """
        return Filter(f"(ip.src == {ip1} and ip.dst == {ip2}) or (ip.src == {ip2} and ip.dst == {ip1})")
    
    @staticmethod
    def combine(filters: List['Filter'], operator: str = "and") -> 'Filter':
        """
        Combine multiple filters with the specified operator.
        
        Args:
            filters: List of filters to combine
            operator: Operator to use ("and" or "or")
            
        Returns:
            Combined filter
        """
        if not filters:
            return Filter("")
        if len(filters) == 1:
            return filters[0]
            
        expressions = [f"({f.expression})" for f in filters]
        return Filter(f" {operator} ".join(expressions))
