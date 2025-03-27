"""
Filter module for Wireshark MCP.

This module provides tools for constructing and manipulating
Wireshark display filters in a structured way.
"""

from enum import Enum
from typing import List, Optional, Dict, Any, Union

class FilterOperator(Enum):
    """Operators for filter expressions."""
    EQUALS = "=="
    NOT_EQUALS = "!="
    GREATER_THAN = ">"
    LESS_THAN = "<"
    GREATER_EQUAL = ">="
    LESS_EQUAL = "<="
    CONTAINS = "contains"
    MATCHES = "matches"
    BITWISE_AND = "&"
    

class LogicalOperator(Enum):
    """Logical operators for combining filters."""
    AND = "and"
    OR = "or"
    NOT = "not"


class FilterExpression:
    """
    Represents a single filter expression in Wireshark display filter syntax.
    
    Examples:
        ip.addr == 192.168.1.1
        tcp.port == 80
        http.request.method == "GET"
    """
    
    def __init__(self, 
                field: str, 
                operator: FilterOperator, 
                value: Any,
                raw: bool = False):
        """
        Initialize a filter expression.
        
        Args:
            field: Field name to filter on
            operator: Comparison operator
            value: Value to compare against
            raw: Whether the value should be treated as a raw string
        """
        self.field = field
        self.operator = operator
        self.value = value
        self.raw = raw
        
    def __str__(self) -> str:
        """Convert to Wireshark display filter syntax."""
        if self.raw:
            return f"{self.field} {self.operator.value} {self.value}"
        
        # Format value based on type
        if isinstance(self.value, str):
            # Quote strings
            formatted_value = f'"{self.value}"'
        elif isinstance(self.value, bool):
            # Convert booleans to lowercase strings
            formatted_value = str(self.value).lower()
        else:
            # Use string representation for numbers and other types
            formatted_value = str(self.value)
            
        return f"{self.field} {self.operator.value} {formatted_value}"


class FilterGroup:
    """
    Represents a group of filter expressions combined with logical operators.
    
    Examples:
        (ip.src == 192.168.1.1 and tcp.port == 80)
        (http.request or http.response)
    """
    
    def __init__(self):
        """Initialize an empty filter group."""
        self.expressions: List[Union[FilterExpression, FilterGroup, str]] = []
        
    def add(self, expression: Union[FilterExpression, 'FilterGroup', str], 
            logical_op: Optional[LogicalOperator] = None) -> 'FilterGroup':
        """
        Add an expression to the group.
        
        Args:
            expression: Filter expression or group to add
            logical_op: Logical operator to prefix (not needed for first expression)
            
        Returns:
            Self for chaining
        """
        if self.expressions and logical_op:
            # Add the logical operator first
            self.expressions.append(logical_op.value)
            
        self.expressions.append(expression)
        return self
        
    def __str__(self) -> str:
        """Convert to Wireshark display filter syntax."""
        if not self.expressions:
            return ""
            
        # Build filter string
        parts = []
        for expr in self.expressions:
            parts.append(str(expr))
            
        # Wrap in parentheses if multiple expressions
        filter_str = " ".join(parts)
        if len(self.expressions) > 1:
            filter_str = f"({filter_str})"
            
        return filter_str


class Filter:
    """
    Main filter class for constructing Wireshark display filters.
    
    This class provides a fluent interface for building complex
    Wireshark display filters in a structured way.
    """
    
    def __init__(self, filter_str: Optional[str] = None):
        """
        Initialize a filter, optionally with a raw filter string.
        
        Args:
            filter_str: Optional raw filter string to use
        """
        self.root = FilterGroup()
        self._raw_filter = filter_str
        
    def __str__(self) -> str:
        """Convert to Wireshark display filter syntax."""
        if self._raw_filter:
            return self._raw_filter
            
        return str(self.root)
    
    def where(self, field: str, 
             operator: FilterOperator, 
             value: Any) -> 'Filter':
        """
        Add a filter condition.
        
        Args:
            field: Field name to filter on
            operator: Comparison operator
            value: Value to compare against
            
        Returns:
            Self for chaining
        """
        expr = FilterExpression(field, operator, value)
        self.root.add(expr)
        return self
    
    def and_where(self, field: str, 
                 operator: FilterOperator, 
                 value: Any) -> 'Filter':
        """
        Add a filter condition with AND logic.
        
        Args:
            field: Field name to filter on
            operator: Comparison operator
            value: Value to compare against
            
        Returns:
            Self for chaining
        """
        expr = FilterExpression(field, operator, value)
        self.root.add(expr, LogicalOperator.AND)
        return self
    
    def or_where(self, field: str, 
                operator: FilterOperator, 
                value: Any) -> 'Filter':
        """
        Add a filter condition with OR logic.
        
        Args:
            field: Field name to filter on
            operator: Comparison operator
            value: Value to compare against
            
        Returns:
            Self for chaining
        """
        expr = FilterExpression(field, operator, value)
        self.root.add(expr, LogicalOperator.OR)
        return self
    
    def group(self, callback=None) -> 'Filter':
        """
        Add a grouped filter condition.
        
        Args:
            callback: Optional callback function that receives the group
            
        Returns:
            Self for chaining
        """
        group = FilterGroup()
        
        if callback:
            callback(group)
            
        self.root.add(group)
        return self
    
    def and_group(self, callback=None) -> 'Filter':
        """
        Add a grouped filter condition with AND logic.
        
        Args:
            callback: Optional callback function that receives the group
            
        Returns:
            Self for chaining
        """
        group = FilterGroup()
        
        if callback:
            callback(group)
            
        self.root.add(group, LogicalOperator.AND)
        return self
    
    def or_group(self, callback=None) -> 'Filter':
        """
        Add a grouped filter condition with OR logic.
        
        Args:
            callback: Optional callback function that receives the group
            
        Returns:
            Self for chaining
        """
        group = FilterGroup()
        
        if callback:
            callback(group)
            
        self.root.add(group, LogicalOperator.OR)
        return self
    
    def raw(self, filter_str: str) -> 'Filter':
        """
        Set a raw filter string, replacing any constructed filter.
        
        Args:
            filter_str: Raw filter string in Wireshark display filter syntax
            
        Returns:
            Self for chaining
        """
        self._raw_filter = filter_str
        return self
    
    @staticmethod
    def equals(field: str, value: Any) -> FilterExpression:
        """Convenience method for creating an equals expression."""
        return FilterExpression(field, FilterOperator.EQUALS, value)
    
    @staticmethod
    def not_equals(field: str, value: Any) -> FilterExpression:
        """Convenience method for creating a not-equals expression."""
        return FilterExpression(field, FilterOperator.NOT_EQUALS, value)
    
    @staticmethod
    def contains(field: str, value: Any) -> FilterExpression:
        """Convenience method for creating a contains expression."""
        return FilterExpression(field, FilterOperator.CONTAINS, value)
    
    @staticmethod
    def matches(field: str, value: Any) -> FilterExpression:
        """Convenience method for creating a matches expression."""
        return FilterExpression(field, FilterOperator.MATCHES, value)
