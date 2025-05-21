from enum import Enum, auto
from typing import Dict, Any, Optional, List, Tuple, Union


class CustomVulnerabilityType(Enum):
    """
    Base class for custom vulnerability types.
    This will be dynamically extended based on user input.
    """
    # Default placeholder type
    CUSTOM = "custom"
    
    @classmethod
    def register_type(cls, type_name: str, type_value: str) -> "CustomVulnerabilityTypeWrapper":
        """
        Dynamically register a new custom vulnerability type.
        Since Python enums are immutable, we use a wrapper class.
        
        Args:
            type_name: The name of the enum constant (converted to uppercase for consistency)
            type_value: The string value of the enum constant
            
        Returns:
            A wrapper that behaves like an enum value
        """
        type_name = type_name.upper().replace(" ", "_")
        # Return our wrapper class that will behave like an enum member
        return CustomVulnerabilityTypeWrapper(type_value, type_name)

    @classmethod
    def get_registered_types(cls) -> Dict[str, str]:
        """
        Get all registered custom vulnerability types.
        
        Returns:
            A dictionary of type names and their values
        """
        return {name: member.value for name, member in cls.__members__.items()}


# Wrapper class that mimics an enum member
class CustomVulnerabilityTypeWrapper:
    """A wrapper class that behaves like an enum value for custom vulnerability types"""
    
    def __init__(self, value: str, name: str):
        self.value = value
        self.name = name
    
    def __str__(self) -> str:
        return f"CustomVulnerabilityType.{self.name}"
    
    def __repr__(self) -> str:
        return self.__str__()
    
    # Make the wrapper mimic an enum value's behavior
    def __eq__(self, other):
        if isinstance(other, CustomVulnerabilityTypeWrapper):
            return self.value == other.value
        elif isinstance(other, str):
            return self.value == other
        elif isinstance(other, Enum):
            return self.value == other.value
        return False


# Registry to store subtypes for each vulnerability type
SUBTYPE_REGISTRY: Dict[str, List[Tuple[str, str]]] = {}


def register_subtype(type_value: str, subtype_name: str, subtype_value: str) -> None:
    """
    Register a subtype for a given vulnerability type.
    
    Args:
        type_value: The string value of the parent vulnerability type
        subtype_name: The name of the subtype (uppercase for enum)
        subtype_value: The string value of the subtype
    """
    if type_value not in SUBTYPE_REGISTRY:
        SUBTYPE_REGISTRY[type_value] = []
    
    # Check if subtype already exists
    for existing_name, existing_value in SUBTYPE_REGISTRY[type_value]:
        if existing_value == subtype_value:
            return
    
    # Add the new subtype
    SUBTYPE_REGISTRY[type_value].append((subtype_name.upper().replace(" ", "_"), subtype_value))


def get_subtypes(type_value: str) -> List[str]:
    """
    Get all registered subtypes for a given vulnerability type.
    
    Args:
        type_value: The string value of the vulnerability type
        
    Returns:
        A list of subtype values
    """
    if type_value not in SUBTYPE_REGISTRY:
        return []
    
    return [subtype_value for _, subtype_value in SUBTYPE_REGISTRY[type_value]]


# Function to check if a vulnerability type+subtype combination is valid
def is_valid_vulnerability(type_value: str, subtype_value: str) -> bool:
    """
    Check if a given vulnerability type and subtype combination is valid.
    
    Args:
        type_value: The string value of the vulnerability type
        subtype_value: The string value of the subtype
        
    Returns:
        True if the combination is valid, False otherwise
    """
    if type_value not in SUBTYPE_REGISTRY:
        return False
    
    return subtype_value in get_subtypes(type_value) 