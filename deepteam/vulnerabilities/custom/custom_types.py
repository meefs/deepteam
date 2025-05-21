from enum import Enum
from typing import Dict, Optional, List, Set, Any, Type



CUSTOM_VULNERABILITY_TYPES: Set[str] = set()
CUSTOM_VULNERABILITY_REGISTRY: Dict[str, Any] = {}


def register_vulnerability_type(type_value: str) -> None:
    """Register a new vulnerability type"""
    CUSTOM_VULNERABILITY_TYPES.add(type_value)


def get_registered_types() -> Set[str]:
    return CUSTOM_VULNERABILITY_TYPES


def is_registered_type(type_value: str) -> bool:
    return type_value in CUSTOM_VULNERABILITY_TYPES


class CustomVulnerabilityType(Enum):
    """Custom vulnerability type enum with prompt support"""
    CUSTOM_VULNERABILITY = "custom_vulnerability"

    def __init__(self, value: str):
        self._value_ = value
        self._prompt: Optional[str] = None

    def get_custom_prompt(self) -> Optional[str]:
        """Get the custom prompt for this vulnerability type"""
        return self._prompt

    def set_custom_prompt(self, prompt: str) -> None:
        """Set the custom prompt for this vulnerability type"""
        self._prompt = prompt 