from enum import Enum
from typing import Optional

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