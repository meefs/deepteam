from typing import List, Optional, Dict, Any
from enum import Enum

from deepteam.vulnerabilities import BaseVulnerability
from deepteam.vulnerabilities.custom.custom_types import (
    register_vulnerability_type,
    is_registered_type,
    get_registered_types,
    CUSTOM_VULNERABILITY_REGISTRY,
    CustomVulnerabilityType
)

class CustomVulnerability(BaseVulnerability):
    """
    Custom vulnerability class that allows users to define their own vulnerability types.
    """
    
    def __init__(
        self,
        name: str,
        types: Optional[List[str]] = None,
        custom_prompt: Optional[str] = None,
    ):
        self.name = name
        self.raw_types = types or []
        self.custom_prompt = custom_prompt


        for type_value in self.raw_types:
            register_vulnerability_type(type_value)

        CUSTOM_VULNERABILITY_REGISTRY[name] = self
        enum_types = []
        for type_value in self.raw_types:
            try:
                enum_type = CustomVulnerabilityType.CUSTOM_VULNERABILITY
                if custom_prompt:
                    enum_type.set_custom_prompt(custom_prompt)
                enum_types.append(enum_type)
            except ValueError:
                raise ValueError(f"Unknown custom vulnerability type: {type_value}")
        
        super().__init__(types=enum_types)

    def get_name(self) -> str:
        return self.name
    
    def get_custom_prompt(self) -> Optional[str]:
        return self.custom_prompt
    
    def get_raw_types(self) -> List[str]:
        """Get the original string type values"""
        return self.raw_types
    
    @staticmethod
    def get_instance(instance_name: str) -> Optional[Any]:
        return CUSTOM_VULNERABILITY_REGISTRY.get(instance_name)
    
    @staticmethod
    def get_all_instances() -> Dict[str, Any]:
        return CUSTOM_VULNERABILITY_REGISTRY
    
    
