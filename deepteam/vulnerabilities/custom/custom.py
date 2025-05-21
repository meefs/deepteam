from typing import List, Optional, Dict, Any, Callable, Union

from deepteam.vulnerabilities import BaseVulnerability
from deepteam.vulnerabilities.custom.types import (
    CustomVulnerabilityType,
    register_subtype,
    is_valid_vulnerability,
    get_subtypes
)


class CustomVulnerability(BaseVulnerability):
    """
    Custom vulnerability class that allows users to define their own vulnerability types and subtypes.
    """
    
    def __init__(
        self,
        type_value: str,
        subtype_value: str,
        custom_prompt: Optional[str] = None,
        purpose: Optional[str] = None,
        validator: Optional[Callable] = None
    ):
        """
        Initialize a custom vulnerability with user-defined type and subtype.
        
        Args:
            type_value: The string value of the vulnerability type
            subtype_value: The string value of the subtype
            custom_prompt: Optional custom prompt template to use for generating attacks
            purpose: Optional purpose description for generating relevant attacks
            validator: Optional custom validator function for checking responses
        """
        # Register the type if it doesn't exist
        vulnerability_type = CustomVulnerabilityType.register_type(
            type_name=type_value.replace(" ", "_"),
            type_value=type_value
        )
        
        # Debug info about the type
        print(f"Using vulnerability type: {vulnerability_type} (type: {type(vulnerability_type)})")
        
        # Register the subtype if it doesn't exist
        register_subtype(
            type_value=type_value,
            subtype_name=subtype_value.replace(" ", "_"),
            subtype_value=subtype_value
        )
        
        # Validate the type-subtype combination
        if not is_valid_vulnerability(type_value, subtype_value):
            raise ValueError(f"Invalid vulnerability combination: {type_value} - {subtype_value}")
        
        # Store the specific subtype
        self.type_value = type_value
        self.subtype_value = subtype_value
        
        # Store additional metadata
        self.custom_prompt = custom_prompt
        self.purpose = purpose
        self.enum_type = vulnerability_type

        super().__init__(types=[vulnerability_type])
    
    @classmethod
    def register_new_type(
        cls,
        type_value: str,
        subtype_values: List[str]
    ) -> "CustomVulnerabilityType":
        """
        Register a new vulnerability type with associated subtypes.
        
        Args:
            type_value: The string value of the vulnerability type
            subtype_values: List of subtype values to associate with this type
            
        Returns:
            The newly registered vulnerability type enum
        """
        # Register the main type
        vulnerability_type = CustomVulnerabilityType.register_type(
            type_name=type_value.replace(" ", "_"),
            type_value=type_value
        )
        
        # Register all subtypes
        for subtype_value in subtype_values:
            register_subtype(
                type_value=type_value,
                subtype_name=subtype_value.replace(" ", "_"),
                subtype_value=subtype_value
            )
        
        return vulnerability_type
    
    def get_name(self) -> str:
        return f"Custom Vulnerability: {self.type_value} - {self.subtype_value}"
    
    def get_type_value(self) -> Union[str, CustomVulnerabilityType]:
        return self.enum_type if hasattr(self, 'enum_type') else self.type_value
    
    def get_subtype_value(self) -> str:
        return self.subtype_value
    
    def get_custom_prompt(self) -> Optional[str]:
        return self.custom_prompt
    
    def get_purpose(self) -> Optional[str]:
        return self.purpose
    
