from typing import List, Literal, Optional

from deepteam.vulnerabilities import BaseVulnerability
from deepteam.vulnerabilities.agentic.semantic_manipulation import SemanticManipulationType
from deepteam.vulnerabilities.utils import validate_vulnerability_types

SemanticManipulationLiteralType = Literal[
    "ambiguous_phrasing", 
    "linguistic_obfuscation", 
    "conflicting_instructions"
]


class SemanticManipulation(BaseVulnerability):
    def __init__(
        self,
        types: Optional[List[SemanticManipulationLiteralType]] = [
            type.value for type in SemanticManipulationType
        ],
    ):
        enum_types = validate_vulnerability_types(
            self.get_name(), types=types, allowed_type=SemanticManipulationType
        )
        super().__init__(types=enum_types)

    def get_name(self) -> str:
        return "Semantic Manipulation" 