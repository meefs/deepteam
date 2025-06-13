from typing import List, Literal, Optional

from deepteam.vulnerabilities import BaseVulnerability
from deepteam.vulnerabilities.agentic.induced_hallucination import InducedHallucinationType
from deepteam.vulnerabilities.utils import validate_vulnerability_types

InducedHallucinationLiteralType = Literal[
    "conflicting_data", 
    "near_duplicates", 
    "time_pressure"
]


class InducedHallucination(BaseVulnerability):
    def __init__(
        self,
        types: Optional[List[InducedHallucinationLiteralType]] = [
            type.value for type in InducedHallucinationType
        ],
    ):
        enum_types = validate_vulnerability_types(
            self.get_name(), types=types, allowed_type=InducedHallucinationType
        )
        super().__init__(types=enum_types)

    def get_name(self) -> str:
        return "Induced Hallucination" 