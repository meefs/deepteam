from typing import List, Literal, Optional

from deepteam.vulnerabilities import BaseVulnerability
from deepteam.vulnerabilities.agentic.decision_manipulation import DecisionManipulationType
from deepteam.vulnerabilities.utils import validate_vulnerability_types

DecisionManipulationLiteralType = Literal[
    "false_context_injection", 
    "conflicting_data_sources", 
    "fabricated_entries"
]


class DecisionManipulation(BaseVulnerability):
    def __init__(
        self,
        types: Optional[List[DecisionManipulationLiteralType]] = [
            type.value for type in DecisionManipulationType
        ],
    ):
        enum_types = validate_vulnerability_types(
            self.get_name(), types=types, allowed_type=DecisionManipulationType
        )
        super().__init__(types=enum_types)

    def get_name(self) -> str:
        return "Decision Manipulation" 