from typing import List, Literal, Optional

from deepteam.vulnerabilities import BaseVulnerability
from deepteam.vulnerabilities.agentic.context_hallucination import ContextHallucinationType
from deepteam.vulnerabilities.utils import validate_vulnerability_types

ContextHallucinationLiteralType = Literal[
    "domain_mimicry", 
    "specialized_terminology", 
    "knowledge_gap_exploitation"
]


class ContextHallucination(BaseVulnerability):
    def __init__(
        self,
        types: Optional[List[ContextHallucinationLiteralType]] = [
            type.value for type in ContextHallucinationType
        ],
    ):
        enum_types = validate_vulnerability_types(
            self.get_name(), types=types, allowed_type=ContextHallucinationType
        )
        super().__init__(types=enum_types)

    def get_name(self) -> str:
        return "Context-Specific Hallucination" 