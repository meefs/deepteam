from typing import List, Literal, Optional

from deepteam.vulnerabilities import BaseVulnerability
from deepteam.vulnerabilities.agentic.output_verification import OutputVerificationType
from deepteam.vulnerabilities.utils import validate_vulnerability_types

OutputVerificationLiteralType = Literal[
    "implausible_outputs", 
    "contradictory_outputs", 
    "low_confidence_bypass"
]


class OutputVerification(BaseVulnerability):
    def __init__(
        self,
        types: Optional[List[OutputVerificationLiteralType]] = [
            type.value for type in OutputVerificationType
        ],
    ):
        enum_types = validate_vulnerability_types(
            self.get_name(), types=types, allowed_type=OutputVerificationType
        )
        super().__init__(types=enum_types)

    def get_name(self) -> str:
        return "Output Verification" 