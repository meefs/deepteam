from typing import List, Literal, Optional

from deepteam.vulnerabilities import BaseVulnerability
from deepteam.vulnerabilities.agentic.direct_control_hijacking import DirectControlHijackingType
from deepteam.vulnerabilities.utils import validate_vulnerability_types

DirectControlHijackingLiteralType = Literal[
    "spoofed_api_calls", 
    "malformed_payloads", 
    "machine_identity_spoofing"
]


class DirectControlHijacking(BaseVulnerability):
    def __init__(
        self,
        types: Optional[List[DirectControlHijackingLiteralType]] = [
            type.value for type in DirectControlHijackingType
        ],
    ):
        enum_types = validate_vulnerability_types(
            self.get_name(), types=types, allowed_type=DirectControlHijackingType
        )
        super().__init__(types=enum_types)

    def get_name(self) -> str:
        return "Direct Control Hijacking" 