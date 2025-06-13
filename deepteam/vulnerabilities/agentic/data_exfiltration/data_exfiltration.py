from typing import List, Literal, Optional

from deepteam.vulnerabilities import BaseVulnerability
from deepteam.vulnerabilities.agentic.data_exfiltration import DataExfiltrationTypes
from deepteam.vulnerabilities.utils import validate_vulnerability_types

DataExfiltrationLiteralType = Literal[
    "cross_session_leakage", 
    "cross_customer_access", 
    "trusted_agent_smuggling"
]


class DataExfiltration(BaseVulnerability):
    def __init__(
        self,
        types: Optional[List[DataExfiltrationLiteralType]] = [
            type.value for type in DataExfiltrationTypes
        ],
    ):
        enum_types = validate_vulnerability_types(
            self.get_name(), types=types, allowed_type=DataExfiltrationTypes
        )
        super().__init__(types=enum_types)

    def get_name(self) -> str:
        return "Data Exfiltration" 