from typing import List, Literal, Optional

from deepteam.vulnerabilities import BaseVulnerability
from deepteam.vulnerabilities.agentic.context_amnesia import ContextAmnesiaType
from deepteam.vulnerabilities.utils import validate_vulnerability_types

ContextAmnesiaLiteralType = Literal[
    "context_reset_exploitation", 
    "task_switching_amnesia", 
    "parameter_dropout"
]


class ContextAmnesia(BaseVulnerability):
    def __init__(
        self,
        types: Optional[List[ContextAmnesiaLiteralType]] = [
            type.value for type in ContextAmnesiaType
        ],
    ):
        enum_types = validate_vulnerability_types(
            self.get_name(), types=types, allowed_type=ContextAmnesiaType
        )
        super().__init__(types=enum_types)

    def get_name(self) -> str:
        return "Context Amnesia" 