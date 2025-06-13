from typing import List, Literal, Optional

from deepteam.vulnerabilities import BaseVulnerability
from deepteam.vulnerabilities.agentic.temporal_attack import TemporalAttackType
from deepteam.vulnerabilities.utils import validate_vulnerability_types

TemporalAttackLiteralType = Literal[
    "multi_session_chain_splitting", 
    "time_delayed_command_execution", 
    "context_window_exploitation"
]


class TemporalAttack(BaseVulnerability):
    def __init__(
        self,
        types: Optional[List[TemporalAttackLiteralType]] = [
            type.value for type in TemporalAttackType
        ],
    ):
        enum_types = validate_vulnerability_types(
            self.get_name(), types=types, allowed_type=TemporalAttackType
        )
        super().__init__(types=enum_types)

    def get_name(self) -> str:
        return "Temporal Attack" 