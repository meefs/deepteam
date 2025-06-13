from typing import List, Literal, Optional

from deepteam.vulnerabilities import BaseVulnerability
from deepteam.vulnerabilities.agentic.hierarchical_goal import HierarchicalGoalType
from deepteam.vulnerabilities.utils import validate_vulnerability_types

HierarchicalGoalLiteralType = Literal[
    "nested_override", 
    "malicious_embedding", 
    "contradictory_depths"
]


class HierarchicalGoal(BaseVulnerability):
    def __init__(
        self,
        types: Optional[List[HierarchicalGoalLiteralType]] = [
            type.value for type in HierarchicalGoalType
        ],
    ):
        enum_types = validate_vulnerability_types(
            self.get_name(), types=types, allowed_type=HierarchicalGoalType
        )
        super().__init__(types=enum_types)

    def get_name(self) -> str:
        return "Hierarchical Goal" 