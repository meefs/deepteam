from typing import List, Literal, Optional

from deepteam.vulnerabilities import BaseVulnerability
from deepteam.vulnerabilities.agentic.goal_interpretation import GoalInterpretationType
from deepteam.vulnerabilities.utils import validate_vulnerability_types

GoalInterpretationLiteralType = Literal[
    "ambiguous_adversarial_input", 
    "subtle_goal_modification", 
    "conflicting_constraints"
]


class GoalInterpretation(BaseVulnerability):
    def __init__(
        self,
        types: Optional[List[GoalInterpretationLiteralType]] = [
            type.value for type in GoalInterpretationType
        ],
    ):
        enum_types = validate_vulnerability_types(
            self.get_name(), types=types, allowed_type=GoalInterpretationType
        )
        super().__init__(types=enum_types)

    def get_name(self) -> str:
        return "Goal Interpretation" 