from typing import List, Literal, Optional

from deepteam.vulnerabilities import BaseVulnerability
from deepteam.vulnerabilities.agentic.goal_extraction import GoalExtractionType
from deepteam.vulnerabilities.utils import validate_vulnerability_types

GoalExtractionLiteralType = Literal[
    "escalating_probing", 
    "cooperative_dialogue", 
    "social_engineering"
]


class GoalExtraction(BaseVulnerability):
    def __init__(
        self,
        types: Optional[List[GoalExtractionLiteralType]] = [
            type.value for type in GoalExtractionType
        ],
    ):
        enum_types = validate_vulnerability_types(
            self.get_name(), types=types, allowed_type=GoalExtractionType
        )
        super().__init__(types=enum_types)

    def get_name(self) -> str:
        return "Goal Extraction" 