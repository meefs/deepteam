from typing import List, Literal, Optional

from deepteam.vulnerabilities import BaseVulnerability
from deepteam.vulnerabilities.agentic.recursive_goal_subversion import RecursiveGoalSubversionType
from deepteam.vulnerabilities.utils import validate_vulnerability_types

RecursiveGoalSubversionLiteralType = Literal[
    "incremental_redefinition", 
    "intermediate_chaining", 
    "cascading_subgoals"
]


class RecursiveGoalSubversion(BaseVulnerability):
    def __init__(
        self,
        types: Optional[List[RecursiveGoalSubversionLiteralType]] = [
            type.value for type in RecursiveGoalSubversionType
        ],
    ):
        enum_types = validate_vulnerability_types(
            self.get_name(), types=types, allowed_type=RecursiveGoalSubversionType
        )
        super().__init__(types=enum_types)

    def get_name(self) -> str:
        return "Recursive Goal Subversion" 