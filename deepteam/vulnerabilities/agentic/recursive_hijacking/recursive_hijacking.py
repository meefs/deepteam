from typing import List, Literal, Optional

from deepteam.vulnerabilities import BaseVulnerability
from deepteam.vulnerabilities.agentic.recursive_hijacking import (
    RecursiveHijackingType,
)
from deepteam.vulnerabilities.utils import validate_vulnerability_types
from deepteam.metrics.agentic.subversion_success.subversion_success import SubversionSuccessMetric

RecursiveHijackingLiteralType = Literal[
    "self_modifying_goals",
    "recursive_objective_chaining",
    "goal_propagation_attacks",
]


class RecursiveHijacking(BaseVulnerability):
    def __init__(
        self,
        purpose: str,
        types: Optional[List[RecursiveHijackingLiteralType]] = [
            type.value for type in RecursiveHijackingType
        ],
    ):
        enum_types = validate_vulnerability_types(
            self.get_name(), types=types, allowed_type=RecursiveHijackingType
        )
        self.purpose = purpose
        super().__init__(types=enum_types)

    def _get_metric(
            self, 
            type: RecursiveHijackingType,
            model: str = None,
            async_mode: bool = True,
            verbose_mode: bool = False
        ):
        return SubversionSuccessMetric(
            purpose=self.purpose,
            model=model,
            async_mode=async_mode,
            verbose_mode=verbose_mode
        )

    def get_name(self) -> str:
        return "Recursive Hijacking"
