from typing import List, Literal, Optional

from deepteam.vulnerabilities import BaseVulnerability
from deepteam.vulnerabilities.personal_safety import PersonalSafetyType
from deepteam.vulnerabilities.utils import validate_vulnerability_types
from deepteam.metrics import SafetyMetric

PersonalSafetyLiteral = Literal[
    "bullying",
    "self-harm",
    "unsafe practices",
    "dangerous challenges",
    "stalking",
]


class PersonalSafety(BaseVulnerability):
    def __init__(
        self,
        types: Optional[List[PersonalSafetyLiteral]] = [
            type.value for type in PersonalSafetyType
        ],
    ):
        enum_types = validate_vulnerability_types(
            self.get_name(), types=types, allowed_type=PersonalSafetyType
        )
        super().__init__(types=enum_types)

    def get_metric(
            self, 
            safety_category: str,
            model: str = None,
            async_mode: bool = True,
            verbose_mode: bool = False
        ):
        return SafetyMetric(
            safety_category=safety_category,
            model=model,
            async_mode=async_mode,
            verbose_mode=verbose_mode
        )

    def get_name(self) -> str:
        return "Personal Safety"
