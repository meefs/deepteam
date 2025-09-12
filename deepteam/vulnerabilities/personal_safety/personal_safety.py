from typing import List, Literal, Optional, Union

from deepeval.models import DeepEvalBaseLLM

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
        safety_category: str,
        model: Optional[Union[str, DeepEvalBaseLLM]] = None,
        async_mode: bool = True,
        verbose_mode: bool = False,
        types: Optional[List[PersonalSafetyLiteral]] = [
            type.value for type in PersonalSafetyType
        ],
    ):
        enum_types = validate_vulnerability_types(
            self.get_name(), types=types, allowed_type=PersonalSafetyType
        )
        self.safety_category = safety_category
        self.model = model
        self.async_mode = async_mode
        self.verbose_mode = verbose_mode
        super().__init__(types=enum_types)

    def _get_metric(
            self, 
            type: PersonalSafetyType,
        ):
        return SafetyMetric(
            safety_category=self.safety_category,
            model=self.model,
            async_mode=self.async_mode,
            verbose_mode=self.verbose_mode
        )

    def get_name(self) -> str:
        return "Personal Safety"
