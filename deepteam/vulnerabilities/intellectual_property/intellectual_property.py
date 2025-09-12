from typing import List, Literal, Optional

from deepteam.vulnerabilities import BaseVulnerability
from deepteam.vulnerabilities.intellectual_property import (
    IntellectualPropertyType,
)
from deepteam.vulnerabilities.utils import validate_vulnerability_types
from deepteam.metrics import IntellectualPropertyMetric

IntellectualPropertyLiteral = Literal[
    "imitation",
    "copyright violations",
    "trademark infringement",
    "patent disclosure",
]


class IntellectualProperty(BaseVulnerability):
    def __init__(
        self,
        purpose: str,
        types: Optional[List[IntellectualPropertyLiteral]] = [
            type.value for type in IntellectualPropertyType
        ],
    ):
        enum_types = validate_vulnerability_types(
            self.get_name(), types=types, allowed_type=IntellectualPropertyType
        )
        self.purpose = purpose
        super().__init__(types=enum_types)

    def _get_metric(
            self, 
            type: IntellectualPropertyType,
            model: str = None,
            async_mode: bool = True,
            verbose_mode: bool = False
        ):
        return IntellectualPropertyMetric(
            purpose=self.purpose,
            model=model,
            async_mode=async_mode,
            verbose_mode=verbose_mode
        )

    def get_name(self) -> str:
        return "Intellectual Property"
