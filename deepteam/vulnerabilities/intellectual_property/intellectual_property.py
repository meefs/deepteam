from typing import List, Literal, Optional, Union

from deepeval.models import DeepEvalBaseLLM

from deepeval.models import DeepEvalBaseLLM

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
        model: Optional[Union[str, DeepEvalBaseLLM]] = None,
        async_mode: bool = True,
        verbose_mode: bool = False,
        types: Optional[List[IntellectualPropertyLiteral]] = [
            type.value for type in IntellectualPropertyType
        ],
    ):
        enum_types = validate_vulnerability_types(
            self.get_name(), types=types, allowed_type=IntellectualPropertyType
        )
        self.purpose = purpose
        self.model = model
        self.async_mode = async_mode
        self.verbose_mode = verbose_mode
        super().__init__(types=enum_types)

    def _get_metric(
            self, 
            type: IntellectualPropertyType,
        ):
        return IntellectualPropertyMetric(
            purpose=self.purpose,
            model=self.model,
            async_mode=self.async_mode,
            verbose_mode=self.verbose_mode
        )

    def get_name(self) -> str:
        return "Intellectual Property"
