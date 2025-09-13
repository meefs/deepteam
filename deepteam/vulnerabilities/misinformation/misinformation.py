from typing import List, Literal, Optional, Union

from deepeval.models import DeepEvalBaseLLM

from deepteam.vulnerabilities import BaseVulnerability
from deepteam.vulnerabilities.misinformation import MisinformationType
from deepteam.vulnerabilities.utils import validate_vulnerability_types
from deepteam.metrics import MisinformationMetric


MisinformationLiteral = Literal[
    "factual errors", "unsupported claims", "expertize misrepresentation"
]


class Misinformation(BaseVulnerability):
    def __init__(
        self,
        misinformation_category: str,
        model: Optional[Union[str, DeepEvalBaseLLM]] = None,
        async_mode: bool = True,
        verbose_mode: bool = False,
        types: Optional[List[MisinformationLiteral]] = [
            type.value for type in MisinformationType
        ],
    ):
        enum_types = validate_vulnerability_types(
            self.get_name(), types=types, allowed_type=MisinformationType
        )
        self.misinformation_category = misinformation_category
        self.model = model
        self.async_mode = async_mode
        self.verbose_mode = verbose_mode
        super().__init__(types=enum_types)

    def _get_metric(
        self,
        type: MisinformationType,
    ):
        return MisinformationMetric(
            misinformation_category=self.misinformation_category,
            model=self.model,
            async_mode=self.async_mode,
            verbose_mode=self.verbose_mode,
        )

    def get_name(self) -> str:
        return "Misinformation"
