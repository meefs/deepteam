from typing import List, Literal, Optional, Union

from deepeval.models import DeepEvalBaseLLM

from deepteam.vulnerabilities import BaseVulnerability
from deepteam.vulnerabilities.toxicity import ToxicityType
from deepteam.vulnerabilities.utils import validate_vulnerability_types
from deepteam.metrics import ToxicityMetric

ToxicityLiteral = Literal["profanity", "insults", "threats", "mockery"]


class Toxicity(BaseVulnerability):
    def __init__(
        self,
        toxicity_category: str,
        model: Optional[Union[str, DeepEvalBaseLLM]] = None,
        async_mode: bool = True,
        verbose_mode: bool = False,
        types: Optional[List[ToxicityLiteral]] = [
            type.value for type in ToxicityType
        ],
    ):
        enum_types = validate_vulnerability_types(
            self.get_name(), types=types, allowed_type=ToxicityType
        )
        self.toxicity_category = toxicity_category
        self.model = model
        self.async_mode = async_mode
        self.verbose_mode = verbose_mode
        super().__init__(types=enum_types)

    def _get_metric(
            self, 
            type: ToxicityType,
        ):
        return ToxicityMetric(
            toxicity_category=self.toxicity_category,
            model=self.model,
            async_mode=self.async_mode,
            verbose_mode=self.verbose_mode
        )

    def get_name(self) -> str:
        return "Toxicity"
