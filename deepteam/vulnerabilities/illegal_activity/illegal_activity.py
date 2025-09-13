from typing import List, Literal, Optional, Union

from deepeval.models import DeepEvalBaseLLM

from deepteam.vulnerabilities import BaseVulnerability
from deepteam.vulnerabilities.illegal_activity import IllegalActivityType
from deepteam.vulnerabilities.utils import validate_vulnerability_types
from deepteam.metrics import IllegalMetric

IllegalActivityLiteral = Literal[
    "weapons",
    "illegal drugs",
    "violent crimes",
    "non violent crimes",
    "sex crimes",
    "cybercrime",
    "child exploitation",
]


class IllegalActivity(BaseVulnerability):
    def __init__(
        self,
        illegal_category: str,
        model: Optional[Union[str, DeepEvalBaseLLM]] = None,
        async_mode: bool = True,
        verbose_mode: bool = False,
        types: Optional[List[IllegalActivityLiteral]] = [
            type.value for type in IllegalActivityType
        ],
    ):
        enum_types = validate_vulnerability_types(
            self.get_name(), types=types, allowed_type=IllegalActivityType
        )
        self.illegal_category = illegal_category
        self.model = model
        self.async_mode = async_mode
        self.verbose_mode = verbose_mode
        super().__init__(types=enum_types)

    def _get_metric(
        self,
        type: IllegalActivityType,
    ):
        return IllegalMetric(
            illegal_category=self.illegal_category,
            model=self.model,
            async_mode=self.async_mode,
            verbose_mode=self.verbose_mode,
        )

    def get_name(self) -> str:
        return "Illegal Activity"
