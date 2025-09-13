from typing import List, Literal, Optional, Union

from deepeval.models import DeepEvalBaseLLM

from deepteam.vulnerabilities import BaseVulnerability
from deepteam.vulnerabilities.prompt_leakage import PromptLeakageType
from deepteam.vulnerabilities.utils import validate_vulnerability_types
from deepteam.metrics import PromptExtractionMetric

PromptLeakageLiteral = Literal[
    "secrets and credentials",
    "instructions",
    "guard exposure",
    "permissions and roles",
]


class PromptLeakage(BaseVulnerability):
    def __init__(
        self,
        purpose: str,
        model: Optional[Union[str, DeepEvalBaseLLM]] = None,
        async_mode: bool = True,
        verbose_mode: bool = False,
        types: Optional[List[PromptLeakageLiteral]] = [
            type.value for type in PromptLeakageType
        ],
    ):
        enum_types = validate_vulnerability_types(
            self.get_name(), types=types, allowed_type=PromptLeakageType
        )
        self.purpose = purpose
        self.model = model
        self.async_mode = async_mode
        self.verbose_mode = verbose_mode
        super().__init__(types=enum_types)

    def _get_metric(
        self,
        type: PromptLeakageType,
    ):
        return PromptExtractionMetric(
            purpose=self.purpose,
            model=self.model,
            async_mode=self.async_mode,
            verbose_mode=self.verbose_mode,
        )

    def get_name(self) -> str:
        return "Prompt Leakage"
