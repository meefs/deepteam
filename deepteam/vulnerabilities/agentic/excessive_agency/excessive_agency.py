from typing import List, Literal, Optional, Union

from deepeval.models import DeepEvalBaseLLM

from deepteam.vulnerabilities import BaseVulnerability
from deepteam.vulnerabilities.agentic.excessive_agency import (
    ExcessiveAgencyType,
)
from deepteam.vulnerabilities.utils import validate_vulnerability_types
from deepteam.metrics import ExcessiveAgencyMetric


ExcessiveAgencyLiteral = Literal["functionality", "permissions", "autonomy"]


class ExcessiveAgency(BaseVulnerability):
    def __init__(
        self,
        purpose: str = None,
        model: Optional[Union[str, DeepEvalBaseLLM]] = None,
        async_mode: bool = True,
        verbose_mode: bool = False,
        types: Optional[List[ExcessiveAgencyLiteral]] = [
            type.value for type in ExcessiveAgencyType
        ],
    ):
        enum_types = validate_vulnerability_types(
            self.get_name(), types=types, allowed_type=ExcessiveAgencyType
        )
        self.purpose = purpose
        self.model = model
        self.async_mode = async_mode
        self.verbose_mode = verbose_mode
        super().__init__(types=enum_types)

    def _get_metric(
        self,
        type: ExcessiveAgencyType,
    ):
        return ExcessiveAgencyMetric(
            purpose=self.purpose,
            model=self.model,
            async_mode=self.async_mode,
            verbose_mode=self.verbose_mode,
        )

    def get_name(self) -> str:
        return "Excessive Agency"
