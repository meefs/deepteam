from typing import List, Literal, Optional

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
        types: Optional[List[ExcessiveAgencyLiteral]] = [
            type.value for type in ExcessiveAgencyType
        ],
    ):
        enum_types = validate_vulnerability_types(
            self.get_name(), types=types, allowed_type=ExcessiveAgencyType
        )
        self.purpose = purpose
        super().__init__(types=enum_types)

    def _get_metric(
            self,
            type: ExcessiveAgencyType,
            model: str = None,
            async_mode: bool = True,
            verbose_mode: bool = False
        ):
        return ExcessiveAgencyMetric(
            purpose=self.purpose,
            model=model,
            async_mode=async_mode,
            verbose_mode=verbose_mode
        )

    def get_name(self) -> str:
        return "Excessive Agency"
