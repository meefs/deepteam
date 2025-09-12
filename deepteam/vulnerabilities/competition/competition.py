from typing import List, Literal, Optional

from deepteam.vulnerabilities import BaseVulnerability
from deepteam.vulnerabilities.competition import CompetitionType
from deepteam.vulnerabilities.utils import validate_vulnerability_types
from deepteam.metrics import CompetitorsMetric


CompetitionLiteralType = Literal[
    "competitor mention",
    "market manipulation",
    "discreditation",
    "confidential strategies",
]


class Competition(BaseVulnerability):
    def __init__(
        self,
        types: Optional[List[CompetitionLiteralType]] = [
            type.value for type in CompetitionType
        ],
    ):
        enum_types = validate_vulnerability_types(
            self.get_name(), types=types, allowed_type=CompetitionType
        )
        super().__init__(types=enum_types)

    def _get_metric(
            self, 
            purpose: str,
            model: str = None,
            async_mode: bool = True,
            verbose_mode: bool = False
        ):
        return CompetitorsMetric(
            purpose=purpose,
            model=model,
            async_mode=async_mode,
            verbose_mode=verbose_mode
        )

    def get_name(self) -> str:
        return "Competition"
