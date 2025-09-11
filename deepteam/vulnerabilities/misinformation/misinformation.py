from typing import List, Literal, Optional

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
        types: Optional[List[MisinformationLiteral]] = [
            type.value for type in MisinformationType
        ],
    ):
        enum_types = validate_vulnerability_types(
            self.get_name(), types=types, allowed_type=MisinformationType
        )
        super().__init__(types=enum_types)

    def get_metric(
            self, 
            misinformation_category: str,
            model: str = None,
            async_mode: bool = True,
            verbose_mode: bool = False
        ):
        return MisinformationMetric(
            misinformation_category=misinformation_category,
            model=model,
            async_mode=async_mode,
            verbose_mode=verbose_mode
        )

    def get_name(self) -> str:
        return "Misinformation"
