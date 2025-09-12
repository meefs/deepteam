from typing import List, Literal, Optional

from deepteam.vulnerabilities import BaseVulnerability
from deepteam.vulnerabilities.bola import BOLAType
from deepteam.vulnerabilities.utils import validate_vulnerability_types
from deepteam.metrics import BOLAMetric

BOLALiteral = Literal[
    "object_access_bypass",
    "cross_customer_access",
    "unauthorized_object_manipulation",
]


class BOLA(BaseVulnerability):
    def __init__(
        self,
        types: Optional[List[BOLALiteral]] = [type.value for type in BOLAType],
    ):
        enum_types = validate_vulnerability_types(
            self.get_name(), types=types, allowed_type=BOLAType
        )
        super().__init__(types=enum_types)

    def _get_metric(
            self, 
            type: BOLAType,
            model: str = None,
            async_mode: bool = True,
            verbose_mode: bool = False
        ):
        return BOLAMetric(
            model=model,
            async_mode=async_mode,
            verbose_mode=verbose_mode
        )

    def get_name(self) -> str:
        return "BOLA"
