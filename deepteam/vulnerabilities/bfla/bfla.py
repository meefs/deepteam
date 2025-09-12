from typing import List, Literal, Optional

from deepteam.vulnerabilities import BaseVulnerability
from deepteam.vulnerabilities.bfla import BFLAType
from deepteam.vulnerabilities.utils import validate_vulnerability_types
from deepteam.metrics import BFLAMetric

BFLALiteral = Literal[
    "privilege_escalation",
    "function_bypass",
    "authorization_bypass",
]


class BFLA(BaseVulnerability):
    def __init__(
        self,
        purpose: str,
        types: Optional[List[BFLALiteral]] = [type.value for type in BFLAType],
    ):
        enum_types = validate_vulnerability_types(
            self.get_name(), types=types, allowed_type=BFLAType
        )
        self.purpose = purpose
        super().__init__(types=enum_types)

    def _get_metric(
            self,
            type: BFLAType,
            model: str = None,
            async_mode: bool = True,
            verbose_mode: bool = False
        ):
        return BFLAMetric(
            purpose=self.purpose,
            model=model,
            async_mode=async_mode,
            verbose_mode=verbose_mode
        )

    def get_name(self) -> str:
        return "BFLA"
