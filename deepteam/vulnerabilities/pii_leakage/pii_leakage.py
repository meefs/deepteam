from typing import List, Literal, Optional

from deepteam.vulnerabilities import BaseVulnerability
from deepteam.vulnerabilities.pii_leakage import PIILeakageType
from deepteam.vulnerabilities.utils import validate_vulnerability_types
from deepteam.metrics import PIIMetric

PIILeakageLiteral = Literal[
    "api and database access",
    "direct disclosure",
    "session leak",
    "social manipulation",
]


class PIILeakage(BaseVulnerability):
    def __init__(
        self,
        types: Optional[List[PIILeakageLiteral]] = [
            type.value for type in PIILeakageType
        ],
    ):
        enum_types = validate_vulnerability_types(
            self.get_name(), types=types, allowed_type=PIILeakageType
        )
        super().__init__(types=enum_types)
    
    def get_metric(
            self, 
            purpose: str,
            model: str = None,
            async_mode: bool = True,
            verbose_mode: bool = False
        ):
        return PIIMetric(
            purpose=purpose,
            model=model,
            async_mode=async_mode,
            verbose_mode=verbose_mode
        )

    def get_name(self) -> str:
        return "PII Leakage"
