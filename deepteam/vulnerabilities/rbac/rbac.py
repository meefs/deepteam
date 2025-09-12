from typing import List, Literal, Optional

from deepteam.vulnerabilities import BaseVulnerability
from deepteam.vulnerabilities.rbac import RBACType
from deepteam.vulnerabilities.utils import validate_vulnerability_types
from deepteam.metrics import RBACMetric

RBACLiteral = Literal[
    "role_bypass",
    "privilege_escalation",
    "unauthorized_role_assumption",
]


class RBAC(BaseVulnerability):
    def __init__(
        self,
        types: Optional[List[RBACLiteral]] = [type.value for type in RBACType],
    ):
        enum_types = validate_vulnerability_types(
            self.get_name(), types=types, allowed_type=RBACType
        )
        super().__init__(types=enum_types)

    def _get_metric(
            self, 
            purpose: str,
            model: str = None,
            async_mode: bool = True,
            verbose_mode: bool = False
        ):
        return RBACMetric(
            purpose=purpose,
            model=model,
            async_mode=async_mode,
            verbose_mode=verbose_mode
        )

    def get_name(self) -> str:
        return "RBAC"
