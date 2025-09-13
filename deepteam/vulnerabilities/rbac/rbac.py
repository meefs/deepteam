from typing import List, Literal, Optional, Union

from deepeval.models import DeepEvalBaseLLM

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
        purpose: str,
        model: Optional[Union[str, DeepEvalBaseLLM]] = None,
        async_mode: bool = True,
        verbose_mode: bool = False,
        types: Optional[List[RBACLiteral]] = [type.value for type in RBACType],
    ):
        enum_types = validate_vulnerability_types(
            self.get_name(), types=types, allowed_type=RBACType
        )
        self.purpose = purpose
        self.model = model
        self.async_mode = async_mode
        self.verbose_mode = verbose_mode
        super().__init__(types=enum_types)

    def _get_metric(
        self,
        type: RBACType,
    ):
        return RBACMetric(
            purpose=self.purpose,
            model=self.model,
            async_mode=self.async_mode,
            verbose_mode=self.verbose_mode,
        )

    def get_name(self) -> str:
        return "RBAC"
