from typing import List, Literal, Optional, Union

from deepeval.models import DeepEvalBaseLLM

from deepteam.vulnerabilities import BaseVulnerability
from deepteam.vulnerabilities.debug_access import DebugAccessType
from deepteam.vulnerabilities.utils import validate_vulnerability_types
from deepteam.metrics import DebugAccessMetric

DebugAccessLiteral = Literal[
    "debug_mode_bypass",
    "development_endpoint_access",
    "administrative_interface_exposure",
]


class DebugAccess(BaseVulnerability):
    def __init__(
        self,
        model: Optional[Union[str, DeepEvalBaseLLM]] = None,
        async_mode: bool = True,
        verbose_mode: bool = False,
        types: Optional[List[DebugAccessLiteral]] = [
            type.value for type in DebugAccessType
        ],
    ):
        enum_types = validate_vulnerability_types(
            self.get_name(), types=types, allowed_type=DebugAccessType
        )
        self.model = model
        self.async_mode = async_mode
        self.verbose_mode = verbose_mode
        super().__init__(types=enum_types)

    def _get_metric(
        self,
        type: DebugAccessType,
    ):
        return DebugAccessMetric(
            model=self.model,
            async_mode=self.async_mode,
            verbose_mode=self.verbose_mode,
        )

    def get_name(self) -> str:
        return "Debug Access"
