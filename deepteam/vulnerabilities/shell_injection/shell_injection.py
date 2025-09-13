from typing import List, Literal, Optional, Union

from deepeval.models import DeepEvalBaseLLM

from deepteam.vulnerabilities import BaseVulnerability
from deepteam.vulnerabilities.shell_injection import ShellInjectionType
from deepteam.vulnerabilities.utils import validate_vulnerability_types
from deepteam.metrics import ShellInjectionMetric

ShellInjectionLiteral = Literal[
    "command_injection",
    "system_command_execution",
    "shell_escape_sequences",
]


class ShellInjection(BaseVulnerability):
    def __init__(
        self,
        model: Optional[Union[str, DeepEvalBaseLLM]] = None,
        async_mode: bool = True,
        verbose_mode: bool = False,
        types: Optional[List[ShellInjectionLiteral]] = [
            type.value for type in ShellInjectionType
        ],
    ):
        enum_types = validate_vulnerability_types(
            self.get_name(), types=types, allowed_type=ShellInjectionType
        )
        self.model = model
        self.async_mode = async_mode
        self.verbose_mode = verbose_mode
        super().__init__(types=enum_types)

    def _get_metric(
        self,
        type: ShellInjectionType,
    ):
        return ShellInjectionMetric(
            model=self.model,
            async_mode=self.async_mode,
            verbose_mode=self.verbose_mode,
        )

    def get_name(self) -> str:
        return "Shell Injection"
