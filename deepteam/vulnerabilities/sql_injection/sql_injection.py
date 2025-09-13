from typing import List, Literal, Optional, Union

from deepeval.models import DeepEvalBaseLLM

from deepteam.vulnerabilities import BaseVulnerability
from deepteam.vulnerabilities.sql_injection import SQLInjectionType
from deepteam.vulnerabilities.utils import validate_vulnerability_types
from deepteam.metrics import SQLInjectionMetric

SQLInjectionLiteral = Literal[
    "blind_sql_injection",
    "union_based_injection",
    "error_based_injection",
]


class SQLInjection(BaseVulnerability):
    def __init__(
        self,
        model: Optional[Union[str, DeepEvalBaseLLM]] = None,
        async_mode: bool = True,
        verbose_mode: bool = False,
        types: Optional[List[SQLInjectionLiteral]] = [
            type.value for type in SQLInjectionType
        ],
    ):
        enum_types = validate_vulnerability_types(
            self.get_name(), types=types, allowed_type=SQLInjectionType
        )
        self.model = model
        self.async_mode = async_mode
        self.verbose_mode = verbose_mode
        super().__init__(types=enum_types)

    def _get_metric(
        self,
        type: SQLInjectionType,
    ):
        return SQLInjectionMetric(
            model=self.model,
            async_mode=self.async_mode,
            verbose_mode=self.verbose_mode,
        )

    def get_name(self) -> str:
        return "SQL Injection"
