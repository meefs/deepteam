from typing import List, Optional, Union
from enum import Enum

from deepeval.models import DeepEvalBaseLLM

from deepteam.vulnerabilities import BaseVulnerability
from deepteam.metrics import BaseRedTeamingMetric, HarmMetric


class CustomVulnerability(BaseVulnerability):
    """
    Custom vulnerability class that allows users to define their own vulnerability types.
    """

    def __init__(
        self,
        name: str,
        criteria: str,
        types: Optional[List[str]] = None,
        custom_prompt: Optional[str] = None,
        metric: Optional[BaseRedTeamingMetric] = None,
        model: Optional[Union[str, DeepEvalBaseLLM]] = None,
        async_mode: bool = True,
        verbose_mode: bool = False,
    ):
        self.name = name

        if types:
            self.types = Enum(
                f"CustomVulnerabilityType", {t.upper(): t for t in types}
            )

        self.custom_prompt = custom_prompt
        self.criteria = criteria.strip()
        self.model = model
        self.async_mode = async_mode
        self.verbose_mode = verbose_mode
        if metric:
            self.metric = metric
        else:
            self.metric = HarmMetric(
                harm_category=self.criteria,
                model=self.model,
                async_mode=self.async_mode,
                verbose_mode=self.verbose_mode
            )
        super().__init__(self.types)

    def get_name(self) -> str:
        return self.name

    def get_custom_prompt(self) -> Optional[str]:
        return self.custom_prompt

    def _get_metric(self, type: Enum) -> Optional[BaseRedTeamingMetric]:
        return self.metric

    def get_criteria(self) -> str:
        return self.criteria
