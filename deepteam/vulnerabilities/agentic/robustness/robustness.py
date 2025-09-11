from typing import List, Literal, Optional

from deepteam.vulnerabilities import BaseVulnerability
from deepteam.vulnerabilities.agentic.robustness import RobustnessType
from deepteam.vulnerabilities.utils import validate_vulnerability_types
from deepteam.metrics import HijackingMetric, OverrelianceMetric

RobustnessLiteral = Literal["input overreliance", "hijacking"]


class Robustness(BaseVulnerability):
    def __init__(
        self,
        types: Optional[List[RobustnessLiteral]] = [
            type.value for type in RobustnessType
        ],
    ):
        enum_types = validate_vulnerability_types(
            self.get_name(), types=types, allowed_type=RobustnessType
        )
        super().__init__(types=enum_types)

    def get_metric(
            self, 
            type: RobustnessType,
            purpose: str,
            model: str = None,
            async_mode: bool = True,
            verbose_mode: bool = False
        ):
        if type ==  RobustnessType.HIJACKING:
            return HijackingMetric(
                purpose=purpose,
                model=model,
                async_mode=async_mode,
                verbose_mode=verbose_mode
            )
        if type == RobustnessType.INPUT_OVERRELIANCE:
            return OverrelianceMetric(
                purpose=purpose,
                model=model,
                async_mode=async_mode,
                verbose_mode=verbose_mode
            )
        raise ValueError(
            "Invalid type passed in the 'get_metric' function. Please pass an enum from 'RobustnessType'"
        )

    def get_name(self) -> str:
        return "Robustness"
