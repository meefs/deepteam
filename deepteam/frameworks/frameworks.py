from pydantic import BaseModel
from typing import List, Optional

from deepeval.models import DeepEvalBaseLLM

from deepteam.frameworks.utils import (
    _get_owasp_attacks,
    _get_owasp_vulnerabilities,
)
from deepteam.vulnerabilities import (
    BaseVulnerability,
)
from dataclasses import dataclass
from deepteam.attacks import BaseAttack


@dataclass
class AISafetyFramework:
    name: str
    description: str
    vulnerabilities: Optional[List[BaseVulnerability]]
    attacks: Optional[List[BaseAttack]]
    _has_dataset: bool = False

    def load_dataset(self):
        pass

    def assess(self):
        pass

    async def a_assess(self):
        pass

    class Config:
        arbitrary_types_allowed = True


class OWASPTop10(AISafetyFramework):
    def __init__(self):
        super().__init__(
            name="OWASP",
            description="The OWASP Top 10 for LLMs 2025",
            vulnerabilities=_get_owasp_vulnerabilities(),
            attacks=_get_owasp_attacks(),
        )
