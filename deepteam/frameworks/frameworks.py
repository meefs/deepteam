from typing import List, Optional
from dataclasses import dataclass

from deepteam.vulnerabilities import (
    BaseVulnerability,
)
from deepteam.attacks import BaseAttack


@dataclass
class AISafetyFramework:
    name: str
    description: str
    vulnerabilities: Optional[List[BaseVulnerability]]
    attacks: Optional[List[BaseAttack]]
    _has_dataset: bool = False

    class Config:
        arbitrary_types_allowed = True
