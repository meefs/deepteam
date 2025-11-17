from typing import List, Optional
from dataclasses import dataclass

from deepteam.vulnerabilities import (
    BaseVulnerability,
)
from deepteam.attacks import BaseAttack
from deepteam.test_case import RTTestCase


@dataclass
class RiskCategory:
    name: str
    vulnerabilities: List[BaseVulnerability]
    attacks: List[BaseAttack]
    test_cases: Optional[List[RTTestCase]] = None
