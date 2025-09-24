from typing import List, Optional
from dataclasses import dataclass
from enum import Enum
from deepeval.test_case import LLMTestCase, Turn


class RTTurn(Turn):
    pass

class RTTestCase(LLMTestCase):
    actual_output: Optional[str] = None
    turns: Optional[List[RTTurn]] = None
    metadata: Optional[dict] = None
    vulnerability: Optional[str] = None
    vulnerability_type: Enum = None
    attack_method: Optional[str] = None
    risk_category: Optional[str] = None
    score: Optional[float] = None
    reason: Optional[str] = None
    error: Optional[str] = None

    def __post_init__(self):
        if self.actual_output is not None and self.turns is not None: 
            raise ValueError(
                "An 'RTTestCase' cannot contain both 'actual_output' and 'turns' at the same time."
            )