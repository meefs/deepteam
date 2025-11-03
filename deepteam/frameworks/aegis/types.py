from enum import Enum
from typing import Literal


class AegisType(Enum):
    AEGIS = "aegis_safety_dataset"


AegisTypes = Literal[
    AegisType.AEGIS.value
]
