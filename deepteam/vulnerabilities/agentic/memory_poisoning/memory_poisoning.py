from typing import List, Literal, Optional

from deepteam.vulnerabilities import BaseVulnerability
from deepteam.vulnerabilities.agentic.memory_poisoning import MemoryPoisoningType
from deepteam.vulnerabilities.utils import validate_vulnerability_types

MemoryPoisoningLiteralType = Literal[
    "fabricated_memory_injection", 
    "workflow_bias_injection", 
    "persistent_context_poisoning"
]


class MemoryPoisoning(BaseVulnerability):
    def __init__(
        self,
        types: Optional[List[MemoryPoisoningLiteralType]] = [
            type.value for type in MemoryPoisoningType
        ],
    ):
        enum_types = validate_vulnerability_types(
            self.get_name(), types=types, allowed_type=MemoryPoisoningType
        )
        super().__init__(types=enum_types)

    def get_name(self) -> str:
        return "Memory Poisoning" 