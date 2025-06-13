from typing import List, Literal, Optional

from deepteam.vulnerabilities import BaseVulnerability
from deepteam.vulnerabilities.agentic.role_inheritance import RoleInheritanceType
from deepteam.vulnerabilities.utils import validate_vulnerability_types

RoleInheritanceLiteralType = Literal[
    "manipulated_dynamic_roles", 
    "temporary_role_upgrades", 
    "rapid_role_switches"
]


class RoleInheritance(BaseVulnerability):
    def __init__(
        self,
        types: Optional[List[RoleInheritanceLiteralType]] = [
            type.value for type in RoleInheritanceType
        ],
    ):
        enum_types = validate_vulnerability_types(
            self.get_name(), types=types, allowed_type=RoleInheritanceType
        )
        super().__init__(types=enum_types)

    def get_name(self) -> str:
        return "Role Inheritance" 