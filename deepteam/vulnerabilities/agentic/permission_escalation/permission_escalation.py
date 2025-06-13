from typing import List, Literal, Optional

from deepteam.vulnerabilities import BaseVulnerability
from deepteam.vulnerabilities.agentic.permission_escalation import PermissionEscalationType
from deepteam.vulnerabilities.utils import validate_vulnerability_types

PermissionEscalationLiteralType = Literal[
    "unscoped_elevated_permissions", 
    "privilege_task_abuse", 
    "chained_inherited_permissions"
]


class PermissionEscalation(BaseVulnerability):
    def __init__(
        self,
        types: Optional[List[PermissionEscalationLiteralType]] = [
            type.value for type in PermissionEscalationType
        ],
    ):
        enum_types = validate_vulnerability_types(
            self.get_name(), types=types, allowed_type=PermissionEscalationType
        )
        super().__init__(types=enum_types)

    def get_name(self) -> str:
        return "Permission Escalation" 