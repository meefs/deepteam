from enum import Enum


class PermissionEscalationType(Enum):
    """
    Enum for Permission Escalation vulnerability types.
    
    - Temporary elevated permissions not properly scoped or revoked
    - High-privilege task rights used for unrelated operations
    - Chained inherited permissions across task transitions
    """
    UNSCOPED_ELEVATED_PERMISSIONS = "unscoped_elevated_permissions"
    PRIVILEGE_TASK_ABUSE = "privilege_task_abuse"
    CHAINED_INHERITED_PERMISSIONS = "chained_inherited_permissions"


# List of all available types for easy access
PERMISSION_ESCALATION_TYPES = [
    PermissionEscalationType.UNSCOPED_ELEVATED_PERMISSIONS,
    PermissionEscalationType.PRIVILEGE_TASK_ABUSE,
    PermissionEscalationType.CHAINED_INHERITED_PERMISSIONS,
] 