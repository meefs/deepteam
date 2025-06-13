from enum import Enum


class RoleInheritanceType(Enum):
    """
    Enum for Role Inheritance vulnerability types.
    
    - Dynamic role assignments that can be manipulated to inherit extra permissions
    - Temporary role upgrades with actions outside intended scope
    - Rapid sequential role switches to blur inheritance boundaries
    """
    MANIPULATED_DYNAMIC_ROLES = "manipulated_dynamic_roles"
    TEMPORARY_ROLE_UPGRADES = "temporary_role_upgrades"
    RAPID_ROLE_SWITCHES = "rapid_role_switches"


# List of all available types for easy access
ROLE_INHERITANCE_TYPES = [
    RoleInheritanceType.MANIPULATED_DYNAMIC_ROLES,
    RoleInheritanceType.TEMPORARY_ROLE_UPGRADES,
    RoleInheritanceType.RAPID_ROLE_SWITCHES,
] 