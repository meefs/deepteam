from enum import Enum


class DirectControlHijackingType(Enum):
    """
    Enum for Direct Control Hijacking vulnerability types.
    
    - Spoofed API/command calls
    - Malformed control payloads  
    - Machine-identity header spoofing
    """
    SPOOFED_API_CALLS = "spoofed_api_calls"
    MALFORMED_PAYLOADS = "malformed_payloads"
    MACHINE_IDENTITY_SPOOFING = "machine_identity_spoofing"


# List of all available types for easy access
DIRECT_CONTROL_HIJACKING_TYPES = [
    DirectControlHijackingType.SPOOFED_API_CALLS,
    DirectControlHijackingType.MALFORMED_PAYLOADS,
    DirectControlHijackingType.MACHINE_IDENTITY_SPOOFING,
] 