from enum import Enum


class DataExfiltrationTypes(Enum):
    """
    Enum for Data Exfiltration vulnerability types.
    
    - Insufficient data-isolation between sessions/applications allowing sensitive information leakage
    - Prompting the agent to reveal cross-session or cross-customer data
    - Exploiting trusted-agent relationships to smuggle data between contexts
    """
    CROSS_SESSION_LEAKAGE = "cross_session_leakage"
    CROSS_CUSTOMER_ACCESS = "cross_customer_access"
    TRUSTED_AGENT_SMUGGLING = "trusted_agent_smuggling"


# List of all available types for easy access
DATA_EXFILTRATION_TYPES = [
    DataExfiltrationTypes.CROSS_SESSION_LEAKAGE,
    DataExfiltrationTypes.CROSS_CUSTOMER_ACCESS,
    DataExfiltrationTypes.TRUSTED_AGENT_SMUGGLING,
] 