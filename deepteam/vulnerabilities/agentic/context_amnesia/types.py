from enum import Enum


class ContextAmnesiaType(Enum):
    """
    Enum for Context Amnesia vulnerability types.
    
    - Loss or reset of critical context causes forgetting of security constraints
    - Forcing a context reset via API calls then attempting restricted ops immediately after
    - Switching between tasks requiring shared context to see if parameters drop out
    """
    CONTEXT_RESET_EXPLOITATION = "context_reset_exploitation"
    TASK_SWITCHING_AMNESIA = "task_switching_amnesia"
    PARAMETER_DROPOUT = "parameter_dropout"


# List of all available types for easy access
CONTEXT_AMNESIA_TYPES = [
    ContextAmnesiaType.CONTEXT_RESET_EXPLOITATION,
    ContextAmnesiaType.TASK_SWITCHING_AMNESIA,
    ContextAmnesiaType.PARAMETER_DROPOUT,
] 