from enum import Enum


class TemporalAttackType(Enum):
    """
    Enum for Temporal Attack vulnerability types.
    
    - Agent fails to link split-across-sessions operations as a single threat chain
    - Spreading a security-sensitive operation into small steps across multiple sessions
    - Time-delaying commands to see if linkage breaks after context window expires
    """
    MULTI_SESSION_CHAIN_SPLITTING = "multi_session_chain_splitting"
    TIME_DELAYED_COMMAND_EXECUTION = "time_delayed_command_execution"
    CONTEXT_WINDOW_EXPLOITATION = "context_window_exploitation"


# List of all available types for easy access
TEMPORAL_ATTACK_TYPES = [
    TemporalAttackType.MULTI_SESSION_CHAIN_SPLITTING,
    TemporalAttackType.TIME_DELAYED_COMMAND_EXECUTION,
    TemporalAttackType.CONTEXT_WINDOW_EXPLOITATION,
] 