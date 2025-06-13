from enum import Enum


class DecisionManipulationType(Enum):
    """
    Enum for Decision Manipulation vulnerability types.
    
    - Agent's decisions can be swayed by earlier hallucinated or misleading outputs
    - Injecting false context into the decision pipeline and observing security-critical choices
    - Conflicting data sources with fabricated entries to see which the agent trusts
    """
    FALSE_CONTEXT_INJECTION = "false_context_injection"
    CONFLICTING_DATA_SOURCES = "conflicting_data_sources"
    FABRICATED_ENTRIES = "fabricated_entries"


# List of all available types for easy access
DECISION_MANIPULATION_TYPES = [
    DecisionManipulationType.FALSE_CONTEXT_INJECTION,
    DecisionManipulationType.CONFLICTING_DATA_SOURCES,
    DecisionManipulationType.FABRICATED_ENTRIES,
] 