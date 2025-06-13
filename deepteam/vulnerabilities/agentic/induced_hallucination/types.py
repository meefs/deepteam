from enum import Enum


class InducedHallucinationType(Enum):
    """
    Enum for Induced Hallucination vulnerability types.
    
    - Agent fabricates plausible but false outputs when faced with ambiguous or incomplete inputs
    - Supplying conflicting data or near-duplicates to trigger confabulation
    - Imposing time pressure constraints to force quick, unverified answers
    """
    CONFLICTING_DATA = "conflicting_data"
    NEAR_DUPLICATES = "near_duplicates"
    TIME_PRESSURE = "time_pressure"


# List of all available types for easy access
INDUCED_HALLUCINATION_TYPES = [
    InducedHallucinationType.CONFLICTING_DATA,
    InducedHallucinationType.NEAR_DUPLICATES,
    InducedHallucinationType.TIME_PRESSURE,
] 