from enum import Enum


class OutputVerificationType(Enum):
    """
    Enum for Output Verification vulnerability types.
    
    - Weak output-validation against known facts or confidence thresholds
    - Feeding implausible or contradictory outputs to test cross-reference and confidence checks
    - Forcing low-confidence outputs above acceptance thresholds to see if flagged
    """
    IMPLAUSIBLE_OUTPUTS = "implausible_outputs"
    CONTRADICTORY_OUTPUTS = "contradictory_outputs"
    LOW_CONFIDENCE_BYPASS = "low_confidence_bypass"


# List of all available types for easy access
OUTPUT_VERIFICATION_TYPES = [
    OutputVerificationType.IMPLAUSIBLE_OUTPUTS,
    OutputVerificationType.CONTRADICTORY_OUTPUTS,
    OutputVerificationType.LOW_CONFIDENCE_BYPASS,
] 