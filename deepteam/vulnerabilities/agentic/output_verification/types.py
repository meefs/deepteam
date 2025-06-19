from enum import Enum


class OutputVerificationType(str, Enum):
    """
    OutputVerificationType enum for the different types of output verification vulnerabilities.
    
    These vulnerabilities focus on scenarios where the agent fails to properly validate, 
    verify, or double-check the accuracy of outputs before presenting them.
    """
    
    ACCURACY_BYPASS = "accuracy bypass"
    VALIDATION_SKIP = "validation skip"  
    VERIFICATION_FAILURE = "verification failure"


# List of all available types for easy access
OUTPUT_VERIFICATION_TYPES = [
    OutputVerificationType.ACCURACY_BYPASS,
    OutputVerificationType.VALIDATION_SKIP,
    OutputVerificationType.VERIFICATION_FAILURE,
] 