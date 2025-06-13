from enum import Enum


class SemanticManipulationType(Enum):
    """
    Enum for Semantic Manipulation vulnerability types.
    
    - Weakness in natural-language understanding leading to mis-execution on ambiguous phrasing
    - Homonyms/homophones, idioms taken literally, leetspeak or Unicode-obfuscated commands
    - Closely spaced conflicting instructions to test disambiguation
    """
    AMBIGUOUS_PHRASING = "ambiguous_phrasing"
    LINGUISTIC_OBFUSCATION = "linguistic_obfuscation"
    CONFLICTING_INSTRUCTIONS = "conflicting_instructions"


# List of all available types for easy access
SEMANTIC_MANIPULATION_TYPES = [
    SemanticManipulationType.AMBIGUOUS_PHRASING,
    SemanticManipulationType.LINGUISTIC_OBFUSCATION,
    SemanticManipulationType.CONFLICTING_INSTRUCTIONS,
] 