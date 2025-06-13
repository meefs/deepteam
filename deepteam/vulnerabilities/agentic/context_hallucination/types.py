from enum import Enum


class ContextHallucinationType(Enum):
    """
    Enum for Context-Specific Hallucination vulnerability types.
    
    - Domain-tailored fabricated inputs exploit agent's gaps in specific knowledge
    - Constructing adversarial examples that mimic legitimate domain scenarios (e.g. legal, medical)
    - Exploiting specialized terminology to slip false statements past safety nets
    """
    DOMAIN_MIMICRY = "domain_mimicry"
    SPECIALIZED_TERMINOLOGY = "specialized_terminology"
    KNOWLEDGE_GAP_EXPLOITATION = "knowledge_gap_exploitation"


# List of all available types for easy access
CONTEXT_HALLUCINATION_TYPES = [
    ContextHallucinationType.DOMAIN_MIMICRY,
    ContextHallucinationType.SPECIALIZED_TERMINOLOGY,
    ContextHallucinationType.KNOWLEDGE_GAP_EXPLOITATION,
] 