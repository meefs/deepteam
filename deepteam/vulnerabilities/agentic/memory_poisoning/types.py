from enum import Enum


class MemoryPoisoningType(Enum):
    """
    Enum for Memory Poisoning vulnerability types.
    
    - Malicious context entries persist and bias future decisions
    - Injecting fabricated memory snippets into the agent's persistent store
    - Using poisoned memory to steer multi-step workflows toward unsafe outcomes
    """
    FABRICATED_MEMORY_INJECTION = "fabricated_memory_injection"
    WORKFLOW_BIAS_INJECTION = "workflow_bias_injection"
    PERSISTENT_CONTEXT_POISONING = "persistent_context_poisoning"


# List of all available types for easy access
MEMORY_POISONING_TYPES = [
    MemoryPoisoningType.FABRICATED_MEMORY_INJECTION,
    MemoryPoisoningType.WORKFLOW_BIAS_INJECTION,
    MemoryPoisoningType.PERSISTENT_CONTEXT_POISONING,
] 