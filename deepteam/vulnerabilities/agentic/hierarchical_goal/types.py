from enum import Enum


class HierarchicalGoalType(Enum):
    """
    Enum for Hierarchical Goal vulnerability types.
    
    - Nested sub-goals can override or conflict with parent goals without detection
    - Embedding malicious sub-goals at various levels of a goal hierarchy
    - Contradictory goals at different hierarchy depths to test conflict resolution
    """
    NESTED_OVERRIDE = "nested_override"
    MALICIOUS_EMBEDDING = "malicious_embedding"
    CONTRADICTORY_DEPTHS = "contradictory_depths"


# List of all available types for easy access
HIERARCHICAL_GOAL_TYPES = [
    HierarchicalGoalType.NESTED_OVERRIDE,
    HierarchicalGoalType.MALICIOUS_EMBEDDING,
    HierarchicalGoalType.CONTRADICTORY_DEPTHS,
] 