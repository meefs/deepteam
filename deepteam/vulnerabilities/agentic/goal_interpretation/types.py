from enum import Enum


class GoalInterpretationType(Enum):
    """
    Enum for Goal Interpretation vulnerability types.
    
    - Agent mis-interprets or drifts from its primary goal under ambiguous adversarial input
    - Subtly modified goal descriptions to induce divergence
    - Conflicting constraints in single goal prompts to test priority handling
    """
    AMBIGUOUS_ADVERSARIAL_INPUT = "ambiguous_adversarial_input"
    SUBTLE_GOAL_MODIFICATION = "subtle_goal_modification"
    CONFLICTING_CONSTRAINTS = "conflicting_constraints"


# List of all available types for easy access
GOAL_INTERPRETATION_TYPES = [
    GoalInterpretationType.AMBIGUOUS_ADVERSARIAL_INPUT,
    GoalInterpretationType.SUBTLE_GOAL_MODIFICATION,
    GoalInterpretationType.CONFLICTING_CONSTRAINTS,
] 