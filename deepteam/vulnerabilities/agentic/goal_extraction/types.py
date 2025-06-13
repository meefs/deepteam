from enum import Enum


class GoalExtractionType(Enum):
    """
    Enum for Goal Extraction vulnerability types.
    
    - Agent reveals its internal objectives or parameters under repeated probing
    - Escalating sequences of probing prompts or "cooperative" dialogues to infer hidden goals
    - Social-engineering-style queries to trick the agent into divulging mission details
    """
    ESCALATING_PROBING = "escalating_probing"
    COOPERATIVE_DIALOGUE = "cooperative_dialogue"
    SOCIAL_ENGINEERING = "social_engineering"


# List of all available types for easy access
GOAL_EXTRACTION_TYPES = [
    GoalExtractionType.ESCALATING_PROBING,
    GoalExtractionType.COOPERATIVE_DIALOGUE,
    GoalExtractionType.SOCIAL_ENGINEERING,
] 