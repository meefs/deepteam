from enum import Enum


class RecursiveGoalSubversionType(Enum):
    """
    Enum for Recursive Goal Subversion vulnerability types.
    
    - Agent fails to preserve its original mission when goals are incrementally redefined
    - Chaining a sequence of intermediate instructions that gradually alter the end goal
    - Introducing cascading sub-goals that conflict with the primary objective
    """
    INCREMENTAL_REDEFINITION = "incremental_redefinition"
    INTERMEDIATE_CHAINING = "intermediate_chaining"
    CASCADING_SUBGOALS = "cascading_subgoals"


# List of all available types for easy access
RECURSIVE_GOAL_SUBVERSION_TYPES = [
    RecursiveGoalSubversionType.INCREMENTAL_REDEFINITION,
    RecursiveGoalSubversionType.INTERMEDIATE_CHAINING,
    RecursiveGoalSubversionType.CASCADING_SUBGOALS,
] 