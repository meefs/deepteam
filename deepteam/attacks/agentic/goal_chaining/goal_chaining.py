import random

from deepteam.attacks import BaseAttack
from deepteam.attacks.agentic.goal_chaining.template import GoalChainingTemplate


class GoalChaining(BaseAttack):
    def __init__(self, weight: int = 2):
        self.weight = weight  # Higher weight since this is a sophisticated attack

    def enhance(self, attack: str) -> str:
        """
        Enhance the given attack with goal chaining techniques.
        Randomly selects from different chaining methods.
        """
        return random.choice([
            GoalChainingTemplate.enhance_incremental_drift(attack),
            GoalChainingTemplate.enhance_sequential_chaining(attack),
            GoalChainingTemplate.enhance_cascading_priorities(attack),
            GoalChainingTemplate.enhance_contextual_evolution(attack),
            GoalChainingTemplate.enhance_subgoal_injection(attack),
        ])

    def get_name(self) -> str:
        return "Goal Chaining" 