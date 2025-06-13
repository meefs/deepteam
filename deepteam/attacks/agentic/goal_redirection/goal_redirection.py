import random

from deepteam.attacks import BaseAttack
from deepteam.attacks.agentic.goal_redirection.template import GoalRedirectionTemplate


class GoalRedirection(BaseAttack):
    def __init__(self, weight: int = 2):
        self.weight = weight  # Higher weight since this is a sophisticated attack

    def enhance(self, attack: str) -> str:
        """
        Enhance the given attack with goal redirection techniques.
        Randomly selects from different redirection methods.
        """
        return random.choice([
            GoalRedirectionTemplate.enhance_ambiguous_framing(attack),
            GoalRedirectionTemplate.enhance_priority_shifting(attack),
            GoalRedirectionTemplate.enhance_constraint_confusion(attack),
            GoalRedirectionTemplate.enhance_goal_drift(attack),
            GoalRedirectionTemplate.enhance_scope_expansion(attack),
        ])

    def get_name(self) -> str:
        return "Goal Redirection" 